package endpoints

import (
	"context"
	"crypto/subtle"
	"net/http"
	"regexp"
	"strings"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
)

// Browser binding of an authorization transaction.
//
// The selection page and the acknowledgement bind the choice of provider to the
// browser that saw the page, but the transaction then travels through the
// identity provider and comes back on /oauth/callback (and, with MFA, through
// /oauth/mfa-challenge and /oauth/mfa-verify). Without more, the callback would
// accept whichever browser carries the provider's state: an attacker could run
// the selection page themselves with their own client and redirect URI, take the
// provider URL, and send it to a victim, whose sign-in would then yield a code
// for the attacker's redirect URI.
//
// So /authorize gives the browser a random secret in an HttpOnly cookie and
// stores its hash in the transaction; every step that can lead to a code
// requires the cookie to match.
const (
	browserBindCookie = "lc_oauth_browser"
	// hostBrowserBindCookie is the name used over https. The __Host- prefix makes
	// browsers refuse the cookie unless it is Secure, has Path=/ and no Domain,
	// which stops a page on a sibling subdomain from planting a secret it knows
	// ("cookie tossing") that /authorize would then reuse.
	hostBrowserBindCookie = "__Host-" + browserBindCookie
)

// browserSecretShape is what a secret we issued looks like (randomToken: 32
// random bytes, base64url). Anything else in the cookie is not ours and is
// replaced rather than reused.
var browserSecretShape = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func (h *Handlers) serverIsHTTPS() bool {
	return strings.HasPrefix(h.metadataProvider.GetServerURL(), "https://")
}

func (h *Handlers) browserBindCookieName() string {
	if h.serverIsHTTPS() {
		return hostBrowserBindCookie
	}
	return browserBindCookie
}

// browserBindingCookie builds the browser-binding cookie.
//
//   - SameSite=Lax, not Strict: the browser must send it on the identity
//     provider's top-level cross-site redirect back to /oauth/callback, which
//     Strict would withhold. Lax still withholds it from cross-site
//     sub-requests and POSTs.
//   - HttpOnly: page scripts never see the secret.
//   - Secure over https. Over https the name is __Host-prefixed, which requires
//     Path=/ (it covers /oauth/callback and the MFA paths); over plain http (local
//     development) the cookie is limited to /oauth, which covers the same paths.
//   - Max-Age is the transaction's lifetime and is renewed by every /authorize
//     that reuses the cookie, so it outlives none of the transactions bound to it.
func (h *Handlers) browserBindingCookie(secret string, maxAge int) *http.Cookie {
	path := "/oauth"
	if h.serverIsHTTPS() {
		path = "/"
	}
	return &http.Cookie{
		Name:     h.browserBindCookieName(),
		Value:    secret,
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.serverIsHTTPS(),
		SameSite: http.SameSiteLaxMode,
	}
}

// bindTransactionToBrowser makes sure this browser holds a browser-binding
// secret, setting the cookie on the response, and returns the hash to store in
// the transaction. An existing well-formed secret is reused, so several
// sign-ins started in one browser at once all stay valid.
func (h *Handlers) bindTransactionToBrowser(w http.ResponseWriter, r *http.Request) (string, error) {
	secret, err := h.ensureBrowserSecret(w, r)
	if err != nil {
		return "", err
	}
	return sha256Hex(secret), nil
}

// ensureBrowserSecret returns this browser's binding secret, reusing a
// well-formed one it presented and otherwise minting one, and (re)sets the
// cookie on the response.
func (h *Handlers) ensureBrowserSecret(w http.ResponseWriter, r *http.Request) (string, error) {
	secret, ok := h.browserSecretOf(r)
	if !ok {
		var err error
		if secret, err = randomToken(); err != nil {
			return "", err
		}
	}
	http.SetCookie(w, h.browserBindingCookie(secret, state.StateTTL))
	return secret, nil
}

// browserSecretOf returns the well-formed browser-binding secret the request
// presents, if any.
func (h *Handlers) browserSecretOf(r *http.Request) (string, bool) {
	c, err := r.Cookie(h.browserBindCookieName())
	if err != nil || !browserSecretShape.MatchString(c.Value) {
		return "", false
	}
	return c.Value, true
}

// transactionBoundToBrowser reports whether the request comes from the browser
// the transaction was bound to at /authorize. A transaction without a binding
// (written before the binding existed) never matches.
func (h *Handlers) transactionBoundToBrowser(r *http.Request, tx *state.OAuthState) bool {
	if tx == nil || tx.BrowserBinding == "" {
		return false
	}
	c, err := r.Cookie(h.browserBindCookieName())
	if err != nil || c.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sha256Hex(c.Value)), []byte(tx.BrowserBinding)) == 1
}

// browserMismatchPage is shown, in place of any redirect to the client, when a
// step of the sign-in comes from a browser the transaction was not started in.
var browserMismatchPage = oauthErrorPage{
	ErrorTitle:   "Sign-in must be restarted",
	ErrorMessage: "This sign-in was not started in this browser, or it expired. Nothing was granted. Go back to the application you were signing in to and start the sign-in again from there.",
	ErrorCode:    "browser_mismatch",
	RetryURL:     limaCharlieWebAppURL,
	RetryLabel:   "Open LimaCharlie",
}

// abandonOnBrowserMismatch ends a transaction whose binding does not match the
// browser presenting it: the transaction is consumed, so the provider callback
// or MFA link cannot be retried from anywhere, and the caller shows a local error
// without contacting the client's redirect URI.
func (h *Handlers) abandonOnBrowserMismatch(r *http.Request, step, txID string, tx *state.OAuthState) {
	h.logger.Warn("SECURITY: sign-in step from a browser the transaction was not started in",
		"step", step, "has_binding", tx != nil && tx.BrowserBinding != "", "redirect_host", redirectHostOf(tx))
	if _, err := h.stateManager.ConsumeOAuthState(context.WithoutCancel(r.Context()), txID); err != nil {
		h.logger.Warn("Failed to abandon OAuth state after browser mismatch", "error", err)
	}
}

func redirectHostOf(tx *state.OAuthState) string {
	if tx == nil {
		return ""
	}
	return redirectHost(tx.RedirectURI)
}
