package endpoints

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/cimd"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"golang.org/x/net/idna"
)

// Provider selection and CIMD (OAuth Client ID Metadata Documents) support for
// the authorization endpoint. Every client goes through the selection page,
// which shows who is asking and where the user will be sent; a direct provider
// parameter is honoured only with the acknowledgement that page issues.
// A CIMD client_id that looks like a URL is resolved ONLY through its
// metadata document: it never falls back to dynamic registrations or to the
// global redirect URI allow-list.

const (
	selectionAckParam  = "selection_ack"
	selectionAckCookie = "lc_oauth_selection"
	// selectionBindCookie ties a selection session to the
	// browser that was shown the selection page, and selectionBindKey is where
	// the hash of its value is kept in the session.
	selectionBindCookie = "lc_oauth_selection_view"
	selectionBindKey    = "_selection_view"
)

// cimdResolver resolves a CIMD client_id to its validated metadata document.
type cimdResolver interface {
	Resolve(ctx context.Context, clientID string) (*cimd.Document, error)
}

// clientDisplay is what the provider-selection page shows about whoever is
// asking: every client gets one, whatever kind it is.
type clientDisplay struct {
	// Name is the client's name, made safe to show: the name in its metadata
	// document (CIMD), the sanitized name it registered with (DCR), or its
	// client_id for clients with no registry entry (allowlisted opaque ids).
	Name string
	// ClientIDHost and ClientID are set for URL (CIMD) clients, whose client_id
	// says where the application lives.
	ClientIDHost string
	ClientID     string
	// SelfReported is set when Name is whatever the application called itself
	// and nothing vouches for it (DCR, opaque ids).
	SelfReported bool
	// RedirectHost is where the user is sent afterwards (host and port, with
	// internationalized names in their ASCII form so look-alikes show).
	RedirectHost string
	Localhost    bool
}

// resolveCIMD resolves clientID, mapping failures to OAuth errors.
func (h *Handlers) resolveCIMD(ctx context.Context, clientID string) (*cimd.Document, *OAuthError) {
	if h.cimd == nil {
		// Fail closed when CIMD is not wired up.
		return nil, NewOAuthError(ErrInvalidClient, "URL client_ids are not supported", http.StatusBadRequest)
	}
	doc, err := h.cimd.Resolve(ctx, clientID)
	if err != nil {
		var ce *cimd.Error
		if errors.As(err, &ce) {
			if ce.Kind == cimd.KindBusy {
				return nil, NewOAuthError(ErrTemporarilyUnavailable, ce.Message, http.StatusServiceUnavailable)
			}
			return nil, NewOAuthError(ErrInvalidClient, ce.Message, http.StatusBadRequest)
		}
		return nil, NewOAuthError(ErrInvalidClient, "could not validate client metadata document", http.StatusBadRequest)
	}
	return doc, nil
}

// authorizeCIMDClient resolves a CIMD client and checks redirectURI against its
// document by exact match.
func (h *Handlers) authorizeCIMDClient(ctx context.Context, clientID, redirectURI string) *OAuthError {
	doc, oerr := h.resolveCIMD(ctx, clientID)
	if oerr != nil {
		h.logger.Info("CIMD authorize rejected", "client_host", clientHost(clientID), "outcome", oerr.Error)
		return oerr
	}
	if !doc.HasRedirectURI(redirectURI) {
		h.logger.Info("CIMD authorize rejected", "client_host", clientHost(clientID), "outcome", "redirect_uri_not_in_document")
		return NewOAuthError(ErrInvalidRequest, "redirect_uri not allowed for this client", http.StatusBadRequest)
	}
	h.logger.Info("CIMD authorize accepted", "client_host", clientHost(clientID), "outcome", "ok")
	return nil
}

func clientHost(clientID string) string {
	if u, err := url.Parse(clientID); err == nil {
		return u.Hostname()
	}
	return ""
}

// selectionDisplay builds the client details for the selection page of a
// session. There is always something to show: a session that is missing or
// expired, or a client that no longer validates, is an error (the page is never
// shown without the details it must show).
func (h *Handlers) selectionDisplay(ctx context.Context, sessionID string) (*clientDisplay, *OAuthError) {
	params, err := h.stateManager.GetSelectionSession(ctx, sessionID)
	if err != nil {
		h.logger.Error("Failed to read selection session", "error", err)
		return nil, NewOAuthError(ErrServerError, "Failed to read session", http.StatusInternalServerError)
	}
	if params == nil {
		return nil, NewOAuthError(ErrInvalidRequest, "Session expired or invalid", http.StatusBadRequest)
	}
	clientID := params["client_id"]
	redirectURI := params["redirect_uri"]
	// Hosts are shown in their ASCII (punycode) form, and a host with control,
	// bidi or other spoofing characters is refused, so a look-alike or
	// bidi-spoofed name can't pass for another site.
	redirectHost, ok := displayHostPort(redirectURI)
	if !ok {
		return nil, NewOAuthError(ErrInvalidRequest, "redirect_uri not allowed for this client", http.StatusBadRequest)
	}
	display := &clientDisplay{
		RedirectHost: redirectHost,
		Localhost:    cimd.IsLoopbackRedirect(redirectURI),
	}

	if cimd.LooksLikeURL(clientID) {
		doc, oerr := h.resolveCIMD(ctx, clientID)
		if oerr != nil {
			return nil, oerr
		}
		if !doc.HasRedirectURI(redirectURI) {
			return nil, NewOAuthError(ErrInvalidRequest, "redirect_uri not allowed for this client", http.StatusBadRequest)
		}
		idHost, err := cimd.DisplayHost(clientHost(clientID))
		if err != nil {
			return nil, NewOAuthError(ErrInvalidClient, "invalid client_id URL", http.StatusBadRequest)
		}
		display.Name = doc.ClientName
		display.ClientID = clientID
		display.ClientIDHost = idHost
		return display, nil
	}

	// Not a URL client: re-check the redirect URI against what vouches for it
	// (the client's registration or the allow-list), then name the client.
	if !h.isValidRedirectURI(ctx, redirectURI, clientID) {
		return nil, NewOAuthError(ErrInvalidRequest, "redirect_uri not allowed for this client", http.StatusBadRequest)
	}
	display.SelfReported = true
	if reg, err := h.stateManager.GetClientRegistration(ctx, clientID); err == nil && reg != nil {
		display.Name = cimd.SanitizeClientName(reg.ClientName)
	}
	if display.Name == "" {
		// An opaque (allow-listed) client id is all there is to show.
		display.Name = cimd.SanitizeClientName(clientID)
	}
	if display.Name == "" {
		return nil, NewOAuthError(ErrInvalidRequest, "client not allowed", http.StatusBadRequest)
	}
	return display, nil
}

// displayHost is how a redirect URI's host is shown: host and port, with an
// internationalized host name in its ASCII (punycode) form, so a look-alike of
// a trusted name cannot pass for it.
func displayHost(u *url.URL) string {
	host := u.Hostname()
	if ascii, err := idna.Lookup.ToASCII(host); err == nil && ascii != "" {
		host = ascii
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		host += ":" + port
	}
	return host
}

// redirectHost is displayHost of a redirect URI string, for logs.
func redirectHost(redirectURI string) string {
	if u, err := url.Parse(redirectURI); err == nil {
		return displayHost(u)
	}
	return ""
}

// displayHostPort returns the host (and port, if any) of uri as it is shown to
// the user: ASCII/punycode, with IPv6 literals bracketed.
func displayHostPort(uri string) (string, bool) {
	u, err := url.Parse(uri)
	if err != nil || u.Hostname() == "" {
		return "", false
	}
	host, err := cimd.DisplayHost(u.Hostname())
	if err != nil {
		return "", false
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		host += ":" + port
	}
	return host, true
}

// bindSelectionToBrowser records that this browser is being shown the
// selection page: a random secret goes into an HttpOnly
// cookie and its hash into the selection session. Only this browser can then
// pick a provider for the session, so a selection link prepared by someone
// else cannot carry a victim past the page that shows who is asking.
func (h *Handlers) bindSelectionToBrowser(w http.ResponseWriter, r *http.Request, sessionID string) error {
	params, err := h.stateManager.GetSelectionSession(r.Context(), sessionID)
	if err != nil || params == nil {
		return fmt.Errorf("selection session expired or invalid")
	}
	secret, err := randomToken()
	if err != nil {
		return err
	}
	// The page also gives the browser its browser-binding secret (or confirms
	// the one it has): the acknowledgement /authorize later accepts is issued
	// to that secret, so it cannot be paired with a different browser.
	if _, err := h.ensureBrowserSecret(w, r); err != nil {
		return err
	}
	params[selectionBindKey] = sha256Hex(secret)
	if err := h.stateManager.UpdateSelectionSession(r.Context(), sessionID, params); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     h.selectionBindCookieName(),
		Value:    secret,
		Path:     h.selectionCookiePath("/oauth/select-provider"),
		MaxAge:   state.SelectionTTL,
		HttpOnly: true,
		Secure:   h.serverIsHTTPS(),
		// Strict: the cookie is only sent when the request was initiated from
		// this site, i.e. by a click on the selection page. With Lax, a page
		// on another site could open the selection page in a popup (setting
		// the cookie) and then navigate the popup to a provider link, since
		// Lax cookies ride along on cross-site top-level GETs.
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

// sameOriginRequest reports whether the browser says the request was initiated
// by a page of this origin. Clients that send no Sec-Fetch-Site header (not a
// browser, or an old one) are judged by the cookies alone.
func sameOriginRequest(r *http.Request) bool {
	site := r.Header.Get("Sec-Fetch-Site")
	return site == "" || site == "same-origin"
}

// selectionBoundToBrowser reports whether this request comes from the browser
// that was shown the selection page for the session. A session nobody was
// shown the page for carries no binding and never passes, whatever the client.
func (h *Handlers) selectionBoundToBrowser(r *http.Request, params map[string]string) bool {
	want := params[selectionBindKey]
	c, err := r.Cookie(h.selectionBindCookieName())
	if want == "" || err != nil || c.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sha256Hex(c.Value)), []byte(want)) == 1
}

// CompleteProviderSelection handles the provider choice for a selection
// session (from the page's form or its provider links): it consumes the
// session and sends the browser back to /authorize with the provider set.
func (h *Handlers) CompleteProviderSelection(w http.ResponseWriter, r *http.Request, sessionID, provider string) {
	params, _ := h.stateManager.ConsumeSelectionSession(r.Context(), sessionID)
	if params == nil {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Session expired or invalid", http.StatusBadRequest))
		return
	}
	if !sameOriginRequest(r) {
		// Defence in depth for the Strict cookies: browsers say who initiated
		// the request. This also covers a same-site (sibling subdomain) page,
		// which Strict cookies do not stop.
		h.logger.Warn("Provider selection initiated from another origin", "redirect_host", redirectHost(params["redirect_uri"]), "sec_fetch_site", r.Header.Get("Sec-Fetch-Site"))
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Sign-in must be started from the application that requested it; open its sign-in link again", http.StatusBadRequest))
		return
	}
	if !h.selectionBoundToBrowser(r, params) {
		// The session is consumed either way, so a leaked link is single-use.
		h.logger.Warn("Provider selection from a browser that was not shown the selection page", "redirect_host", redirectHost(params["redirect_uri"]))
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Sign-in must be started from the application that requested it; open its sign-in link again", http.StatusBadRequest))
		return
	}
	delete(params, selectionBindKey)
	params["provider"] = provider
	h.RedirectToAuthorize(w, r, params)
}

// RedirectToAuthorize sends the browser back to /authorize with the stored
// OAuth parameters plus the chosen provider (set by the caller in params).
//
// It also issues a single-use acknowledgement proving the browser went through
// the selection page, which is where the client name and redirect hostname are
// shown. /authorize refuses to skip that page for any client without it. The
// acknowledgement is bound to the request parameters and, through a cookie, to
// this browser, so a link prepared by someone else does not carry it over.
func (h *Handlers) RedirectToAuthorize(w http.ResponseWriter, r *http.Request, params map[string]string) {
	token, err := randomToken()
	secret, err2 := randomToken()
	if err != nil || err2 != nil {
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to generate session", http.StatusInternalServerError))
		return
	}
	// The acknowledgement belongs to the browser that holds the browser-binding
	// secret the selection page gave it; /authorize accepts it from that
	// browser only. A browser without the secret has not been through the page.
	browserSecret, ok := h.browserSecretOf(r)
	if !ok {
		h.logger.Warn("Provider selection from a browser without a browser binding", "redirect_host", redirectHost(params["redirect_uri"]))
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Sign-in must be started from the application that requested it; open its sign-in link again", http.StatusBadRequest))
		return
	}
	value := sha256Hex(secret) + "|" + ackBinding(params["client_id"], params["redirect_uri"], params["state"], params["code_challenge"]) + "|" + sha256Hex(browserSecret)
	if err := h.stateManager.SetEphemeral(r.Context(), state.SelectionAckPrefix+token, value, state.SelectionAckTTL); err != nil {
		h.logger.Error("Failed to store selection acknowledgement", "error", err)
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to store session", http.StatusInternalServerError))
		return
	}
	http.SetCookie(w, h.ackCookie(secret, int(state.SelectionAckTTL.Seconds())))
	params[selectionAckParam] = token

	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	http.Redirect(w, r, "/authorize?"+q.Encode(), http.StatusFound)
}

// consumeSelectionAck reports whether this /authorize request carries a valid
// acknowledgement from the selection page for exactly these parameters. The
// acknowledgement is single-use.
func (h *Handlers) consumeSelectionAck(w http.ResponseWriter, r *http.Request, clientID, redirectURI, stateParam, challenge string) bool {
	token := r.URL.Query().Get(selectionAckParam)
	c, err := r.Cookie(h.selectionAckCookieName())
	if token == "" || err != nil || c.Value == "" {
		return false
	}
	stored, err := h.stateManager.ConsumeEphemeral(r.Context(), state.SelectionAckPrefix+token)
	if err != nil || stored == "" {
		return false
	}
	http.SetCookie(w, h.ackCookie("", -1))
	// The acknowledgement was issued to one browser: the one now presenting it
	// must hold that browser's binding secret, which is also the secret the
	// transaction is then bound to. A planted acknowledgement cookie of a known
	// value cannot be paired with a browser that is not the one it was issued to.
	browserSecret, ok := h.browserSecretOf(r)
	if !ok {
		return false
	}
	want := sha256Hex(c.Value) + "|" + ackBinding(clientID, redirectURI, stateParam, challenge) + "|" + sha256Hex(browserSecret)
	return subtle.ConstantTimeCompare([]byte(stored), []byte(want)) == 1
}

// hostSelectionCookiePrefix is what the selection cookies are named with over
// https: __Host- makes browsers refuse them unless they are Secure, Path=/ and
// have no Domain, so a page on a sibling subdomain cannot plant a value it knows.
const hostSelectionCookiePrefix = "__Host-"

func (h *Handlers) selectionAckCookieName() string {
	if h.serverIsHTTPS() {
		return hostSelectionCookiePrefix + selectionAckCookie
	}
	return selectionAckCookie
}

func (h *Handlers) selectionBindCookieName() string {
	if h.serverIsHTTPS() {
		return hostSelectionCookiePrefix + selectionBindCookie
	}
	return selectionBindCookie
}

// selectionCookiePath is the path of a selection cookie: the __Host- prefix
// forces "/" over https; plain-http local development keeps the narrow path.
func (h *Handlers) selectionCookiePath(narrow string) string {
	if h.serverIsHTTPS() {
		return "/"
	}
	return narrow
}

func (h *Handlers) ackCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     h.selectionAckCookieName(),
		Value:    value,
		Path:     h.selectionCookiePath("/authorize"),
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.serverIsHTTPS(),
		// Strict: sent on the /authorize redirect that the provider choice
		// (same-site) started, not on anything a third party navigates to.
		SameSite: http.SameSiteStrictMode,
	}
}

func ackBinding(clientID, redirectURI, stateParam, challenge string) string {
	return sha256Hex(clientID + "\x00" + redirectURI + "\x00" + stateParam + "\x00" + challenge)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
