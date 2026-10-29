package endpoints

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/cimd"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
)

// CIMD (OAuth Client ID Metadata Documents) support for the authorization
// endpoint. A client_id that looks like a URL is resolved ONLY through its
// metadata document: it never falls back to dynamic registrations or to the
// global redirect URI allow-list.

const (
	selectionAckParam  = "selection_ack"
	selectionAckCookie = "lc_oauth_selection"
)

// cimdResolver resolves a CIMD client_id to its validated metadata document.
type cimdResolver interface {
	Resolve(ctx context.Context, clientID string) (*cimd.Document, error)
}

// clientDisplay is what the provider-selection page shows about a CIMD client.
type clientDisplay struct {
	Name         string
	ClientIDHost string
	ClientID     string
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

// selectionDisplay builds the client details for the selection page, or nil for
// clients that are not CIMD clients. Any problem with a CIMD client is an error
// (the page is never shown without the details it must show).
func (h *Handlers) selectionDisplay(ctx context.Context, sessionID string) (*clientDisplay, *OAuthError) {
	params, err := h.stateManager.GetSelectionSession(ctx, sessionID)
	if err != nil || params == nil {
		return nil, nil // expired; picking a provider will report it
	}
	clientID := params["client_id"]
	if !cimd.LooksLikeURL(clientID) {
		return nil, nil
	}
	redirectURI := params["redirect_uri"]
	doc, oerr := h.resolveCIMD(ctx, clientID)
	if oerr != nil {
		return nil, oerr
	}
	if !doc.HasRedirectURI(redirectURI) {
		return nil, NewOAuthError(ErrInvalidRequest, "redirect_uri not allowed for this client", http.StatusBadRequest)
	}
	u, err := url.Parse(redirectURI)
	if err != nil || u.Host == "" {
		return nil, NewOAuthError(ErrInvalidRequest, "redirect_uri not allowed for this client", http.StatusBadRequest)
	}
	return &clientDisplay{
		Name:         doc.ClientName,
		ClientID:     clientID,
		ClientIDHost: clientHost(clientID),
		RedirectHost: u.Host,
		Localhost:    cimd.IsLoopbackRedirect(redirectURI),
	}, nil
}

// RedirectToAuthorize sends the browser back to /authorize with the stored
// OAuth parameters plus the chosen provider (set by the caller in params).
//
// For CIMD clients it also issues a single-use acknowledgement proving the
// browser went through the selection page, which is where the client name and
// redirect hostname are shown. /authorize refuses to skip that page for CIMD
// clients without it. The acknowledgement is bound to the request parameters
// and, through a cookie, to this browser, so a link prepared by someone else
// does not carry it over.
func (h *Handlers) RedirectToAuthorize(w http.ResponseWriter, r *http.Request, params map[string]string) {
	if cimd.LooksLikeURL(params["client_id"]) {
		token, err := randomToken()
		secret, err2 := randomToken()
		if err != nil || err2 != nil {
			WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to generate session", http.StatusInternalServerError))
			return
		}
		value := sha256Hex(secret) + "|" + ackBinding(params["client_id"], params["redirect_uri"], params["state"], params["code_challenge"])
		if err := h.stateManager.SetEphemeral(r.Context(), state.SelectionAckPrefix+token, value, state.SelectionAckTTL); err != nil {
			h.logger.Error("Failed to store selection acknowledgement", "error", err)
			WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to store session", http.StatusInternalServerError))
			return
		}
		http.SetCookie(w, h.ackCookie(secret, int(state.SelectionAckTTL.Seconds())))
		params[selectionAckParam] = token
	}

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
	c, err := r.Cookie(selectionAckCookie)
	if token == "" || err != nil || c.Value == "" {
		return false
	}
	stored, err := h.stateManager.ConsumeEphemeral(r.Context(), state.SelectionAckPrefix+token)
	if err != nil || stored == "" {
		return false
	}
	http.SetCookie(w, h.ackCookie("", -1))
	want := sha256Hex(c.Value) + "|" + ackBinding(clientID, redirectURI, stateParam, challenge)
	return subtle.ConstantTimeCompare([]byte(stored), []byte(want)) == 1
}

func (h *Handlers) ackCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     selectionAckCookie,
		Value:    value,
		Path:     "/authorize",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   strings.HasPrefix(h.metadataProvider.GetServerURL(), "https://"),
		SameSite: http.SameSiteLaxMode,
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
