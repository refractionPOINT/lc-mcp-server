package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

// errInvalidCredentials marks a presented credential the server has rejected
// (unknown, expired or malformed token), as opposed to a failure to check it
// (Redis or Firebase unavailable). Only the former may be answered with an
// HTTP 401: a 401 makes an OAuth client refresh or re-run the login, which is
// right for a dead token and wrong for a transient backend error.
var errInvalidCredentials = errors.New("invalid credentials")

// requestHasCredentials reports whether a request carries a credential the
// MCP endpoint accepts, or carries none and the server has its own credentials
// to fall back on. It does not validate them. It agrees with resolveRequestAuth:
// a request that presents credential headers short of a complete set has no
// credentials, whether or not the server has its own, because it never falls
// back to them.
func (s *Server) requestHasCredentials(r *http.Request) bool {
	lcUID, lcOID, lcAPIKey := r.Header.Get("X-LC-UID"), r.Header.Get("X-LC-OID"), r.Header.Get("X-LC-API-KEY")
	if r.Header.Get("Authorization") != "" {
		return true
	}
	if lcAPIKey != "" && (lcUID != "" || lcOID != "") {
		return true
	}
	if lcUID != "" || lcOID != "" || lcAPIKey != "" {
		return false
	}
	return s.serverAuthCtx != nil && s.serverAuthCtx.HasCredentials()
}

// writeAuthChallenge answers with HTTP 401 and a WWW-Authenticate header, as
// the MCP authorization spec requires. MCP clients (Grok Bot, Cursor, Claude)
// only start the OAuth flow, or refresh an expired token, on this status; a
// JSON-RPC error inside an HTTP 200 leaves them stuck with failing tool calls.
// The header points to the protected resource metadata, from which the client
// discovers the authorization server.
//
// oauthError is an RFC 6750 error code ("invalid_token") or "" when no
// credential was presented at all.
func (s *Server) writeAuthChallenge(w http.ResponseWriter, r *http.Request, id json.RawMessage, oauthError, description string) {
	var challenge string
	if s.metadataProvider != nil {
		// RFC 6750 3.1: a request with no credential gets no error attributes.
		headerDescription := ""
		if oauthError != "" {
			headerDescription = description
		}
		// Point at the metadata document for the exact MCP path the client used.
		challenge = s.metadataProvider.GenerateWWWAuthenticateHeaderForResource(s.challengeResourcePath(r), oauthError, headerDescription, "", http.StatusUnauthorized)
	} else {
		// OAuth is not configured (API key or server credential deployments):
		// there is no metadata to point to, but the header is still mandatory.
		challenge = `Bearer realm="limacharlie-mcp"`
		if oauthError != "" {
			challenge += fmt.Sprintf(`, error="%s", error_description="%s"`, oauthError, description)
		}
	}
	w.Header().Set("WWW-Authenticate", challenge)
	s.writeRPCError(w, id, newRPCError(http.StatusUnauthorized, rpcServerError, "Unauthorized", description))
}

// incompleteCredentialsDetail explains which credential headers a request
// presented without a usable combination.
func incompleteCredentialsDetail(uid, oid, apiKey string) string {
	var present []string
	if uid != "" {
		present = append(present, "X-LC-UID")
	}
	if oid != "" {
		present = append(present, "X-LC-OID")
	}
	if apiKey != "" {
		present = append(present, "X-LC-API-KEY")
	}
	return fmt.Sprintf("Incomplete credentials (%s presented): provide Authorization, X-LC-UID + X-LC-API-KEY, or X-LC-OID + X-LC-API-KEY headers",
		strings.Join(present, ", "))
}

// writeInsufficientScope answers a tool call that the request's OAuth access
// token is not scoped for, as the MCP authorization spec ("Runtime
// Insufficient Scope Errors", 2026-07-28) prescribes: HTTP 403 with a
// WWW-Authenticate Bearer challenge carrying error="insufficient_scope", the
// scope needed for the operation and the protected resource metadata URL, so a
// client can step up to the needed scope and retry. err is an
// *auth.InsufficientScopeError.
func (s *Server) writeInsufficientScope(w http.ResponseWriter, r *http.Request, id json.RawMessage, err error) {
	var scopeErr *auth.InsufficientScopeError
	if !errors.As(err, &scopeErr) {
		scopeErr = &auth.InsufficientScopeError{Tool: "unknown", Required: auth.ScopeWrite}
	}
	// No quotes in the text: it is also an auth-param quoted-string.
	description := fmt.Sprintf("The access token does not grant the %s scope required to call %s", scopeErr.Required, scopeErr.Tool)

	var challenge string
	if s.metadataProvider != nil {
		challenge = s.metadataProvider.GenerateWWWAuthenticateHeaderForResource(s.challengeResourcePath(r), "insufficient_scope", description, scopeErr.Required, http.StatusForbidden)
	} else {
		challenge = fmt.Sprintf(`Bearer realm="limacharlie-mcp", error="insufficient_scope", scope="%s", error_description="%s"`, scopeErr.Required, description)
	}
	w.Header().Set("WWW-Authenticate", challenge)
	s.logger.Warn("Rejected tool call: insufficient OAuth scope", "tool", scopeErr.Tool, "required", scopeErr.Required, "granted", scopeErr.Granted)
	s.writeRPCError(w, id, newRPCError(http.StatusForbidden, rpcServerError, "Forbidden", description))
}

// challengeResourcePath is the MCP path a challenge's resource_metadata should
// name: the exact endpoint the client used, so the metadata's "resource"
// matches the URL the client is talking to (RFC 9728 section 3.3). The bare
// root path keeps the root document.
func (s *Server) challengeResourcePath(r *http.Request) string {
	if r != nil && r.URL.Path != "/" && s.isMCPEndpointPath(r.URL.Path) {
		return r.URL.Path
	}
	return ""
}
