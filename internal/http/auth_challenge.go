package http

import (
	"errors"
	"fmt"
	"net/http"
)

// errInvalidCredentials marks a presented credential the server has rejected
// (unknown, expired or malformed token), as opposed to a failure to check it
// (Redis or Firebase unavailable). Only the former may be answered with an
// HTTP 401: a 401 makes an OAuth client refresh or re-run the login, which is
// right for a dead token and wrong for a transient backend error.
var errInvalidCredentials = errors.New("invalid credentials")

// requestHasCredentials reports whether a request carries any credential the
// MCP endpoint accepts, or whether the server has its own credentials to fall
// back on. It does not validate them.
func (s *Server) requestHasCredentials(r *http.Request) bool {
	if r.Header.Get("Authorization") != "" {
		return true
	}
	if r.Header.Get("X-LC-API-KEY") != "" && (r.Header.Get("X-LC-UID") != "" || r.Header.Get("X-LC-OID") != "") {
		return true
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
func (s *Server) writeAuthChallenge(w http.ResponseWriter, id interface{}, oauthError, description string) {
	var challenge string
	if s.metadataProvider != nil {
		// RFC 6750 3.1: a request with no credential gets no error attributes.
		headerDescription := ""
		if oauthError != "" {
			headerDescription = description
		}
		challenge = s.metadataProvider.GenerateWWWAuthenticateHeader(oauthError, headerDescription, "", http.StatusUnauthorized)
	} else {
		// OAuth is not configured (API key or server credential deployments):
		// there is no metadata to point to, but the header is still mandatory.
		challenge = `Bearer realm="limacharlie-mcp"`
		if oauthError != "" {
			challenge += fmt.Sprintf(`, error="%s", error_description="%s"`, oauthError, description)
		}
	}
	w.Header().Set("WWW-Authenticate", challenge)
	NewResponseWriter(w, s.logger).WriteJSON(http.StatusUnauthorized, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    -32000,
			"message": "Unauthorized",
			"data":    description,
		},
	})
}
