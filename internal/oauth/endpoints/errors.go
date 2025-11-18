package endpoints

import (
	"encoding/json"
	"net/http"
)

// OAuthError represents an OAuth 2.0 error response
type OAuthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	StatusCode       int    `json:"-"`
}

// OAuth error codes (RFC 6749)
const (
	ErrInvalidRequest          = "invalid_request"
	ErrUnauthorizedClient      = "unauthorized_client"
	ErrAccessDenied            = "access_denied"
	ErrUnsupportedResponseType = "unsupported_response_type"
	ErrInvalidScope            = "invalid_scope"
	ErrServerError             = "server_error"
	ErrTemporarilyUnavailable  = "temporarily_unavailable"
	ErrInvalidClient           = "invalid_client"
	ErrInvalidGrant            = "invalid_grant"
	ErrUnsupportedGrantType    = "unsupported_grant_type"
)

// NewOAuthError creates a new OAuth error
func NewOAuthError(code, description string, statusCode int) *OAuthError {
	return &OAuthError{
		Error:            code,
		ErrorDescription: description,
		StatusCode:       statusCode,
	}
}

// WriteOAuthError writes an OAuth error response
func WriteOAuthError(w http.ResponseWriter, err *OAuthError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.StatusCode)
	json.NewEncoder(w).Encode(err)
}

// WriteOAuthErrorRedirect writes an OAuth error as a redirect
func WriteOAuthErrorRedirect(w http.ResponseWriter, r *http.Request, redirectURI, state, errorCode, errorDescription string) {
	// Build error redirect URL
	redirectURL := redirectURI + "?error=" + errorCode
	if errorDescription != "" {
		redirectURL += "&error_description=" + errorDescription
	}
	if state != "" {
		redirectURL += "&state=" + state
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// writeHTML writes an HTML response
func writeHTML(w http.ResponseWriter, statusCode int, html string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	w.Write([]byte(html))
}
