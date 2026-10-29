package endpoints

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

// buildAuthorizationResponseURL appends params to the client's redirect URI as
// query parameters. Any query already present on the redirect URI is preserved;
// params override same-named entries so a registered URI cannot shadow the
// protocol parameters. Values are percent-encoded.
func buildAuthorizationResponseURL(redirectURI string, params url.Values) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URI: %w", err)
	}
	if u.Scheme == "" {
		return "", fmt.Errorf("invalid redirect URI: missing scheme")
	}
	q := u.Query()
	for k, vs := range params {
		q[k] = vs
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// authorizationResponseParams returns the parameters common to every
// authorization response: state (when the client sent one) and the RFC 9207
// "iss" parameter. iss must equal the "issuer" in the authorization server
// metadata, byte for byte, because clients compare with simple string equality.
func authorizationResponseParams(issuer, state string) url.Values {
	params := url.Values{}
	if state != "" {
		params.Set("state", state)
	}
	params.Set("iss", issuer)
	return params
}

// AuthorizationSuccessURL builds the redirect back to the client carrying the
// authorization code, state and the RFC 9207 iss parameter.
func AuthorizationSuccessURL(issuer, redirectURI, state, code string) (string, error) {
	params := authorizationResponseParams(issuer, state)
	params.Set("code", code)
	return buildAuthorizationResponseURL(redirectURI, params)
}

// WriteOAuthErrorRedirect writes an OAuth error as a redirect to the client,
// including the RFC 9207 iss parameter. If the redirect URI cannot be used it
// fails closed with a local JSON server_error instead of redirecting.
func WriteOAuthErrorRedirect(w http.ResponseWriter, r *http.Request, issuer, redirectURI, state, errorCode, errorDescription string) {
	params := authorizationResponseParams(issuer, state)
	params.Set("error", errorCode)
	if errorDescription != "" {
		params.Set("error_description", errorDescription)
	}

	redirectURL, err := buildAuthorizationResponseURL(redirectURI, params)
	if err != nil {
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to build authorization response", http.StatusInternalServerError))
		return
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
