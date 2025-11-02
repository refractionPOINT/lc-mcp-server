package endpoints

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/firebase"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/metadata"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/token"
	"log/slog"
)

// Handlers contains all OAuth endpoint handlers
type Handlers struct {
	stateManager        *state.Manager
	tokenManager        *token.Manager
	firebaseClient      *firebase.Client
	metadataProvider    *metadata.Provider
	logger              *slog.Logger
	templates           *template.Template
	allowedRedirectURIs []string // SECURITY: Allowlist of permitted redirect URIs
}

// NewHandlers creates new OAuth endpoint handlers
func NewHandlers(stateManager *state.Manager, tokenManager *token.Manager, firebaseClient *firebase.Client, metadataProvider *metadata.Provider, allowedRedirectURIs []string, logger *slog.Logger) (*Handlers, error) {
	// Load templates (will create simple inline templates)
	tmpl, err := template.New("oauth").Parse(providerSelectionHTML + mfaChallengeHTML + errorPageHTML)
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	return &Handlers{
		stateManager:        stateManager,
		tokenManager:        tokenManager,
		firebaseClient:      firebaseClient,
		metadataProvider:    metadataProvider,
		logger:              logger,
		templates:           tmpl,
		allowedRedirectURIs: allowedRedirectURIs,
	}, nil
}

// HandleAuthorize handles GET /authorize - OAuth authorization endpoint
func (h *Handlers) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Method not allowed", http.StatusMethodNotAllowed))
		return
	}

	// Parse and validate request
	params := r.URL.Query()

	responseType := params.Get("response_type")
	clientID := params.Get("client_id")
	redirectURI := params.Get("redirect_uri")
	stateParam := params.Get("state")
	codeChallenge := params.Get("code_challenge")
	codeChallengeMethod := params.Get("code_challenge_method")
	scope := params.Get("scope")
	resource := params.Get("resource")
	provider := params.Get("provider")

	// Validate required parameters
	if responseType != "code" {
		WriteOAuthError(w, NewOAuthError(ErrUnsupportedResponseType, "Only 'code' response type is supported", http.StatusBadRequest))
		return
	}
	if clientID == "" || redirectURI == "" || stateParam == "" {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Missing required parameters", http.StatusBadRequest))
		return
	}
	if codeChallenge == "" || codeChallengeMethod != "S256" {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "PKCE with S256 is required", http.StatusBadRequest))
		return
	}

	// SECURITY: Validate redirect URI against allowlist (exact match)
	if !h.isRedirectURIAllowed(redirectURI) {
		h.logger.Warn("Rejected unauthorized redirect_uri", "uri", redirectURI)
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "redirect_uri not allowed", http.StatusBadRequest))
		return
	}

	// Filter scope to supported scopes
	if scope == "" {
		scope = metadata.DefaultScope
	} else {
		scope = metadata.FilterScopeToSupported(scope)
	}

	// Check if provider selection is needed
	if provider == "" {
		// Redirect to provider selection page
		sessionID, err := h.stateManager.GenerateSelectionSessionID()
		if err != nil {
			h.logger.Error("")
			WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to generate session", http.StatusInternalServerError))
			return
		}

		// Store OAuth params
		paramsMap := map[string]string{
			"response_type":         responseType,
			"client_id":             clientID,
			"redirect_uri":          redirectURI,
			"state":                 stateParam,
			"code_challenge":        codeChallenge,
			"code_challenge_method": codeChallengeMethod,
			"scope":                 scope,
			"resource":              resource,
		}

		if err := h.stateManager.StoreSelectionSession(r.Context(), sessionID, paramsMap); err != nil {
			h.logger.Error("")
			WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to store session", http.StatusInternalServerError))
			return
		}

		// Redirect to provider selection page
		selectionURL := h.metadataProvider.GetServerURL() + "/oauth/select-provider?session=" + sessionID
		http.Redirect(w, r, selectionURL, http.StatusFound)
		return
	}

	// Normalize provider
	providerID := h.normalizeProvider(provider)
	if providerID == "" {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Unsupported provider", http.StatusBadRequest))
		return
	}

	// Store OAuth state
	if resource == "" {
		resource = h.metadataProvider.GetServerURL()
	}

	oauthState := state.NewOAuthState(stateParam, codeChallenge, codeChallengeMethod, redirectURI, clientID, scope, resource, providerID)
	if err := h.stateManager.StoreOAuthState(r.Context(), oauthState); err != nil {
		h.logger.Error("")
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to store state", http.StatusInternalServerError))
		return
	}

	// Create Firebase auth URI
	serverURL := h.metadataProvider.GetServerURL()
	callbackURL := serverURL + "/oauth/callback"

	sessionID, firebaseAuthURI, err := h.firebaseClient.CreateAuthURI(r.Context(), providerID, callbackURL, []string{"openid", "email", "profile"})
	if err != nil {
		h.logger.Error("")
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to initiate authentication", http.StatusInternalServerError))
		return
	}

	// Extract Firebase state from auth URI
	parsedURI, _ := url.Parse(firebaseAuthURI)
	firebaseState := parsedURI.Query().Get("state")

	// Store bidirectional mappings
	ctx := r.Context()
	h.stateManager.StoreSelectionSession(ctx, "oauth:session:"+stateParam, map[string]string{"firebase_state": firebaseState})
	h.stateManager.StoreSelectionSession(ctx, "oauth:state:"+firebaseState, map[string]string{"oauth_state": stateParam})
	h.stateManager.StoreSelectionSession(ctx, "oauth:fbsession:"+firebaseState, map[string]string{"session_id": sessionID})

	// Redirect to Firebase OAuth URL
	http.Redirect(w, r, firebaseAuthURI, http.StatusFound)
}

// HandleCallback handles GET /oauth/callback - OAuth callback from provider
func (h *Handlers) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Validate callback
	queryString, err := h.firebaseClient.ValidateProviderCallback(r.URL.RequestURI())
	if err != nil {
		h.logger.Error("")
		writeHTML(w, http.StatusBadRequest, "<h1>OAuth Error</h1><p>Invalid callback</p>")
		return
	}

	// Extract Firebase state from query
	params, _ := url.ParseQuery(queryString)
	firebaseState := params.Get("state")

	// Get OAuth state from Firebase state mapping
	stateData, _ := h.stateManager.ConsumeSelectionSession(r.Context(), "oauth:state:"+firebaseState)
	if stateData == nil {
		h.logger.Error("OAuth state not found for Firebase state")
		writeHTML(w, http.StatusBadRequest, "<h1>OAuth Error</h1><p>State expired or invalid</p>")
		return
	}

	oauthStateParam := stateData["oauth_state"]

	// Get OAuth state
	oauthState, err := h.stateManager.ConsumeOAuthState(r.Context(), oauthStateParam)
	if err != nil || oauthState == nil {
		h.logger.Error("Failed to get OAuth state")
		writeHTML(w, http.StatusBadRequest, "<h1>OAuth Error</h1><p>State expired</p>")
		return
	}

	// Get Firebase session ID
	sessionData, _ := h.stateManager.ConsumeSelectionSession(r.Context(), "oauth:fbsession:"+firebaseState)
	if sessionData == nil {
		h.logger.Error("Firebase session not found")
		writeHTML(w, http.StatusBadRequest, "<h1>OAuth Error</h1><p>Session expired</p>")
		return
	}

	sessionID := sessionData["session_id"]

	// Sign in with IdP
	requestURI := h.metadataProvider.GetServerURL() + "/oauth/callback"
	resp, err := h.firebaseClient.SignInWithIdp(r.Context(), requestURI, queryString, sessionID, oauthState.Provider)

	// Check for MFA required
	if mfaErr, ok := err.(*firebase.MFARequiredError); ok {
		// Store MFA session
		mfaSessionID, _ := h.stateManager.GenerateMFASessionID()
		mfaSession := state.NewMFASession(mfaErr.MFAPendingCredential, mfaErr.MFAEnrollmentID, oauthStateParam, mfaErr.DisplayName, mfaErr.LocalID, mfaErr.Email, &mfaErr.PendingToken)
		h.stateManager.StoreMFASession(r.Context(), mfaSessionID, mfaSession)

		// Redirect to MFA challenge page
		mfaURL := h.metadataProvider.GetServerURL() + "/oauth/mfa-challenge?session=" + mfaSessionID
		http.Redirect(w, r, mfaURL, http.StatusFound)
		return
	}

	if err != nil {
		h.logger.Error("")
		WriteOAuthErrorRedirect(w, r, oauthState.RedirectURI, oauthState.State, ErrServerError, "Authentication failed")
		return
	}

	// Generate authorization code
	code, _ := h.stateManager.GenerateAuthorizationCode()

	// Parse expires_in and calculate absolute expiration time
	expiresIn := int64(3600)
	if resp.ExpiresIn != "" {
		fmt.Sscanf(resp.ExpiresIn, "%d", &expiresIn)
	}
	expiresAt := time.Now().Unix() + expiresIn

	authCode := state.NewAuthorizationCode(code, oauthState.State, resp.LocalID, resp.IDToken, resp.RefreshToken, expiresAt, oauthState.RedirectURI, oauthState.ClientID, oauthState.Scope, &oauthState.CodeChallenge, &oauthState.CodeChallengeMethod)
	h.stateManager.StoreAuthorizationCode(r.Context(), authCode)

	// Redirect to client with code
	redirectURL := oauthState.RedirectURI + "?code=" + code + "&state=" + oauthState.State
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// HandleToken handles POST /token - OAuth token endpoint
func (h *Handlers) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Method not allowed", http.StatusMethodNotAllowed))
		return
	}

	r.ParseForm()
	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		h.handleRefreshTokenGrant(w, r)
	default:
		WriteOAuthError(w, NewOAuthError(ErrUnsupportedGrantType, "Unsupported grant type", http.StatusBadRequest))
	}
}

func (h *Handlers) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	_ = r.FormValue("client_id") // client_id validation not implemented
	codeVerifier := r.FormValue("code_verifier")

	if code == "" || redirectURI == "" || codeVerifier == "" {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Missing required parameters", http.StatusBadRequest))
		return
	}

	// Consume authorization code
	authCode, err := h.stateManager.ConsumeAuthorizationCode(r.Context(), code)
	if err != nil || authCode == nil {
		WriteOAuthError(w, NewOAuthError(ErrInvalidGrant, "Invalid or expired authorization code", http.StatusBadRequest))
		return
	}

	// Validate PKCE
	if !h.validatePKCE(codeVerifier, *authCode.CodeChallenge) {
		WriteOAuthError(w, NewOAuthError(ErrInvalidGrant, "Invalid code verifier", http.StatusBadRequest))
		return
	}

	// Create token response
	tokenResp, err := h.tokenManager.CreateTokenResponse(r.Context(), authCode.UID, authCode.FirebaseIDToken, authCode.FirebaseRefreshToken, authCode.FirebaseExpiresAt, authCode.Scope)
	if err != nil {
		h.logger.Error("")
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to issue tokens", http.StatusInternalServerError))
		return
	}

	writeJSON(w, http.StatusOK, tokenResp)
}

func (h *Handlers) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")

	if refreshToken == "" {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Missing refresh_token", http.StatusBadRequest))
		return
	}

	// Refresh access token
	tokenResp, err := h.tokenManager.RefreshAccessToken(r.Context(), refreshToken)
	if err != nil {
		WriteOAuthError(w, NewOAuthError(ErrInvalidGrant, "Invalid or expired refresh token", http.StatusBadRequest))
		return
	}

	writeJSON(w, http.StatusOK, tokenResp)
}

// HandleRevoke handles POST /revoke - Token revocation
func (h *Handlers) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Method not allowed", http.StatusMethodNotAllowed))
		return
	}

	r.ParseForm()
	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint")

	if token == "" {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Missing token", http.StatusBadRequest))
		return
	}

	h.tokenManager.RevokeToken(r.Context(), token, tokenTypeHint)

	// Always return 200 OK per OAuth spec
	w.WriteHeader(http.StatusOK)
}

// HandleIntrospect handles POST /introspect - Token introspection
func (h *Handlers) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Method not allowed", http.StatusMethodNotAllowed))
		return
	}

	r.ParseForm()
	token := r.FormValue("token")

	if token == "" {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Missing token", http.StatusBadRequest))
		return
	}

	resp, err := h.tokenManager.IntrospectToken(r.Context(), token)
	if err != nil {
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Introspection failed", http.StatusInternalServerError))
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// Helper functions

func (h *Handlers) normalizeProvider(provider string) string {
	switch provider {
	case "google", "google.com":
		return "google.com"
	case "microsoft", "microsoft.com":
		return "microsoft.com"
	default:
		return ""
	}
}

func (h *Handlers) validatePKCE(verifier, challenge string) bool {
	hash := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])
	return computed == challenge
}

func (h *Handlers) isRedirectURIAllowed(redirectURI string) bool {
	// SECURITY: Exact match validation - no wildcards, no prefix matching
	for _, allowed := range h.allowedRedirectURIs {
		if redirectURI == allowed {
			return true
		}
	}
	return false
}

// HTML templates (inline for simplicity)
const providerSelectionHTML = `{{define "provider_selection"}}
<!DOCTYPE html>
<html>
<head><title>Select Provider</title></head>
<body>
<h1>Select Authentication Provider</h1>
<form method="POST" action="/oauth/select-provider">
<input type="hidden" name="session" value="{{.SessionID}}">
<button type="submit" name="provider" value="google">Google</button>
<button type="submit" name="provider" value="microsoft">Microsoft</button>
</form>
</body>
</html>
{{end}}`

const mfaChallengeHTML = `{{define "mfa_challenge"}}
<!DOCTYPE html>
<html>
<head><title>MFA Verification</title></head>
<body>
<h1>Two-Factor Authentication</h1>
<form method="POST" action="/oauth/mfa-verify">
<input type="hidden" name="session" value="{{.SessionID}}">
<label>Enter 6-digit code:</label>
<input type="text" name="code" maxlength="6" required>
<button type="submit">Verify</button>
</form>
</body>
</html>
{{end}}`

const errorPageHTML = `{{define "error"}}
<!DOCTYPE html>
<html>
<head><title>OAuth Error</title></head>
<body>
<h1>Authentication Error</h1>
<p>{{.Error}}</p>
</body>
</html>
{{end}}`

func (h *Handlers) HandleProviderSelection(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method == http.MethodGet {
		h.templates.ExecuteTemplate(w, "provider_selection", map[string]string{"SessionID": sessionID})
	} else {
		// Handle POST - provider selected
		provider := r.FormValue("provider")
		params, _ := h.stateManager.ConsumeSelectionSession(r.Context(), sessionID)
		params["provider"] = provider
		// Build authorize URL with provider
		q := url.Values{}
		for k, v := range params {
			q.Set(k, v)
		}
		authorizeURL := "/authorize?" + q.Encode()
		http.Redirect(w, r, authorizeURL, http.StatusFound)
	}
}

func (h *Handlers) HandleMFAChallenge(w http.ResponseWriter, r *http.Request, sessionID string) {
	h.templates.ExecuteTemplate(w, "mfa_challenge", map[string]string{"SessionID": sessionID})
}

func (h *Handlers) HandleMFAVerify(w http.ResponseWriter, r *http.Request, sessionID, code string) {
	mfaSession, _ := h.stateManager.ConsumeMFASession(r.Context(), sessionID)
	if mfaSession == nil {
		writeHTML(w, http.StatusBadRequest, "<h1>MFA Error</h1><p>Session expired</p>")
		return
	}

	// Verify MFA code
	resp, err := h.firebaseClient.FinalizeMFASignIn(r.Context(), mfaSession.MFAPendingCredential, mfaSession.MFAEnrollmentID, code)
	if err != nil {
		h.logger.Error("")
		writeHTML(w, http.StatusBadRequest, "<h1>MFA Error</h1><p>Invalid code</p>")
		return
	}

	// Get original OAuth state
	oauthState, _ := h.stateManager.GetOAuthState(r.Context(), mfaSession.OAuthState)
	if oauthState == nil {
		writeHTML(w, http.StatusBadRequest, "<h1>Error</h1><p>OAuth state expired</p>")
		return
	}

	// Generate authorization code and redirect
	authCode, _ := h.stateManager.GenerateAuthorizationCode()
	expiresIn := int64(3600)
	if resp.ExpiresIn != "" {
		fmt.Sscanf(resp.ExpiresIn, "%d", &expiresIn)
	}
	expiresAt := time.Now().Unix() + expiresIn

	authCodeData := state.NewAuthorizationCode(authCode, oauthState.State, resp.LocalID, resp.IDToken, resp.RefreshToken, expiresAt, oauthState.RedirectURI, oauthState.ClientID, oauthState.Scope, &oauthState.CodeChallenge, &oauthState.CodeChallengeMethod)
	h.stateManager.StoreAuthorizationCode(r.Context(), authCodeData)

	redirectURL := oauthState.RedirectURI + "?code=" + authCode + "&state=" + oauthState.State
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// HandleProtectedResourceMetadata handles RFC 9728 Protected Resource Metadata requests
func (h *Handlers) HandleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := h.metadataProvider.GetProtectedResourceMetadata()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "%s", metadata)
}

// HandleAuthorizationServerMetadata handles RFC 8414 Authorization Server Metadata requests
func (h *Handlers) HandleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := h.metadataProvider.GetAuthorizationServerMetadata()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "%s", metadata)
}
