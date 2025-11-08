package endpoints

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

// contextKey is a type for context keys to avoid collisions
type contextKey string

// Handlers contains all OAuth endpoint handlers
type Handlers struct {
	stateManager        *state.Manager
	tokenManager        *token.Manager
	firebaseClient      *firebase.Client
	metadataProvider    *metadata.Provider
	logger              *slog.Logger
	templates           *template.Template
	allowedRedirectURIs []string // Whitelist of allowed redirect URIs for security
}

// NewHandlers creates new OAuth endpoint handlers
func NewHandlers(stateManager *state.Manager, tokenManager *token.Manager, firebaseClient *firebase.Client, metadataProvider *metadata.Provider, logger *slog.Logger, allowedRedirectURIs []string) (*Handlers, error) {
	// Load templates from files
	tmpl, err := template.ParseGlob("templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	// Validate that at least some redirect URIs are configured
	if len(allowedRedirectURIs) == 0 {
		logger.Warn("No allowed redirect URIs configured - defaulting to localhost only")
		allowedRedirectURIs = []string{
			"http://localhost/callback",
			"http://127.0.0.1/callback",
		}
	}

	logger.Info("OAuth handlers initialized with redirect URI whitelist", "count", len(allowedRedirectURIs))

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

	// SECURITY FIX: Validate redirect URI against whitelist with exact match
	// Prevents open redirect attacks (e.g., https://evil.com)
	if !h.isValidRedirectURI(r.Context(), redirectURI, clientID) {
		h.logger.Warn("Invalid redirect_uri (not in whitelist)", "uri", redirectURI, "client_id", clientID)
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "redirect_uri not allowed for this client", http.StatusBadRequest))
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
			h.logger.Error("Failed to generate selection session ID", "error", err)
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
			h.logger.Error("Failed to store selection session", "error", err, "session_id", sessionID)
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
		h.logger.Error("Failed to store OAuth state", "error", err, "state", stateParam)
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to store state", http.StatusInternalServerError))
		return
	}

	// Create Firebase auth URI
	serverURL := h.metadataProvider.GetServerURL()
	callbackURL := serverURL + "/oauth/callback"

	sessionID, firebaseAuthURI, err := h.firebaseClient.CreateAuthURI(r.Context(), providerID, callbackURL, []string{"openid", "email", "profile"})
	if err != nil {
		h.logger.Error("Failed to create Firebase auth URI", "error", err, "provider", providerID)
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
		h.logger.Error("Failed to validate provider callback", "error", err, "uri", r.URL.RequestURI())
		writeHTML(w, http.StatusBadRequest, "<h1>OAuth Error</h1><p>Invalid callback</p>")
		return
	}

	// Extract Firebase state from query
	params, _ := url.ParseQuery(queryString)
	firebaseState := params.Get("state")

	if firebaseState == "" {
		h.logger.Error("Missing Firebase state in callback")
		writeHTML(w, http.StatusBadRequest, "<h1>OAuth Error</h1><p>Missing state parameter</p>")
		return
	}

	// SECURITY FIX: Atomically consume all OAuth state mappings to prevent TOCTOU race conditions
	// This prevents attacks where an attacker tries to reuse state mappings between check and use
	oauthStateParam, sessionID, err := h.stateManager.ConsumeOAuthStateMappings(r.Context(), firebaseState)
	if err != nil {
		h.logger.Error("Failed to consume OAuth state mappings", "error", err, "firebase_state", firebaseState)
		writeHTML(w, http.StatusBadRequest, "<h1>OAuth Error</h1><p>State expired or invalid</p>")
		return
	}

	// Get OAuth state (don't consume yet - may need it for MFA flow)
	oauthState, err := h.stateManager.GetOAuthState(r.Context(), oauthStateParam)
	if err != nil || oauthState == nil {
		h.logger.Error("Failed to get OAuth state", "error", err, "oauth_state", oauthStateParam)
		writeHTML(w, http.StatusBadRequest, "<h1>OAuth Error</h1><p>State expired</p>")
		return
	}

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
		h.logger.Error("Firebase sign-in failed", "error", err, "provider", oauthState.Provider)
		WriteOAuthErrorRedirect(w, r, oauthState.RedirectURI, oauthState.State, ErrServerError, "Authentication failed")
		return
	}

	// No MFA required - consume OAuth state now that we're completing the flow
	_, err = h.stateManager.ConsumeOAuthState(r.Context(), oauthStateParam)
	if err != nil {
		h.logger.Error("Failed to consume OAuth state")
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
	clientID := r.FormValue("client_id")
	codeVerifier := r.FormValue("code_verifier")

	if code == "" || redirectURI == "" || codeVerifier == "" || clientID == "" {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Missing required parameters", http.StatusBadRequest))
		return
	}

	// Consume authorization code
	authCode, err := h.stateManager.ConsumeAuthorizationCode(r.Context(), code)
	if err != nil || authCode == nil {
		WriteOAuthError(w, NewOAuthError(ErrInvalidGrant, "Invalid or expired authorization code", http.StatusBadRequest))
		return
	}

	// SECURITY FIX: Validate client_id matches the one from authorization request
	// Prevents authorization code theft attacks where attacker uses stolen code with different client
	if clientID != authCode.ClientID {
		h.logger.Warn("Client ID mismatch in token exchange",
			"expected", authCode.ClientID,
			"received", clientID,
			"code", code[:10]+"...")
		WriteOAuthError(w, NewOAuthError(ErrInvalidGrant, "Invalid client credentials", http.StatusBadRequest))
		return
	}

	// SECURITY FIX: Validate redirect_uri matches the one from authorization request
	// Prevents redirect URI manipulation attacks during token exchange
	if redirectURI != authCode.RedirectURI {
		h.logger.Warn("Redirect URI mismatch in token exchange",
			"expected", authCode.RedirectURI,
			"received", redirectURI,
			"client_id", clientID,
			"code", code[:10]+"...")
		WriteOAuthError(w, NewOAuthError(ErrInvalidGrant, "redirect_uri mismatch", http.StatusBadRequest))
		return
	}

	// Log what we retrieved from the authorization code
	h.logger.Info("Retrieved authorization code", "uid", authCode.UID, "has_uid", authCode.UID != "", "scope", authCode.Scope, "client_id", clientID)

	// Validate PKCE
	if !h.validatePKCE(codeVerifier, *authCode.CodeChallenge) {
		WriteOAuthError(w, NewOAuthError(ErrInvalidGrant, "Invalid code verifier", http.StatusBadRequest))
		return
	}

	// Create token response
	tokenResp, err := h.tokenManager.CreateTokenResponse(r.Context(), authCode.UID, authCode.FirebaseIDToken, authCode.FirebaseRefreshToken, authCode.FirebaseExpiresAt, authCode.Scope)
	if err != nil {
		h.logger.Error("Failed to create token response", "error", err, "uid", authCode.UID)
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

// Templates are now loaded from files in templates/ directory
// See: templates/select_provider.html, templates/mfa_challenge.html, templates/oauth_error.html

func (h *Handlers) HandleProviderSelection(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method == http.MethodGet {
		// Extract CSP nonce from context (using plain string to match middleware)
		nonce := ""
		if n, ok := r.Context().Value("csp_nonce").(string); ok {
			nonce = n
		}

		data := struct {
			SessionID string
			CSPNonce  string
		}{
			SessionID: sessionID,
			CSPNonce:  nonce,
		}
		h.templates.ExecuteTemplate(w, "select_provider.html", data)
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
	// Get MFA session to extract email
	mfaSession, _ := h.stateManager.GetMFASession(r.Context(), sessionID)

	email := "user"
	if mfaSession != nil && mfaSession.Email != "" {
		email = mfaSession.Email
	}

	// SECURITY FIX: Get current attempt count from Redis
	attemptsUsed, _ := h.stateManager.GetMFAAttemptCount(r.Context(), sessionID)

	// Extract CSP nonce from context (using plain string to match middleware)
	nonce := ""
	if n, ok := r.Context().Value("csp_nonce").(string); ok {
		nonce = n
	}

	data := struct {
		SessionID         string
		Email             string
		MaxAttempts       int
		AttemptCount      int
		AttemptsRemaining int
		CSPNonce          string
	}{
		SessionID:         sessionID,
		Email:             email,
		MaxAttempts:       state.MaxMFAAttempts,
		AttemptCount:      attemptsUsed,
		AttemptsRemaining: state.MaxMFAAttempts - attemptsUsed,
		CSPNonce:          nonce,
	}
	h.templates.ExecuteTemplate(w, "mfa_challenge.html", data)
}

func (h *Handlers) HandleMFAVerify(w http.ResponseWriter, r *http.Request, sessionID, code string) {
	// SECURITY FIX: Check and increment attempts BEFORE processing MFA verification
	// This prevents brute force attacks on MFA codes
	attempts, err := h.stateManager.IncrementMFAAttempts(r.Context(), sessionID)
	if err != nil {
		h.logger.Error("Failed to increment MFA attempts", "error", err, "session_id", sessionID)
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success":           false,
			"error":             "server_error",
			"error_description": "Failed to process MFA attempt",
		})
		return
	}

	// SECURITY FIX: Check if max attempts exceeded
	if attempts > state.MaxMFAAttempts {
		h.logger.Warn("MFA max attempts exceeded", "session_id", sessionID, "attempts", attempts)

		// Consume (delete) the MFA session to prevent further attempts
		h.stateManager.ConsumeMFASession(r.Context(), sessionID)

		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"success":           false,
			"error":             "too_many_attempts",
			"error_description": "Maximum verification attempts exceeded. Please restart authentication.",
		})
		return
	}

	// Get MFA session (non-destructive read for now)
	mfaSession, err := h.stateManager.GetMFASession(r.Context(), sessionID)
	if mfaSession == nil || err != nil {
		h.logger.Error("MFA session not found or invalid", "session_id", sessionID, "error", err)
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success":           false,
			"error":             "invalid_request",
			"error_description": "Session expired or invalid. Please restart authentication.",
		})
		return
	}

	// Verify MFA code
	resp, err := h.firebaseClient.FinalizeMFASignIn(r.Context(), mfaSession.MFAPendingCredential, mfaSession.MFAEnrollmentID, code)
	if err != nil {
		h.logger.Error("MFA verification failed",
			"error", err,
			"session_id", sessionID,
			"attempt", attempts,
			"remaining", state.MaxMFAAttempts-attempts)

		// SECURITY FIX: Include attempts info in error response
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success":            false,
			"error":              "invalid_code",
			"error_description":  fmt.Sprintf("Invalid verification code. %d attempt(s) remaining.", state.MaxMFAAttempts-attempts),
			"attempts_remaining": state.MaxMFAAttempts - attempts,
		})
		return
	}

	// Log what Firebase returned to debug UID issues
	h.logger.Info("MFA response received from Firebase", "local_id", resp.LocalID, "has_id_token", resp.IDToken != "", "has_refresh_token", resp.RefreshToken != "")

	// Get and consume original OAuth state (MFA flow is completing)
	oauthState, err := h.stateManager.ConsumeOAuthState(r.Context(), mfaSession.OAuthState)
	if err != nil || oauthState == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success":           false,
			"error":             "invalid_request",
			"error_description": "OAuth state expired. Please restart the authentication flow.",
		})
		return
	}

	// Generate authorization code
	authCode, _ := h.stateManager.GenerateAuthorizationCode()
	expiresIn := int64(3600)
	if resp.ExpiresIn != "" {
		fmt.Sscanf(resp.ExpiresIn, "%d", &expiresIn)
	}
	expiresAt := time.Now().Unix() + expiresIn

	// SECURITY FIX: Validate UID consistency between Firebase response and MFA session
	// This prevents UID tampering attacks via Redis modification
	h.logger.Info("MFA UID validation",
		"firebase_local_id", resp.LocalID,
		"session_local_id", mfaSession.LocalID,
		"has_firebase_uid", resp.LocalID != "",
		"has_session_uid", mfaSession.LocalID != "")

	// Verify Firebase's LocalID matches the session LocalID (if Firebase returns it)
	if resp.LocalID != "" && resp.LocalID != mfaSession.LocalID {
		h.logger.Error("SECURITY ALERT: UID mismatch detected - possible Redis tampering",
			"session_uid", mfaSession.LocalID,
			"firebase_uid", resp.LocalID,
			"session_id", sessionID,
			"email", mfaSession.Email)
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success":           false,
			"error":             "invalid_request",
			"error_description": "Authentication session is invalid. Please restart the login process.",
		})
		return
	}

	// Use Firebase's LocalID as authoritative source, with fallback to session
	uid := resp.LocalID
	uidSource := "firebase_response"
	if uid == "" {
		// Fallback to session LocalID only if Firebase doesn't return it
		uid = mfaSession.LocalID
		uidSource = "session_fallback"
		h.logger.Warn("Firebase did not return LocalID in MFA finalization response, using session LocalID",
			"uid", uid,
			"session_id", sessionID)
	}

	// Additional validation: UID must not be empty
	if uid == "" {
		h.logger.Error("SECURITY ALERT: Empty UID after MFA verification",
			"session_id", sessionID,
			"email", mfaSession.Email)
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success":           false,
			"error":             "server_error",
			"error_description": "Authentication failed. Please contact support.",
		})
		return
	}

	// SECURITY FIX: Defense-in-depth validation of ID token's sub claim
	// Verify that the ID token's subject matches the UID we're using
	if resp.IDToken != "" {
		tokenUID, err := firebase.ExtractUIDFromIDToken(resp.IDToken)
		if err != nil {
			h.logger.Warn("Failed to extract UID from ID token for validation",
				"error", err,
				"session_id", sessionID)
		} else if tokenUID != uid {
			h.logger.Error("SECURITY ALERT: UID mismatch between ID token and determined UID",
				"token_uid", tokenUID,
				"used_uid", uid,
				"session_id", sessionID,
				"email", mfaSession.Email)
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"success":           false,
				"error":             "invalid_request",
				"error_description": "Authentication verification failed.",
			})
			return
		} else {
			h.logger.Info("ID token sub claim validated successfully",
				"uid", uid,
				"session_id", sessionID)
		}
	}

	authCodeData := state.NewAuthorizationCode(authCode, oauthState.State, uid, resp.IDToken, resp.RefreshToken, expiresAt, oauthState.RedirectURI, oauthState.ClientID, oauthState.Scope, &oauthState.CodeChallenge, &oauthState.CodeChallengeMethod)
	h.logger.Info("Storing authorization code after MFA",
		"uid", uid,
		"source", uidSource,
		"session_id", sessionID)
	h.stateManager.StoreAuthorizationCode(r.Context(), authCodeData)

	// SECURITY FIX: Consume MFA session on success to clean up session and attempt counter
	h.stateManager.ConsumeMFASession(r.Context(), sessionID)

	// Return JSON with redirect URL instead of HTTP redirect
	redirectURL := oauthState.RedirectURI + "?code=" + authCode + "&state=" + oauthState.State
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"redirect_url": redirectURL,
	})
}

// HandleProtectedResourceMetadata handles RFC 9728 Protected Resource Metadata requests
func (h *Handlers) HandleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := h.metadataProvider.GetProtectedResourceMetadata()
	writeJSON(w, http.StatusOK, metadata)
}

// HandleAuthorizationServerMetadata handles RFC 8414 Authorization Server Metadata requests
func (h *Handlers) HandleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := h.metadataProvider.GetAuthorizationServerMetadata()
	writeJSON(w, http.StatusOK, metadata)
}

// HandleRegister handles POST /register - Dynamic Client Registration (RFC 7591)
func (h *Handlers) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Method not allowed", http.StatusMethodNotAllowed))
		return
	}

	// Parse request body
	var req struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to parse registration request", "error", err)
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Invalid JSON request body", http.StatusBadRequest))
		return
	}

	// Validate required parameters
	if req.ClientName == "" {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Missing client_name parameter", http.StatusBadRequest))
		return
	}

	if len(req.RedirectURIs) == 0 {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Missing redirect_uris parameter", http.StatusBadRequest))
		return
	}

	// SECURITY FIX: Validate redirect URIs with proper URL parsing
	// Only allow localhost (HTTP) or HTTPS URIs, with proper host validation
	for _, uri := range req.RedirectURIs {
		u, err := url.Parse(uri)
		if err != nil || u.Host == "" {
			h.logger.Warn("Invalid redirect URI in registration", "uri", uri, "client_name", req.ClientName)
			WriteOAuthError(w, NewOAuthError(
				"invalid_redirect_uri",
				fmt.Sprintf("Invalid redirect_uri format: %s", uri),
				http.StatusBadRequest,
			))
			return
		}

		// Only allow localhost or HTTPS for dynamic registration
		if u.Scheme == "http" {
			host := u.Hostname()
			if host != "localhost" && host != "127.0.0.1" {
				h.logger.Warn("HTTP redirect URI not allowed (only localhost)", "uri", uri, "client_name", req.ClientName)
				WriteOAuthError(w, NewOAuthError(
					"invalid_redirect_uri",
					fmt.Sprintf("HTTP redirect URIs only allowed for localhost: %s", uri),
					http.StatusBadRequest,
				))
				return
			}
		} else if u.Scheme != "https" {
			h.logger.Warn("Invalid redirect URI scheme", "uri", uri, "scheme", u.Scheme, "client_name", req.ClientName)
			WriteOAuthError(w, NewOAuthError(
				"invalid_redirect_uri",
				fmt.Sprintf("Only HTTP (localhost) and HTTPS schemes allowed: %s", uri),
				http.StatusBadRequest,
			))
			return
		}
	}

	// Generate client ID (no secret for public clients)
	clientID, err := h.stateManager.GenerateClientID()
	if err != nil {
		h.logger.Error("Failed to generate client ID", "error", err)
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to generate client ID", http.StatusInternalServerError))
		return
	}

	// Store registration
	registration := state.NewClientRegistration(clientID, req.ClientName, req.RedirectURIs)
	if err := h.stateManager.StoreClientRegistration(r.Context(), registration); err != nil {
		h.logger.Error("Failed to store client registration", "error", err, "client_id", clientID)
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to register client", http.StatusInternalServerError))
		return
	}

	h.logger.Info("Registered new OAuth client", "client_id", clientID, "client_name", req.ClientName)

	// Build response per RFC 7591
	response := map[string]interface{}{
		"client_id":                  clientID,
		"client_name":                req.ClientName,
		"redirect_uris":              req.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none", // Public client
	}

	writeJSON(w, http.StatusCreated, response)
}

// isValidRedirectURI validates redirect URIs against whitelist and registered clients
// SECURITY FIX: Now uses exact match against whitelist instead of accepting any HTTPS URL
func (h *Handlers) isValidRedirectURI(ctx context.Context, uri string, clientID string) bool {
	// Parse URL for validation
	u, err := url.Parse(uri)
	if err != nil {
		h.logger.Warn("Invalid redirect URI format", "uri", uri, "error", err)
		return false
	}

	// Check for open redirect patterns
	if u.Host == "" {
		h.logger.Warn("Redirect URI missing host", "uri", uri)
		return false
	}

	// If dynamic client registration is being used, check registered URIs first
	if clientID != "" {
		client, err := h.stateManager.GetClientRegistration(ctx, clientID)
		if err == nil && client != nil {
			for _, allowedURI := range client.RedirectURIs {
				if uri == allowedURI { // Exact match
					h.logger.Debug("Redirect URI matched registered client URI", "uri", uri, "client_id", clientID)
					return true
				}
			}
			// If client is registered but URI doesn't match, deny
			h.logger.Warn("Redirect URI not in client registration", "uri", uri, "client_id", clientID)
			return false
		}
	}

	// Check against global allowed redirect URIs (exact match)
	for _, allowedURI := range h.allowedRedirectURIs {
		if uri == allowedURI {
			return true
		}
	}

	// Special case: localhost/127.0.0.1 with proper validation
	if u.Scheme == "http" {
		host := u.Hostname() // Use Hostname() to strip port
		if host == "localhost" || host == "127.0.0.1" {
			// Only allow if there's a localhost entry in allowed URIs
			for _, allowedURI := range h.allowedRedirectURIs {
				allowedURL, _ := url.Parse(allowedURI)
				if allowedURL != nil {
					allowedHost := allowedURL.Hostname()
					if allowedHost == "localhost" || allowedHost == "127.0.0.1" {
						h.logger.Debug("Allowing localhost redirect", "uri", uri)
						return true
					}
				}
			}
		}
	}

	h.logger.Warn("Redirect URI not in whitelist", "uri", uri, "allowed_count", len(h.allowedRedirectURIs))
	return false
}
