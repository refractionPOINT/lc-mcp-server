package endpoints

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/cimd"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/firebase"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/metadata"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/resource"
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
	firebaseClient      firebase.ClientInterface
	metadataProvider    *metadata.Provider
	logger              *slog.Logger
	templates           *template.Template
	allowedRedirectURIs []string     // Whitelist of allowed redirect URIs for security
	cimd                cimdResolver // Client ID Metadata Document resolver; nil rejects URL client_ids
}

// NewHandlers creates new OAuth endpoint handlers
func NewHandlers(stateManager *state.Manager, tokenManager *token.Manager, firebaseClient firebase.ClientInterface, metadataProvider *metadata.Provider, logger *slog.Logger, allowedRedirectURIs []string) (*Handlers, error) {
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
		cimd:                cimd.NewFetcher(stateManager, logger),
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
	// A URL client_id is a Client ID Metadata Document client: its document is
	// the only authority for its redirect URIs.
	isCIMD := cimd.LooksLikeURL(clientID)
	if isCIMD {
		if oerr := h.authorizeCIMDClient(r.Context(), clientID, redirectURI); oerr != nil {
			WriteOAuthError(w, oerr)
			return
		}
	} else if !h.isValidRedirectURI(r.Context(), redirectURI, clientID) {
		h.logger.Warn("Invalid redirect_uri (not in whitelist)", "uri", redirectURI, "client_id", clientID)
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "redirect_uri not allowed for this client", http.StatusBadRequest))
		return
	}

	// RFC 8707: bind the authorization to the MCP resource the client names, or
	// to the whole server when it names none. The canonical form is what is
	// stored, so every later comparison is between canonical values.
	canonicalResource, err := h.authorizeResource(params["resource"])
	if err != nil {
		h.logger.Warn("Invalid resource in authorization request", "error", err, "client_id", clientID)
		WriteOAuthError(w, NewOAuthError(ErrInvalidTarget, "resource is not a valid resource of this server", http.StatusBadRequest))
		return
	}

	// Every client must pass through the selection page, which shows who is
	// asking and where the user will be sent. A direct provider parameter is
	// honoured only with the acknowledgement that page issues, so no client,
	// registered or not, can send the user straight to the identity provider.
	if provider != "" && !h.consumeSelectionAck(w, r, clientID, redirectURI, stateParam, codeChallenge) {
		h.logger.Info("Client skipped the selection page; showing it", "cimd", isCIMD, "redirect_host", redirectHost(redirectURI))
		provider = ""
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
			"resource":              canonicalResource,
		}

		if err := h.stateManager.CreateSelectionSession(r.Context(), sessionID, paramsMap); err != nil {
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

	// Bind the transaction to this browser for its whole life: the provider
	// callback and the MFA steps only proceed from the browser that holds the
	// secret behind this hash.
	browserBinding, err := h.bindTransactionToBrowser(w, r)
	if err != nil {
		h.logger.Error("Failed to bind OAuth transaction to browser", "error", err)
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to generate session", http.StatusInternalServerError))
		return
	}

	// Store the transaction under a server-generated id; the client's state is
	// only data in it.
	oauthState := state.NewOAuthState(stateParam, codeChallenge, codeChallengeMethod, redirectURI, clientID, scope, canonicalResource, providerID)
	oauthState.BrowserBinding = browserBinding
	txID, err := h.stateManager.CreateOAuthState(r.Context(), oauthState)
	if err != nil {
		h.logger.Error("Failed to store OAuth state", "error", err)
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to store state", http.StatusInternalServerError))
		return
	}
	// From here on a failure abandons the transaction.
	abandon := func() { _, _ = h.stateManager.ConsumeOAuthState(context.WithoutCancel(r.Context()), txID) }

	// Create Firebase auth URI
	serverURL := h.metadataProvider.GetServerURL()
	callbackURL := serverURL + "/oauth/callback"

	sessionID, firebaseAuthURI, err := h.firebaseClient.CreateAuthURI(r.Context(), providerID, callbackURL, []string{"openid", "email", "profile"})
	if err != nil {
		abandon()
		h.logger.Error("Failed to create Firebase auth URI", "error", err, "provider", providerID)
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to initiate authentication", http.StatusInternalServerError))
		return
	}

	// Extract Firebase state from auth URI
	parsedURI, err := url.Parse(firebaseAuthURI)
	firebaseState := ""
	if err == nil {
		firebaseState = parsedURI.Query().Get("state")
	}
	if firebaseState == "" {
		abandon()
		h.logger.Error("Firebase auth URI carries no state", "provider", providerID)
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to initiate authentication", http.StatusInternalServerError))
		return
	}

	// Bind the provider round trip to the transaction: the state that comes
	// back on the callback leads to the server's transaction id.
	if err := h.stateManager.StoreOAuthMappings(r.Context(), firebaseState, txID, sessionID); err != nil {
		abandon()
		h.logger.Error("Failed to store OAuth mappings", "error", err, "provider", providerID)
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to initiate authentication", http.StatusInternalServerError))
		return
	}

	// Redirect to Firebase OAuth URL
	http.Redirect(w, r, firebaseAuthURI, http.StatusFound)
}

// HandleCallback handles GET /oauth/callback - OAuth callback from provider
func (h *Handlers) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Validate callback
	queryString, err := h.firebaseClient.ValidateProviderCallback(r.URL.RequestURI())
	if err != nil {
		// Never log the query: it carries the provider's authorization code.
		h.logger.Error("Failed to validate provider callback", "error", err, "path", r.URL.Path,
			"has_code", r.URL.Query().Has("code"), "has_state", r.URL.Query().Has("state"))
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
	txID, sessionID, err := h.stateManager.ConsumeOAuthStateMappings(r.Context(), firebaseState)
	if err != nil {
		h.logger.Error("Failed to consume OAuth state mappings", "error", err, "firebase_state", firebaseState)
		writeHTML(w, http.StatusBadRequest, "<h1>OAuth Error</h1><p>State expired or invalid</p>")
		return
	}

	// Get OAuth state (don't consume yet - may need it for MFA flow)
	oauthState, err := h.stateManager.GetOAuthState(r.Context(), txID)
	if err != nil || oauthState == nil {
		h.logger.Error("Failed to get OAuth state", "error", err)
		writeHTML(w, http.StatusBadRequest, "<h1>OAuth Error</h1><p>State expired</p>")
		return
	}

	// The browser returning from the provider must be the one that started this
	// transaction: otherwise a provider URL prepared by someone else (with their
	// own client and redirect URI) could be completed by a victim, whose code
	// would go to the preparer. Checked before anything is exchanged with the
	// provider, and a code is never issued without it.
	if !h.transactionBoundToBrowser(r, oauthState) {
		h.abandonOnBrowserMismatch(r, "callback", txID, oauthState)
		h.renderOAuthError(w, http.StatusForbidden, browserMismatchPage)
		return
	}

	// Sign in with IdP
	requestURI := h.metadataProvider.GetServerURL() + "/oauth/callback"
	resp, err := h.firebaseClient.SignInWithIdp(r.Context(), requestURI, queryString, sessionID, oauthState.Provider)

	// Check for MFA required
	if mfaErr, ok := err.(*firebase.MFARequiredError); ok {
		// Generate MFA session ID with proper error handling
		mfaSessionID, genErr := h.stateManager.GenerateMFASessionID()
		if genErr != nil || mfaSessionID == "" {
			h.logger.Error("Failed to generate MFA session ID", "error", genErr, "provider", oauthState.Provider)
			WriteOAuthErrorRedirect(w, r, h.metadataProvider.GetServerURL(), oauthState.RedirectURI, oauthState.State, ErrServerError, "Failed to initiate MFA challenge")
			return
		}

		// Store MFA session with proper error handling
		mfaSession := state.NewMFASession(mfaErr.MFAPendingCredential, mfaErr.MFAEnrollmentID, txID, mfaErr.DisplayName, mfaErr.LocalID, mfaErr.Email, &mfaErr.PendingToken)
		if storeErr := h.stateManager.StoreMFASession(r.Context(), mfaSessionID, mfaSession); storeErr != nil {
			h.logger.Error("Failed to store MFA session", "error", storeErr, "provider", oauthState.Provider)
			WriteOAuthErrorRedirect(w, r, h.metadataProvider.GetServerURL(), oauthState.RedirectURI, oauthState.State, ErrServerError, "Failed to initiate MFA challenge")
			return
		}

		h.logger.Info("MFA session created", "provider", oauthState.Provider)

		// Redirect to MFA challenge page
		mfaURL := h.metadataProvider.GetServerURL() + "/oauth/mfa-challenge?session=" + mfaSessionID
		http.Redirect(w, r, mfaURL, http.StatusFound)
		return
	}

	var unsupportedErr *firebase.MFAUnsupportedError
	if errors.As(err, &unsupportedErr) {
		// The account only has factors this server cannot verify (e.g. SMS).
		// Tell the user in the browser; a redirect would surface only a
		// generic error in the MCP client.
		if _, err := h.stateManager.ConsumeOAuthState(r.Context(), txID); err != nil {
			h.logger.Warn("Failed to consume OAuth state after unsupported MFA", "error", err)
		}
		h.renderOAuthError(w, http.StatusForbidden, oauthErrorPage{
			ErrorTitle:   "Authenticator App Required",
			ErrorMessage: "Your account uses a multi-factor method that MCP sign-in does not support. MCP sign-in supports authenticator apps (TOTP) only. Add an authenticator app as a second factor in the LimaCharlie web app, then sign in again from your MCP client.",
			ErrorCode:    "mfa_method_unsupported",
			RetryURL:     limaCharlieWebAppURL,
			RetryLabel:   "Open LimaCharlie",
		})
		return
	}

	if err != nil {
		h.logger.Error("Firebase sign-in failed", "error", err, "provider", oauthState.Provider)
		WriteOAuthErrorRedirect(w, r, h.metadataProvider.GetServerURL(), oauthState.RedirectURI, oauthState.State, ErrServerError, "Authentication failed")
		return
	}

	// No MFA required - consume OAuth state now that we're completing the flow
	_, err = h.stateManager.ConsumeOAuthState(r.Context(), txID)
	if err != nil {
		h.logger.Error("Failed to consume OAuth state")
		WriteOAuthErrorRedirect(w, r, h.metadataProvider.GetServerURL(), oauthState.RedirectURI, oauthState.State, ErrServerError, "Authentication failed")
		return
	}

	// Generate authorization code
	code, err := h.stateManager.GenerateAuthorizationCode()
	if err != nil {
		h.logger.Error("Failed to generate authorization code", "error", err)
		WriteOAuthErrorRedirect(w, r, h.metadataProvider.GetServerURL(), oauthState.RedirectURI, oauthState.State, ErrServerError, "Authentication failed")
		return
	}

	// Parse expires_in and calculate absolute expiration time
	expiresIn := int64(3600)
	if resp.ExpiresIn != "" {
		fmt.Sscanf(resp.ExpiresIn, "%d", &expiresIn)
	}
	expiresAt := time.Now().Unix() + expiresIn

	authCode := state.NewAuthorizationCode(code, oauthState.State, resp.LocalID, resp.IDToken, resp.RefreshToken, expiresAt, oauthState.RedirectURI, oauthState.ClientID, oauthState.Scope, &oauthState.CodeChallenge, &oauthState.CodeChallengeMethod)
	authCode.Resource, err = h.stateResource(oauthState)
	if err != nil {
		h.logger.Error("OAuth state carries an invalid resource", "error", err, "client_id", oauthState.ClientID)
		WriteOAuthErrorRedirect(w, r, h.metadataProvider.GetServerURL(), oauthState.RedirectURI, oauthState.State, ErrInvalidTarget, "resource is not a valid resource of this server")
		return
	}
	if err := h.stateManager.StoreAuthorizationCode(r.Context(), authCode); err != nil {
		h.logger.Error("Failed to store authorization code", "error", err)
		WriteOAuthErrorRedirect(w, r, h.metadataProvider.GetServerURL(), oauthState.RedirectURI, oauthState.State, ErrServerError, "Authentication failed")
		return
	}

	// Redirect to client with code
	redirectURL, err := AuthorizationSuccessURL(h.metadataProvider.GetServerURL(), oauthState.RedirectURI, oauthState.State, code)
	if err != nil {
		h.logger.Error("Failed to build authorization response URL", "error", err)
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to build authorization response", http.StatusInternalServerError))
		return
	}
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
		// Safely truncate code for logging (handle codes shorter than 10 chars)
		codeLog := code
		if len(code) > 10 {
			codeLog = code[:10] + "..."
		}
		h.logger.Warn("Redirect URI mismatch in token exchange",
			"expected", authCode.RedirectURI,
			"received", redirectURI,
			"client_id", clientID,
			"code", codeLog)
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

	// RFC 8707: a resource named on the token request may narrow, never widen,
	// what the user authorized. Without one the tokens get the authorized resource.
	tokenResource, err := h.codeGrantResource(authCode, r.Form["resource"])
	if err != nil {
		h.logger.Warn("Invalid resource in token request", "error", err, "client_id", clientID, "authorized", authCode.Resource)
		WriteOAuthError(w, NewOAuthError(ErrInvalidTarget, "resource is not covered by the authorized resource", http.StatusBadRequest))
		return
	}

	// Create token response
	tokenResp, err := h.tokenManager.CreateTokenResponse(r.Context(), authCode.UID, authCode.FirebaseIDToken, authCode.FirebaseRefreshToken, authCode.FirebaseExpiresAt, authCode.Scope, tokenResource, authCode.ClientID)
	if err != nil {
		h.logger.Error("Failed to create token response", "error", err, "uid", authCode.UID)
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Failed to issue tokens", http.StatusInternalServerError))
		return
	}

	writeJSON(w, http.StatusOK, tokenResp)
}

func (h *Handlers) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")

	if refreshToken == "" {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Missing refresh_token", http.StatusBadRequest))
		return
	}
	if len(clientID) > token.MaxClientIDLen {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Invalid client_id", http.StatusBadRequest))
		return
	}

	// Refresh access token. The refresh token is bound to the client it was
	// issued to, which must be the one presenting it.
	tokenResp, err := h.tokenManager.RefreshAccessToken(r.Context(), refreshToken, clientID, h.refreshResourceResolver(r.Form["resource"]))
	if errors.Is(err, token.ErrClientMismatch) {
		WriteOAuthError(w, NewOAuthError(ErrInvalidGrant, "Invalid client credentials", http.StatusBadRequest))
		return
	}
	if errors.Is(err, token.ErrInvalidTarget) {
		WriteOAuthError(w, NewOAuthError(ErrInvalidTarget, "resource is not covered by the authorized resource", http.StatusBadRequest))
		return
	}
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

	// RFC 7009: 200 whether the token was revoked or was never valid, so an
	// unknown token is no error. A backend failure is: the token may still be
	// live, and 200 would tell the client it is dead.
	if err := h.tokenManager.RevokeToken(r.Context(), token, tokenTypeHint); err != nil {
		h.logger.Error("Token revocation failed", "error", err)
		WriteOAuthError(w, NewOAuthError(ErrServerError, "Revocation failed; retry later", http.StatusInternalServerError))
		return
	}

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

// resourcePolicy is the RFC 8707 policy for this server's public URL.
func (h *Handlers) resourcePolicy() *resource.Policy {
	return resource.NewPolicy(h.metadataProvider.GetServerURL())
}

// requestedResource returns the single resource named by a request's
// "resource" parameters, or "" when it names none. Several resources (allowed
// by RFC 8707) are refused: a token here has exactly one audience.
func requestedResource(values []string) (string, error) {
	var requested []string
	for _, v := range values {
		if v != "" {
			requested = append(requested, v)
		}
	}
	switch len(requested) {
	case 0:
		return "", nil
	case 1:
		return requested[0], nil
	}
	return "", fmt.Errorf("%w: multiple resources are not supported", resource.ErrInvalidResource)
}

// authorizeResource returns the canonical resource an authorization request is
// for: the named one, validated, or the whole server when none is named.
func (h *Handlers) authorizeResource(values []string) (string, error) {
	policy := h.resourcePolicy()
	requested, err := requestedResource(values)
	if err != nil {
		return "", err
	}
	if requested == "" {
		return policy.Origin(), nil
	}
	return policy.Canonicalize(requested)
}

// stateResource returns the canonical resource of a stored authorization
// request. A state without one (written before resource binding existed) is
// for the whole server, which is what the authorization endpoint defaulted it
// to. A stored resource that is no longer valid for this server (for example
// after MCP_SERVER_URL changed) is an error.
func (h *Handlers) stateResource(oauthState *state.OAuthState) (string, error) {
	policy := h.resourcePolicy()
	if oauthState.Resource == "" {
		return policy.Origin(), nil
	}
	return policy.Canonicalize(oauthState.Resource)
}

// codeGrantResource decides the resource of the tokens issued for an
// authorization code, from the resource the code was authorized for and the
// one named on the token request, if any.
func (h *Handlers) codeGrantResource(authCode *state.AuthorizationCode, values []string) (string, error) {
	policy := h.resourcePolicy()
	authorized := authCode.Resource
	if authorized == "" {
		authorized = policy.Origin() // code written before resource binding existed
	} else {
		var err error
		if authorized, err = policy.Canonicalize(authorized); err != nil {
			return "", err
		}
	}
	requested, err := requestedResource(values)
	if err != nil {
		return "", err
	}
	if requested == "" {
		return authorized, nil
	}
	canonical, err := policy.Canonicalize(requested)
	if err != nil {
		return "", err
	}
	if !policy.Covers(authorized, canonical) {
		return "", fmt.Errorf("%w: %q is not covered by %q", resource.ErrInvalidResource, canonical, authorized)
	}
	return canonical, nil
}

// refreshResourceResolver decides the resource of the tokens issued by a
// refresh: the one the refresh token is bound to, or a narrower one named on
// the request. A refresh token without a resource predates resource binding;
// it stays unbound (every endpoint, as before) whatever the request names, so
// that a client that is signed in today is not turned away. What it names is
// logged to see when legacy tokens can be bound.
func (h *Handlers) refreshResourceResolver(values []string) token.ResourceResolver {
	return func(authorized string) (string, error) {
		policy := h.resourcePolicy()
		requested, err := requestedResource(values)
		if authorized == "" {
			if err == nil && requested != "" {
				canonical, cerr := policy.Canonicalize(requested)
				h.logger.Info("Refreshing a legacy token that has no resource binding",
					"requested_resource", requested, "valid", cerr == nil, "canonical", canonical)
			}
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("%w: %v", token.ErrInvalidTarget, err)
		}
		if requested == "" {
			return authorized, nil
		}
		canonical, err := policy.Canonicalize(requested)
		if err != nil {
			return "", fmt.Errorf("%w: %v", token.ErrInvalidTarget, err)
		}
		if !policy.Covers(authorized, canonical) {
			return "", fmt.Errorf("%w: %q is not covered by %q", token.ErrInvalidTarget, canonical, authorized)
		}
		return canonical, nil
	}
}

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

// writeMFAVerifyError reports a failed mfaSignIn:finalize call. Only a wrong
// code is reported as one; other failures will not be fixed by a new code.
func (h *Handlers) writeMFAVerifyError(w http.ResponseWriter, r *http.Request, sessionID string, attempts int, err error) {
	switch {
	case errors.Is(err, firebase.ErrMFAInvalidCode):
		// SECURITY FIX: Include attempts info in error response
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success":            false,
			"error":              "invalid_code",
			"error_description":  fmt.Sprintf("Invalid verification code. %d attempt(s) remaining.", state.MaxMFAAttempts-attempts),
			"attempts_remaining": state.MaxMFAAttempts - attempts,
		})
	case errors.Is(err, firebase.ErrMFASessionExpired):
		// Firebase no longer accepts the pending credential, so no code can succeed
		h.stateManager.ConsumeMFASession(r.Context(), sessionID)
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success":           false,
			"error":             "session_expired",
			"error_description": "Your sign-in session expired. Please restart authentication from your MCP client.",
		})
	case errors.Is(err, firebase.ErrMFATooManyAttempts):
		writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"success":           false,
			"error":             "too_many_attempts",
			"error_description": "Too many verification attempts. Please wait a few minutes, then restart authentication from your MCP client.",
		})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success":           false,
			"error":             "server_error",
			"error_description": "We could not verify your code because of a server error. Please restart authentication from your MCP client. If this keeps happening, contact support.",
		})
	}
}

// limaCharlieWebAppURL is where users manage their account, including MFA
const limaCharlieWebAppURL = "https://app.limacharlie.io"

// oauthErrorPage is the data for templates/oauth_error.html
type oauthErrorPage struct {
	ErrorTitle   string
	ErrorMessage string
	ErrorCode    string
	ErrorDetails string
	RetryURL     string
	RetryLabel   string
	SupportURL   string
}

// renderOAuthError renders the browser-facing error page, falling back to
// plain HTML when templates are unavailable or fail to render.
func (h *Handlers) renderOAuthError(w http.ResponseWriter, statusCode int, page oauthErrorPage) {
	if h.templates != nil {
		var buf bytes.Buffer
		err := h.templates.ExecuteTemplate(&buf, "oauth_error.html", page)
		if err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(statusCode)
			buf.WriteTo(w)
			return
		}
		h.logger.Error("Failed to render OAuth error page", "error", err, "error_code", page.ErrorCode)
	}
	writeHTML(w, statusCode, "<h1>"+html.EscapeString(page.ErrorTitle)+"</h1><p>"+html.EscapeString(page.ErrorMessage)+"</p>")
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

		// The page always says who is asking and where the user will be sent,
		// and is bound to this browser: nothing is shown without that.
		client, oerr := h.selectionDisplay(r.Context(), sessionID)
		if oerr != nil {
			WriteOAuthError(w, oerr)
			return
		}
		if err := h.bindSelectionToBrowser(w, r, sessionID); err != nil {
			h.logger.Warn("Failed to bind selection session to browser", "error", err)
			WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "Session expired or invalid", http.StatusBadRequest))
			return
		}
		// No window.opener for whoever opened this page: a cross-site opener
		// must not be able to navigate it after it has rendered.
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")

		data := struct {
			SessionID string
			CSPNonce  string
			Client    *clientDisplay
		}{
			SessionID: sessionID,
			CSPNonce:  nonce,
			Client:    client,
		}
		h.templates.ExecuteTemplate(w, "select_provider.html", data)
	} else {
		// Handle POST - provider selected
		h.CompleteProviderSelection(w, r, sessionID, r.FormValue("provider"))
	}
}

func (h *Handlers) HandleMFAChallenge(w http.ResponseWriter, r *http.Request, sessionID string) {
	// Get MFA session to extract email
	mfaSession, _ := h.stateManager.GetMFASession(r.Context(), sessionID)
	if mfaSession == nil {
		h.renderOAuthError(w, http.StatusBadRequest, mfaExpiredPage)
		return
	}

	// The challenge belongs to a transaction, which belongs to one browser. No
	// identity information is rendered before this passes.
	switch h.mfaBrowserBound(r, "mfa-challenge", sessionID, mfaSession) {
	case mfaBindingExpired:
		h.renderOAuthError(w, http.StatusBadRequest, mfaExpiredPage)
		return
	case mfaBindingMismatch:
		h.renderOAuthError(w, http.StatusForbidden, browserMismatchPage)
		return
	}

	email := "user"
	if mfaSession.Email != "" {
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

// mfaExpiredPage is shown in place of the MFA challenge when the sign-in it
// belongs to no longer exists.
var mfaExpiredPage = oauthErrorPage{
	ErrorTitle:   "Sign-in expired",
	ErrorMessage: "This sign-in expired or was already completed. Nothing was granted. Go back to the application you were signing in to and start the sign-in again from there.",
	ErrorCode:    "session_expired",
	RetryURL:     limaCharlieWebAppURL,
	RetryLabel:   "Open LimaCharlie",
}

type mfaBindingResult int

const (
	mfaBindingOK mfaBindingResult = iota
	// mfaBindingExpired: the MFA session's transaction is gone or cannot be read.
	mfaBindingExpired
	// mfaBindingMismatch: the transaction belongs to another browser.
	mfaBindingMismatch
)

// mfaBrowserBound checks that the request comes from the browser the MFA
// session's transaction was started in. It fails closed: a transaction that is
// missing or unreadable (expired, consumed, store trouble) proves nothing about
// the browser, so the MFA session is dropped and the step is refused before it
// shows an identity, counts an attempt or reaches the provider. On a mismatch
// the transaction is abandoned as well.
func (h *Handlers) mfaBrowserBound(r *http.Request, step, sessionID string, mfaSession *state.MFASession) mfaBindingResult {
	tx, err := h.stateManager.GetOAuthState(r.Context(), mfaSession.OAuthState)
	if err != nil || tx == nil {
		h.logger.Warn("MFA step for a missing or unreadable transaction", "step", step, "error", err)
		h.stateManager.ConsumeMFASession(context.WithoutCancel(r.Context()), sessionID)
		return mfaBindingExpired
	}
	if h.transactionBoundToBrowser(r, tx) {
		return mfaBindingOK
	}
	h.abandonOnBrowserMismatch(r, step, mfaSession.OAuthState, tx)
	h.stateManager.ConsumeMFASession(context.WithoutCancel(r.Context()), sessionID)
	return mfaBindingMismatch
}

func (h *Handlers) HandleMFAVerify(w http.ResponseWriter, r *http.Request, sessionID, code string) {
	// Before anything is counted or sent to the provider: only the browser the
	// transaction was started in may verify its MFA challenge, and a session id
	// seen by anyone else cannot be used to burn its attempts.
	if pre, _ := h.stateManager.GetMFASession(r.Context(), sessionID); pre != nil {
		switch h.mfaBrowserBound(r, "mfa-verify", sessionID, pre) {
		case mfaBindingExpired:
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"success":           false,
				"error":             "invalid_request",
				"error_description": "Session expired or invalid. Please restart authentication.",
			})
			return
		case mfaBindingMismatch:
			writeJSON(w, http.StatusForbidden, map[string]interface{}{
				"success":           false,
				"error":             "browser_mismatch",
				"error_description": "This sign-in was not started in this browser, or it expired. Go back to the application you were signing in to and start the sign-in again from there.",
			})
			return
		}
	}

	// SECURITY FIX: Check and increment attempts BEFORE processing MFA verification
	// This prevents brute force attacks on MFA codes
	attempts, err := h.stateManager.IncrementMFAAttempts(r.Context(), sessionID)
	if errors.Is(err, state.ErrMFASessionNotFound) {
		h.logger.Warn("MFA verify for missing or expired session", "session_id", sessionID)
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success":           false,
			"error":             "invalid_request",
			"error_description": "Session expired or invalid. Please restart authentication.",
		})
		return
	}
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
		h.writeMFAVerifyError(w, r, sessionID, attempts, err)
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

	// The record just consumed is the authority: no code without the binding.
	// (Checked above too, but the transaction could have been replaced between.)
	if !h.transactionBoundToBrowser(r, oauthState) {
		h.logger.Warn("SECURITY: MFA verification from a browser the transaction was not started in",
			"redirect_host", redirectHost(oauthState.RedirectURI))
		h.stateManager.ConsumeMFASession(r.Context(), sessionID)
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"success":           false,
			"error":             "browser_mismatch",
			"error_description": "This sign-in was not started in this browser, or it expired. Go back to the application you were signing in to and start the sign-in again from there.",
		})
		return
	}

	// Generate authorization code
	authCode, err := h.stateManager.GenerateAuthorizationCode()
	if err != nil {
		h.logger.Error("Failed to generate authorization code", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success":           false,
			"error":             "server_error",
			"error_description": "Failed to complete authentication.",
		})
		return
	}
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
	if authCodeData.Resource, err = h.stateResource(oauthState); err != nil {
		h.logger.Error("OAuth state carries an invalid resource", "error", err, "client_id", oauthState.ClientID)
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success":           false,
			"error":             ErrInvalidTarget,
			"error_description": "resource is not a valid resource of this server",
		})
		return
	}
	h.logger.Info("Storing authorization code after MFA",
		"uid", uid,
		"source", uidSource,
		"session_id", sessionID)
	if err := h.stateManager.StoreAuthorizationCode(r.Context(), authCodeData); err != nil {
		h.logger.Error("Failed to store authorization code after MFA", "error", err, "session_id", sessionID)
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success":           false,
			"error":             "server_error",
			"error_description": "Failed to complete authentication.",
		})
		return
	}

	// SECURITY FIX: Consume MFA session on success to clean up session and attempt counter
	h.stateManager.ConsumeMFASession(r.Context(), sessionID)

	// Return JSON with redirect URL instead of HTTP redirect
	redirectURL, err := AuthorizationSuccessURL(h.metadataProvider.GetServerURL(), oauthState.RedirectURI, oauthState.State, authCode)
	if err != nil {
		h.logger.Error("Failed to build authorization response URL", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success":           false,
			"error":             "server_error",
			"error_description": "Failed to complete authentication.",
		})
		return
	}
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
	// The name is shown to users on the sign-in page, so it is kept plain:
	// control and bidi/format characters are dropped and the length is bounded
	// (RFC 7591 lets the server replace requested metadata values; the response
	// carries the stored one).
	req.ClientName = cimd.SanitizeClientName(req.ClientName)
	if req.ClientName == "" {
		WriteOAuthError(w, NewOAuthError(ErrInvalidRequest, "client_name must contain printable text", http.StatusBadRequest))
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
	// URL client_ids are validated against their metadata document only; they
	// never reach the registration lookup or the global allow-list below.
	if cimd.LooksLikeURL(clientID) {
		return h.authorizeCIMDClient(ctx, clientID, uri) == nil
	}

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
