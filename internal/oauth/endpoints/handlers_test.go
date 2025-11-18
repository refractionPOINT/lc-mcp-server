package endpoints

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/firebase"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===== HandleAuthorize Tests =====

func TestHandleAuthorize_ValidRequest(t *testing.T) {
	handlers, stateManager, mockFB := testHandlers(t)
	ctx := context.Background()

	// Track if CreateAuthURI was called
	createAuthURICalled := false
	mockFB.createAuthURIFunc = func(ctx context.Context, provider, continueURI string, scopes []string) (string, string, error) {
		createAuthURICalled = true
		assert.Equal(t, "google.com", provider)
		assert.Contains(t, continueURI, "/oauth/callback")
		return "session-123", "https://firebase.example.com/auth?state=fb-state-456", nil
	}

	// Create PKCE challenge
	verifier := "test-verifier-123456789012345678901234567890"
	challenge := generatePKCEChallenge(verifier)

	// Build request
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", "test-client")
	params.Set("redirect_uri", "https://app.example.com/callback")
	params.Set("state", "client-state-123")
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")
	params.Set("scope", "openid profile")
	params.Set("provider", "google")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()

	handlers.HandleAuthorize(w, req)

	// Should redirect to Firebase
	assert.Equal(t, http.StatusFound, w.Code)
	assert.True(t, createAuthURICalled)

	location := w.Header().Get("Location")
	assert.Contains(t, location, "firebase.example.com")

	// Verify state was stored
	storedState, err := stateManager.GetOAuthState(ctx, "client-state-123")
	assert.NoError(t, err)
	require.NotNil(t, storedState)
	assert.Equal(t, "client-state-123", storedState.State)
	assert.Equal(t, challenge, storedState.CodeChallenge)
	assert.Equal(t, "google.com", storedState.Provider)
}

func TestHandleAuthorize_MethodNotAllowed(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/authorize", nil)
	w := httptest.NewRecorder()

	handlers.HandleAuthorize(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)

	var errResp OAuthError
	json.NewDecoder(w.Body).Decode(&errResp)
	assert.Equal(t, ErrInvalidRequest, errResp.Error)
}

func TestHandleAuthorize_InvalidResponseType(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	params := url.Values{}
	params.Set("response_type", "token") // Not supported
	params.Set("client_id", "test-client")
	params.Set("redirect_uri", "https://app.example.com/callback")
	params.Set("state", "state-123")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()

	handlers.HandleAuthorize(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp OAuthError
	json.NewDecoder(w.Body).Decode(&errResp)
	assert.Equal(t, ErrUnsupportedResponseType, errResp.Error)
}

func TestHandleAuthorize_MissingRequiredParameters(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	tests := []struct {
		name   string
		params map[string]string
	}{
		{
			name: "missing client_id",
			params: map[string]string{
				"response_type":         "code",
				"redirect_uri":          "https://app.example.com/callback",
				"state":                 "state-123",
				"code_challenge":        "challenge",
				"code_challenge_method": "S256",
			},
		},
		{
			name: "missing redirect_uri",
			params: map[string]string{
				"response_type":         "code",
				"client_id":             "test-client",
				"state":                 "state-123",
				"code_challenge":        "challenge",
				"code_challenge_method": "S256",
			},
		},
		{
			name: "missing state",
			params: map[string]string{
				"response_type":         "code",
				"client_id":             "test-client",
				"redirect_uri":          "https://app.example.com/callback",
				"code_challenge":        "challenge",
				"code_challenge_method": "S256",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := url.Values{}
			for k, v := range tt.params {
				params.Set(k, v)
			}

			req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
			w := httptest.NewRecorder()

			handlers.HandleAuthorize(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var errResp OAuthError
			json.NewDecoder(w.Body).Decode(&errResp)
			assert.Equal(t, ErrInvalidRequest, errResp.Error)
		})
	}
}

func TestHandleAuthorize_PKCERequired(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	tests := []struct {
		name                string
		codeChallenge       string
		codeChallengeMethod string
	}{
		{"missing code_challenge", "", "S256"},
		{"missing code_challenge_method", "challenge", ""},
		{"wrong method (plain)", "challenge", "plain"},
		{"missing both", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := url.Values{}
			params.Set("response_type", "code")
			params.Set("client_id", "test-client")
			params.Set("redirect_uri", "https://app.example.com/callback")
			params.Set("state", "state-123")

			if tt.codeChallenge != "" {
				params.Set("code_challenge", tt.codeChallenge)
			}
			if tt.codeChallengeMethod != "" {
				params.Set("code_challenge_method", tt.codeChallengeMethod)
			}

			req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
			w := httptest.NewRecorder()

			handlers.HandleAuthorize(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var errResp OAuthError
			json.NewDecoder(w.Body).Decode(&errResp)
			assert.Equal(t, ErrInvalidRequest, errResp.Error)
			assert.Contains(t, errResp.ErrorDescription, "PKCE")
		})
	}
}

// SECURITY TEST: Open redirect attack prevention
func TestHandleAuthorize_RedirectURIWhitelist(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	verifier := "test-verifier-123456789012345678901234567890"
	challenge := generatePKCEChallenge(verifier)

	tests := []struct {
		name        string
		redirectURI string
		shouldAllow bool
	}{
		{"allowed exact match", "https://app.example.com/callback", true},
		{"allowed localhost", "http://localhost:3000/callback", true},
		{"allowed 127.0.0.1", "http://127.0.0.1:3000/callback", true},
		{"evil domain", "https://evil.com/steal-tokens", false},
		{"subdomain attack", "https://app.example.com.evil.com/callback", false},
		{"open redirect", "https://app.example.com/callback?redirect=https://evil.com", false},
		{"non-whitelisted HTTPS", "https://other-app.com/callback", false},
		{"non-localhost HTTP", "http://192.168.1.1/callback", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := url.Values{}
			params.Set("response_type", "code")
			params.Set("client_id", "test-client")
			params.Set("redirect_uri", tt.redirectURI)
			params.Set("state", "state-"+tt.name)
			params.Set("code_challenge", challenge)
			params.Set("code_challenge_method", "S256")
			params.Set("provider", "google")

			req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
			w := httptest.NewRecorder()

			handlers.HandleAuthorize(w, req)

			if tt.shouldAllow {
				assert.Equal(t, http.StatusFound, w.Code, "Should allow: %s", tt.redirectURI)
			} else {
				assert.Equal(t, http.StatusBadRequest, w.Code, "Should block: %s", tt.redirectURI)

				var errResp OAuthError
				json.NewDecoder(w.Body).Decode(&errResp)
				assert.Equal(t, ErrInvalidRequest, errResp.Error)
				assert.Contains(t, errResp.ErrorDescription, "redirect_uri")
			}
		})
	}
}

func TestHandleAuthorize_UnsupportedProvider(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	verifier := "test-verifier-123456789012345678901234567890"
	challenge := generatePKCEChallenge(verifier)

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", "test-client")
	params.Set("redirect_uri", "https://app.example.com/callback")
	params.Set("state", "state-123")
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")
	params.Set("provider", "unsupported-provider")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()

	handlers.HandleAuthorize(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp OAuthError
	json.NewDecoder(w.Body).Decode(&errResp)
	assert.Equal(t, ErrInvalidRequest, errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "provider")
}

func TestHandleAuthorize_ProviderNormalization(t *testing.T) {
	handlers, stateManager, _ := testHandlers(t)
	ctx := context.Background()

	verifier := "test-verifier-123456789012345678901234567890"
	challenge := generatePKCEChallenge(verifier)

	tests := []struct {
		inputProvider    string
		expectedProvider string
	}{
		{"google", "google.com"},
		{"google.com", "google.com"},
		{"microsoft", "microsoft.com"},
		{"microsoft.com", "microsoft.com"},
	}

	for _, tt := range tests {
		t.Run(tt.inputProvider, func(t *testing.T) {
			params := url.Values{}
			params.Set("response_type", "code")
			params.Set("client_id", "test-client")
			params.Set("redirect_uri", "https://app.example.com/callback")
			params.Set("state", "state-"+tt.inputProvider)
			params.Set("code_challenge", challenge)
			params.Set("code_challenge_method", "S256")
			params.Set("provider", tt.inputProvider)

			req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
			w := httptest.NewRecorder()

			handlers.HandleAuthorize(w, req)

			assert.Equal(t, http.StatusFound, w.Code)

			// Verify provider was normalized in stored state
			storedState, err := stateManager.GetOAuthState(ctx, "state-"+tt.inputProvider)
			assert.NoError(t, err)
			require.NotNil(t, storedState)
			assert.Equal(t, tt.expectedProvider, storedState.Provider)
		})
	}
}

// ===== HandleCallback Tests =====

func TestHandleCallback_ValidCallback(t *testing.T) {
	handlers, stateManager, mockFB := testHandlers(t)
	ctx := context.Background()

	// Setup: Store OAuth state
	verifier := "test-verifier-123456789012345678901234567890"
	challenge := generatePKCEChallenge(verifier)

	oauthState := state.NewOAuthState(
		"oauth-state-123",
		challenge,
		"S256",
		"https://app.example.com/callback",
		"test-client",
		"openid profile",
		"https://test.example.com",
		"google.com",
	)
	err := stateManager.StoreOAuthState(ctx, oauthState)
	require.NoError(t, err)

	// Store state mappings
	fbState := "firebase-state-456"
	sessionID := "session-789"
	stateManager.StoreSelectionSession(ctx, "oauth:session:oauth-state-123", map[string]string{"firebase_state": fbState})
	stateManager.StoreSelectionSession(ctx, "oauth:state:"+fbState, map[string]string{"oauth_state": "oauth-state-123"})
	stateManager.StoreSelectionSession(ctx, "oauth:fbsession:"+fbState, map[string]string{"session_id": sessionID})

	// Mock Firebase sign-in
	signInCalled := false
	mockFB.signInWithIdpFunc = func(ctx context.Context, requestURI, postBody, sid, providerId string) (*firebase.SignInWithIdpResponse, error) {
		signInCalled = true
		assert.Equal(t, sessionID, sid)
		assert.Equal(t, "google.com", providerId)
		return &firebase.SignInWithIdpResponse{
			LocalID:      "test-uid-123",
			IDToken:      "test-id-token",
			RefreshToken: "test-refresh-token",
			ExpiresIn:    "3600",
		}, nil
	}

	// Build callback request
	callbackURL := "/oauth/callback?state=" + fbState + "&code=firebase-auth-code"
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	w := httptest.NewRecorder()

	handlers.HandleCallback(w, req)

	// Should redirect to client with authorization code
	assert.Equal(t, http.StatusFound, w.Code)
	assert.True(t, signInCalled)

	location := w.Header().Get("Location")
	assert.Contains(t, location, "https://app.example.com/callback")
	assert.Contains(t, location, "code=")
	assert.Contains(t, location, "state=oauth-state-123")

	// Parse redirect URL to extract code
	redirectURL, _ := url.Parse(location)
	code := redirectURL.Query().Get("code")
	assert.NotEmpty(t, code)

	// Try to consume the code to verify it exists
	authCode, err := stateManager.ConsumeAuthorizationCode(ctx, code)
	assert.NoError(t, err)
	require.NotNil(t, authCode)
	assert.Equal(t, "test-uid-123", authCode.UID)
	assert.Equal(t, "test-client", authCode.ClientID)
}

func TestHandleCallback_MissingFirebaseState(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=test", nil)
	w := httptest.NewRecorder()

	handlers.HandleCallback(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Missing state")
}

func TestHandleCallback_InvalidState(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	// State that doesn't exist
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?state=non-existent-state&code=test", nil)
	w := httptest.NewRecorder()

	handlers.HandleCallback(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "expired or invalid")
}

// SECURITY TEST: State reuse attack (TOCTOU)
func TestHandleCallback_StateReuseAttack(t *testing.T) {
	handlers, stateManager, _ := testHandlers(t)
	ctx := context.Background()

	// Setup OAuth state
	oauthState := state.NewOAuthState(
		"oauth-state-reuse",
		"challenge",
		"S256",
		"https://app.example.com/callback",
		"test-client",
		"openid",
		"",
		"google.com",
	)
	stateManager.StoreOAuthState(ctx, oauthState)

	// Store mappings
	fbState := "fb-state-reuse"
	sessionID := "session-reuse"
	stateManager.StoreSelectionSession(ctx, "oauth:session:oauth-state-reuse", map[string]string{"firebase_state": fbState})
	stateManager.StoreSelectionSession(ctx, "oauth:state:"+fbState, map[string]string{"oauth_state": "oauth-state-reuse"})
	stateManager.StoreSelectionSession(ctx, "oauth:fbsession:"+fbState, map[string]string{"session_id": sessionID})

	callbackURL := "/oauth/callback?state=" + fbState + "&code=test"

	// First request should succeed
	req1 := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	w1 := httptest.NewRecorder()
	handlers.HandleCallback(w1, req1)
	assert.Equal(t, http.StatusFound, w1.Code)

	// Second request with same state should fail (state consumed)
	req2 := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	w2 := httptest.NewRecorder()
	handlers.HandleCallback(w2, req2)
	assert.Equal(t, http.StatusBadRequest, w2.Code)
	assert.Contains(t, w2.Body.String(), "expired or invalid")
}

func TestHandleCallback_FirebaseSignInFailure(t *testing.T) {
	handlers, stateManager, mockFB := testHandlers(t)
	ctx := context.Background()

	// Setup OAuth state
	oauthState := state.NewOAuthState(
		"oauth-state-fail",
		"challenge",
		"S256",
		"https://app.example.com/callback",
		"test-client",
		"openid",
		"",
		"google.com",
	)
	stateManager.StoreOAuthState(ctx, oauthState)

	// Store mappings
	fbState := "fb-state-fail"
	sessionID := "session-fail"
	stateManager.StoreSelectionSession(ctx, "oauth:session:oauth-state-fail", map[string]string{"firebase_state": fbState})
	stateManager.StoreSelectionSession(ctx, "oauth:state:"+fbState, map[string]string{"oauth_state": "oauth-state-fail"})
	stateManager.StoreSelectionSession(ctx, "oauth:fbsession:"+fbState, map[string]string{"session_id": sessionID})

	// Mock Firebase failure
	mockFB.signInWithIdpFunc = func(ctx context.Context, requestURI, postBody, sid, providerId string) (*firebase.SignInWithIdpResponse, error) {
		return nil, assert.AnError
	}

	callbackURL := "/oauth/callback?state=" + fbState + "&code=test"
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	w := httptest.NewRecorder()

	handlers.HandleCallback(w, req)

	// Should redirect to client with error
	assert.Equal(t, http.StatusFound, w.Code)

	location := w.Header().Get("Location")
	assert.Contains(t, location, "error=")
	assert.Contains(t, location, "state=oauth-state-fail")
}

// ===== HandleToken Tests =====

func TestHandleToken_AuthorizationCodeGrant_Success(t *testing.T) {
	handlers, stateManager, _ := testHandlers(t)
	ctx := context.Background()

	// Setup: Store authorization code
	verifier := "test-verifier-123456789012345678901234567890"
	challenge := generatePKCEChallenge(verifier)

	authCode := state.NewAuthorizationCode(
		"test-code-123",
		"client-state",
		"test-uid",
		"fb-id-token",
		"fb-refresh-token",
		time.Now().Unix()+3600,
		"https://app.example.com/callback",
		"test-client",
		"openid profile",
		&challenge,
		stringPtr("S256"),
	)
	err := stateManager.StoreAuthorizationCode(ctx, authCode)
	require.NoError(t, err)

	// Build token request
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "test-code-123")
	form.Set("redirect_uri", "https://app.example.com/callback")
	form.Set("client_id", "test-client")
	form.Set("code_verifier", verifier)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handlers.HandleToken(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var tokenResp map[string]interface{}
	err = json.NewDecoder(w.Body).Decode(&tokenResp)
	require.NoError(t, err)

	assert.NotEmpty(t, tokenResp["access_token"])
	assert.NotEmpty(t, tokenResp["refresh_token"])
	assert.Equal(t, "Bearer", tokenResp["token_type"])
	assert.NotEmpty(t, tokenResp["expires_in"])

	// Verify code was consumed (single-use) - trying to consume again should fail
	consumed, _ := stateManager.ConsumeAuthorizationCode(ctx, "test-code-123")
	assert.Nil(t, consumed, "Authorization code should be consumed")
}

func TestHandleToken_MethodNotAllowed(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()

	handlers.HandleToken(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)

	var errResp OAuthError
	json.NewDecoder(w.Body).Decode(&errResp)
	assert.Equal(t, ErrInvalidRequest, errResp.Error)
}

func TestHandleToken_UnsupportedGrantType(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	form := url.Values{}
	form.Set("grant_type", "password") // Not supported

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handlers.HandleToken(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp OAuthError
	json.NewDecoder(w.Body).Decode(&errResp)
	assert.Equal(t, ErrUnsupportedGrantType, errResp.Error)
}

func TestHandleToken_MissingParameters(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	tests := []struct {
		name   string
		params map[string]string
	}{
		{
			name: "missing code",
			params: map[string]string{
				"grant_type":    "authorization_code",
				"redirect_uri":  "https://app.example.com/callback",
				"client_id":     "test-client",
				"code_verifier": "verifier",
			},
		},
		{
			name: "missing redirect_uri",
			params: map[string]string{
				"grant_type":    "authorization_code",
				"code":          "test-code",
				"client_id":     "test-client",
				"code_verifier": "verifier",
			},
		},
		{
			name: "missing code_verifier",
			params: map[string]string{
				"grant_type":   "authorization_code",
				"code":         "test-code",
				"redirect_uri": "https://app.example.com/callback",
				"client_id":    "test-client",
			},
		},
		{
			name: "missing client_id",
			params: map[string]string{
				"grant_type":    "authorization_code",
				"code":          "test-code",
				"redirect_uri":  "https://app.example.com/callback",
				"code_verifier": "verifier",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			for k, v := range tt.params {
				form.Set(k, v)
			}

			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			handlers.HandleToken(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var errResp OAuthError
			json.NewDecoder(w.Body).Decode(&errResp)
			assert.Equal(t, ErrInvalidRequest, errResp.Error)
		})
	}
}

func TestHandleToken_InvalidAuthorizationCode(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "non-existent-code")
	form.Set("redirect_uri", "https://app.example.com/callback")
	form.Set("client_id", "test-client")
	form.Set("code_verifier", "verifier")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handlers.HandleToken(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp OAuthError
	json.NewDecoder(w.Body).Decode(&errResp)
	assert.Equal(t, ErrInvalidGrant, errResp.Error)
}

// SECURITY TEST: Client ID mismatch (authorization code theft)
func TestHandleToken_ClientIDMismatch(t *testing.T) {
	handlers, stateManager, _ := testHandlers(t)
	ctx := context.Background()

	verifier := "test-verifier-123456789012345678901234567890"
	challenge := generatePKCEChallenge(verifier)

	// Store code for client-1
	authCode := state.NewAuthorizationCode(
		"stolen-code",
		"state",
		"uid",
		"token",
		"refresh",
		time.Now().Unix()+3600,
		"https://app.example.com/callback",
		"client-1", // Original client
		"openid",
		&challenge,
		stringPtr("S256"),
	)
	stateManager.StoreAuthorizationCode(ctx, authCode)

	// Attacker tries to use code with different client_id
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "stolen-code")
	form.Set("redirect_uri", "https://app.example.com/callback")
	form.Set("client_id", "client-2") // Different client!
	form.Set("code_verifier", verifier)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handlers.HandleToken(w, req)

	// Should reject
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp OAuthError
	json.NewDecoder(w.Body).Decode(&errResp)
	assert.Equal(t, ErrInvalidGrant, errResp.Error)
}

// SECURITY TEST: Redirect URI mismatch
func TestHandleToken_RedirectURIMismatch(t *testing.T) {
	handlers, stateManager, _ := testHandlers(t)
	ctx := context.Background()

	verifier := "test-verifier-123456789012345678901234567890"
	challenge := generatePKCEChallenge(verifier)

	authCode := state.NewAuthorizationCode(
		"test-code",
		"state",
		"uid",
		"token",
		"refresh",
		time.Now().Unix()+3600,
		"https://app.example.com/callback", // Original redirect URI
		"test-client",
		"openid",
		&challenge,
		stringPtr("S256"),
	)
	stateManager.StoreAuthorizationCode(ctx, authCode)

	// Try to exchange with different redirect_uri
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "test-code")
	form.Set("redirect_uri", "https://evil.com/steal") // Different!
	form.Set("client_id", "test-client")
	form.Set("code_verifier", verifier)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handlers.HandleToken(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp OAuthError
	json.NewDecoder(w.Body).Decode(&errResp)
	assert.Equal(t, ErrInvalidGrant, errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "redirect_uri")
}

// SECURITY TEST: Invalid PKCE verifier
func TestHandleToken_InvalidPKCEVerifier(t *testing.T) {
	handlers, stateManager, _ := testHandlers(t)
	ctx := context.Background()

	verifier := "correct-verifier-123456789012345678901234"
	challenge := generatePKCEChallenge(verifier)

	authCode := state.NewAuthorizationCode(
		"test-code",
		"state",
		"uid",
		"token",
		"refresh",
		time.Now().Unix()+3600,
		"https://app.example.com/callback",
		"test-client",
		"openid",
		&challenge,
		stringPtr("S256"),
	)
	stateManager.StoreAuthorizationCode(ctx, authCode)

	// Try with wrong verifier
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "test-code")
	form.Set("redirect_uri", "https://app.example.com/callback")
	form.Set("client_id", "test-client")
	form.Set("code_verifier", "wrong-verifier-000000000000000000000")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handlers.HandleToken(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp OAuthError
	json.NewDecoder(w.Body).Decode(&errResp)
	assert.Equal(t, ErrInvalidGrant, errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "verifier")
}

// SECURITY TEST: Code reuse attack
func TestHandleToken_CodeReuseAttack(t *testing.T) {
	handlers, stateManager, _ := testHandlers(t)
	ctx := context.Background()

	verifier := "test-verifier-123456789012345678901234567890"
	challenge := generatePKCEChallenge(verifier)

	authCode := state.NewAuthorizationCode(
		"reusable-code",
		"state",
		"uid",
		"token",
		"refresh",
		time.Now().Unix()+3600,
		"https://app.example.com/callback",
		"test-client",
		"openid",
		&challenge,
		stringPtr("S256"),
	)
	stateManager.StoreAuthorizationCode(ctx, authCode)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "reusable-code")
	form.Set("redirect_uri", "https://app.example.com/callback")
	form.Set("client_id", "test-client")
	form.Set("code_verifier", verifier)

	// First exchange should succeed
	req1 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w1 := httptest.NewRecorder()
	handlers.HandleToken(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Second exchange with same code should fail
	req2 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	handlers.HandleToken(w2, req2)
	assert.Equal(t, http.StatusBadRequest, w2.Code)

	var errResp OAuthError
	json.NewDecoder(w2.Body).Decode(&errResp)
	assert.Equal(t, ErrInvalidGrant, errResp.Error)
}

func TestHandleToken_RefreshTokenGrant_Success(t *testing.T) {
	handlers, stateManager, mockFB := testHandlers(t)
	ctx := context.Background()

	// Store access and refresh tokens
	accessTokenData := state.NewAccessTokenData(
		"test-access-token",
		"test-uid",
		"fb-id-token",
		"fb-refresh-token",
		time.Now().Unix()+3600,
		"openid profile",
		3600,
	)
	stateManager.StoreAccessToken(ctx, accessTokenData)

	refreshTokenData := state.NewRefreshTokenData(
		"test-refresh-token",
		"test-access-token",
		"test-uid",
		"fb-refresh-token",
		"openid profile",
	)
	stateManager.StoreRefreshToken(ctx, refreshTokenData)

	// Mock Firebase refresh
	mockFB.refreshIDTokenFunc = func(ctx context.Context, refreshToken string) (string, int64, error) {
		expiresAt := time.Now().Add(1 * time.Hour).Unix()
		return "new-id-token", expiresAt, nil
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", "test-refresh-token")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handlers.HandleToken(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var tokenResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&tokenResp)
	assert.NotEmpty(t, tokenResp["access_token"])
	assert.NotEmpty(t, tokenResp["refresh_token"])
}

func TestHandleToken_RefreshTokenGrant_InvalidToken(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", "invalid-refresh-token")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handlers.HandleToken(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp OAuthError
	json.NewDecoder(w.Body).Decode(&errResp)
	assert.Equal(t, ErrInvalidGrant, errResp.Error)
}

// ===== HandleRevoke Tests =====

func TestHandleRevoke_Success(t *testing.T) {
	handlers, stateManager, _ := testHandlers(t)
	ctx := context.Background()

	// Store a token
	accessTokenData := state.NewAccessTokenData(
		"revoke-me",
		"uid",
		"id-token",
		"refresh",
		time.Now().Unix()+3600,
		"openid",
		3600,
	)
	stateManager.StoreAccessToken(ctx, accessTokenData)

	form := url.Values{}
	form.Set("token", "revoke-me")
	form.Set("token_type_hint", "access_token")

	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handlers.HandleRevoke(w, req)

	// Always returns 200 per OAuth spec
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify token was revoked
	retrieved, _ := stateManager.GetAccessTokenData(ctx, "revoke-me")
	assert.Nil(t, retrieved)
}

func TestHandleRevoke_MethodNotAllowed(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/revoke", nil)
	w := httptest.NewRecorder()

	handlers.HandleRevoke(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleRevoke_MissingToken(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	form := url.Values{}
	// No token parameter

	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handlers.HandleRevoke(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleRevoke_NonExistentToken(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	form := url.Values{}
	form.Set("token", "non-existent-token")

	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handlers.HandleRevoke(w, req)

	// Should still return 200 per OAuth spec (idempotent)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ===== HandleIntrospect Tests =====

func TestHandleIntrospect_ActiveToken(t *testing.T) {
	handlers, stateManager, _ := testHandlers(t)
	ctx := context.Background()

	// Store valid token
	accessTokenData := state.NewAccessTokenData(
		"active-token",
		"test-uid",
		"id-token",
		"refresh",
		time.Now().Unix()+3600,
		"openid profile",
		3600,
	)
	stateManager.StoreAccessToken(ctx, accessTokenData)

	form := url.Values{}
	form.Set("token", "active-token")

	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handlers.HandleIntrospect(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, true, resp["active"])
	assert.Equal(t, "test-uid", resp["sub"])
	assert.Equal(t, "openid profile", resp["scope"])
}

func TestHandleIntrospect_InactiveToken(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	form := url.Values{}
	form.Set("token", "inactive-token")

	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handlers.HandleIntrospect(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, false, resp["active"])
}

func TestHandleIntrospect_MethodNotAllowed(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/introspect", nil)
	w := httptest.NewRecorder()

	handlers.HandleIntrospect(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleIntrospect_MissingToken(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	form := url.Values{}

	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handlers.HandleIntrospect(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
