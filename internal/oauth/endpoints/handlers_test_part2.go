package endpoints

import (
	"bytes"
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

// ===== HandleRegister Tests (Dynamic Client Registration - RFC 7591) =====

func TestHandleRegister_Success(t *testing.T) {
	handlers, stateManager, _ := testHandlers(t)
	ctx := context.Background()

	requestBody := map[string]interface{}{
		"client_name": "Test Application",
		"redirect_uris": []string{
			"https://app.example.com/callback",
			"http://localhost:3000/callback",
		},
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.HandleRegister(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	assert.NotEmpty(t, resp["client_id"])
	assert.Equal(t, "Test Application", resp["client_name"])
	assert.Equal(t, "none", resp["token_endpoint_auth_method"])

	// Verify registration was stored
	clientID := resp["client_id"].(string)
	registration, err := stateManager.GetClientRegistration(ctx, clientID)
	assert.NoError(t, err)
	require.NotNil(t, registration)
	assert.Equal(t, "Test Application", registration.ClientName)
	assert.Len(t, registration.RedirectURIs, 2)
}

func TestHandleRegister_MethodNotAllowed(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	w := httptest.NewRecorder()

	handlers.HandleRegister(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleRegister_InvalidJSON(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.HandleRegister(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp OAuthError
	json.NewDecoder(w.Body).Decode(&errResp)
	assert.Equal(t, ErrInvalidRequest, errResp.Error)
}

func TestHandleRegister_MissingClientName(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	requestBody := map[string]interface{}{
		"redirect_uris": []string{"https://app.example.com/callback"},
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.HandleRegister(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp OAuthError
	json.NewDecoder(w.Body).Decode(&errResp)
	assert.Equal(t, ErrInvalidRequest, errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "client_name")
}

func TestHandleRegister_MissingRedirectURIs(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	requestBody := map[string]interface{}{
		"client_name": "Test App",
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.HandleRegister(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var errResp OAuthError
	json.NewDecoder(w.Body).Decode(&errResp)
	assert.Equal(t, ErrInvalidRequest, errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "redirect_uris")
}

func TestHandleRegister_InvalidRedirectURI(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	tests := []struct {
		name string
		uri  string
	}{
		{"malformed URI", "not-a-valid-uri"},
		{"no host", "http://"},
		{"non-localhost HTTP", "http://192.168.1.1/callback"},
		{"custom scheme", "myapp://callback"},
		{"javascript", "javascript:alert(1)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestBody := map[string]interface{}{
				"client_name":   "Test App",
				"redirect_uris": []string{tt.uri},
			}

			body, _ := json.Marshal(requestBody)
			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handlers.HandleRegister(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var errResp OAuthError
			json.NewDecoder(w.Body).Decode(&errResp)
			assert.Equal(t, "invalid_redirect_uri", errResp.Error)
		})
	}
}

func TestHandleRegister_ValidHTTPSAndLocalhost(t *testing.T) {
	handlers, stateManager, _ := testHandlers(t)
	ctx := context.Background()

	requestBody := map[string]interface{}{
		"client_name": "Test App",
		"redirect_uris": []string{
			"https://secure.example.com/callback",
			"http://localhost:3000/callback",
			"http://127.0.0.1:8080/oauth",
		},
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.HandleRegister(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	clientID := resp["client_id"].(string)
	registration, _ := stateManager.GetClientRegistration(ctx, clientID)
	assert.Len(t, registration.RedirectURIs, 3)
}

// ===== isValidRedirectURI Tests =====

func TestIsValidRedirectURI_ExactMatch(t *testing.T) {
	handlers, _, _ := testHandlers(t)
	ctx := context.Background()

	tests := []struct {
		uri      string
		expected bool
	}{
		{"https://app.example.com/callback", true},
		{"https://app.example.com/oauth/callback", true},
		{"http://localhost:3000/callback", true},
		{"http://127.0.0.1:3000/callback", true},
		{"https://evil.com/callback", false},
		{"https://app.example.com.evil.com/callback", false},
		{"http://192.168.1.1/callback", false},
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			result := handlers.isValidRedirectURI(ctx, tt.uri, "")
			assert.Equal(t, tt.expected, result, "URI: %s", tt.uri)
		})
	}
}

func TestIsValidRedirectURI_RegisteredClient(t *testing.T) {
	handlers, stateManager, _ := testHandlers(t)
	ctx := context.Background()

	// Register a client with specific URIs
	registration := state.NewClientRegistration(
		"registered-client",
		"Test Client",
		[]string{
			"https://registered-app.com/callback",
			"http://localhost:4000/oauth",
		},
	)
	stateManager.StoreClientRegistration(ctx, registration)

	tests := []struct {
		name     string
		uri      string
		clientID string
		expected bool
	}{
		{
			"registered client with matching URI",
			"https://registered-app.com/callback",
			"registered-client",
			true,
		},
		{
			"registered client with non-matching URI",
			"https://other-app.com/callback",
			"registered-client",
			false,
		},
		{
			"registered client localhost match",
			"http://localhost:4000/oauth",
			"registered-client",
			true,
		},
		{
			"unregistered client falls back to whitelist",
			"https://app.example.com/callback",
			"unknown-client",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handlers.isValidRedirectURI(ctx, tt.uri, tt.clientID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidRedirectURI_MalformedURI(t *testing.T) {
	handlers, _, _ := testHandlers(t)
	ctx := context.Background()

	malformedURIs := []string{
		"not a uri",
		"",
		"://missing-scheme",
		"http:/missing-slash",
	}

	for _, uri := range malformedURIs {
		t.Run(uri, func(t *testing.T) {
			result := handlers.isValidRedirectURI(ctx, uri, "")
			assert.False(t, result, "Should reject malformed URI: %s", uri)
		})
	}
}

func TestIsValidRedirectURI_MissingHost(t *testing.T) {
	handlers, _, _ := testHandlers(t)
	ctx := context.Background()

	urisWithoutHost := []string{
		"https:///callback",
		"http:///test",
		"/relative/path",
	}

	for _, uri := range urisWithoutHost {
		t.Run(uri, func(t *testing.T) {
			result := handlers.isValidRedirectURI(ctx, uri, "")
			assert.False(t, result, "Should reject URI without host: %s", uri)
		})
	}
}

func TestIsValidRedirectURI_LocalhostVariations(t *testing.T) {
	handlers, _, _ := testHandlers(t)
	ctx := context.Background()

	// These should be allowed because whitelist contains localhost entries
	tests := []struct {
		uri      string
		expected bool
	}{
		{"http://localhost:3000/callback", true},
		{"http://127.0.0.1:3000/callback", true},
		{"http://localhost:8080/oauth", true},
		{"http://127.0.0.1:9000/cb", true},
		{"https://localhost:3000/callback", false}, // HTTPS localhost not in whitelist
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			result := handlers.isValidRedirectURI(ctx, tt.uri, "")
			assert.Equal(t, tt.expected, result, "URI: %s", tt.uri)
		})
	}
}

// ===== validatePKCE Tests =====

func TestValidatePKCE_ValidS256(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	verifier := "test-verifier-123456789012345678901234567890"
	challenge := generatePKCEChallenge(verifier)

	result := handlers.validatePKCE(verifier, challenge)
	assert.True(t, result)
}

func TestValidatePKCE_InvalidVerifier(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	correctVerifier := "correct-verifier-12345678901234567890"
	challenge := generatePKCEChallenge(correctVerifier)

	wrongVerifier := "wrong-verifier-000000000000000000000"

	result := handlers.validatePKCE(wrongVerifier, challenge)
	assert.False(t, result)
}

func TestValidatePKCE_EmptyVerifier(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	challenge := "some-challenge"

	result := handlers.validatePKCE("", challenge)
	assert.False(t, result)
}

func TestValidatePKCE_EmptyChallenge(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	verifier := "some-verifier"

	result := handlers.validatePKCE(verifier, "")
	assert.False(t, result)
}

// ===== MFA Flow Tests =====

func TestHandleMFAVerify_Success(t *testing.T) {
	handlers, stateManager, mockFB := testHandlers(t)
	ctx := context.Background()

	// Setup: Store OAuth state
	verifier := "test-verifier-123456789012345678901234567890"
	challenge := generatePKCEChallenge(verifier)

	oauthState := state.NewOAuthState(
		"oauth-mfa-state",
		challenge,
		"S256",
		"https://app.example.com/callback",
		"test-client",
		"openid profile",
		"",
		"google.com",
	)
	stateManager.StoreOAuthState(ctx, oauthState)

	// Setup: Store MFA session
	mfaSession := state.NewMFASession(
		"mfa-pending-cred",
		"mfa-enrollment-id",
		"oauth-mfa-state",
		"Test User",
		"test-uid-123",
		"user@example.com",
		nil,
	)
	sessionID, _ := stateManager.GenerateMFASessionID()
	stateManager.StoreMFASession(ctx, sessionID, mfaSession)

	// Mock successful MFA verification
	mockFB.finalizeMFASignInFunc = func(ctx context.Context, pending, enrollment, code string) (*firebase.FinalizeMFAResponse, error) {
		assert.Equal(t, "123456", code)
		return &firebase.FinalizeMFAResponse{
			LocalID:      "test-uid-123",
			IDToken:      "mfa-id-token",
			RefreshToken: "mfa-refresh-token",
			ExpiresIn:    "3600",
		}, nil
	}

	// Build MFA verify request
	form := url.Values{}
	form.Set("code", "123456")

	req := httptest.NewRequest(http.MethodPost, "/oauth/mfa-verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handlers.HandleMFAVerify(w, req, sessionID, "123456")

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, true, resp["success"])
	assert.NotEmpty(t, resp["redirect_url"])
	assert.Contains(t, resp["redirect_url"].(string), "code=")
	assert.Contains(t, resp["redirect_url"].(string), "state=oauth-mfa-state")

	// Verify MFA session was consumed
	consumed, _ := stateManager.GetMFASession(ctx, sessionID)
	assert.Nil(t, consumed, "MFA session should be consumed after success")
}

func TestHandleMFAVerify_InvalidCode(t *testing.T) {
	handlers, stateManager, mockFB := testHandlers(t)
	ctx := context.Background()

	// Setup OAuth state
	oauthState := state.NewOAuthState(
		"oauth-mfa-fail",
		"challenge",
		"S256",
		"https://app.example.com/callback",
		"test-client",
		"openid",
		"",
		"google.com",
	)
	stateManager.StoreOAuthState(ctx, oauthState)

	// Setup MFA session
	mfaSession := state.NewMFASession(
		"pending",
		"enrollment",
		"oauth-mfa-fail",
		"User",
		"uid",
		"user@test.com",
		nil,
	)
	sessionID, _ := stateManager.GenerateMFASessionID()
	stateManager.StoreMFASession(ctx, sessionID, mfaSession)

	// Mock MFA failure
	mockFB.finalizeMFASignInFunc = func(ctx context.Context, pending, enrollment, code string) (*firebase.FinalizeMFAResponse, error) {
		return nil, assert.AnError
	}

	req := httptest.NewRequest(http.MethodPost, "/mfa-verify", nil)
	w := httptest.NewRecorder()

	handlers.HandleMFAVerify(w, req, sessionID, "wrong-code")

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, false, resp["success"])
	assert.Equal(t, "invalid_code", resp["error"])
	assert.Contains(t, resp["error_description"], "remaining")

	// MFA session should still exist for retry
	stillExists, _ := stateManager.GetMFASession(ctx, sessionID)
	assert.NotNil(t, stillExists, "MFA session should persist for retry")
}

func TestHandleMFAVerify_BruteForceProtection(t *testing.T) {
	handlers, stateManager, mockFB := testHandlers(t)
	ctx := context.Background()

	// Setup OAuth state
	oauthState := state.NewOAuthState(
		"oauth-brute",
		"challenge",
		"S256",
		"https://app.example.com/callback",
		"test-client",
		"openid",
		"",
		"google.com",
	)
	stateManager.StoreOAuthState(ctx, oauthState)

	// Setup MFA session
	mfaSession := state.NewMFASession(
		"pending",
		"enrollment",
		"oauth-brute",
		"User",
		"uid",
		"user@test.com",
		nil,
	)
	sessionID, _ := stateManager.GenerateMFASessionID()
	stateManager.StoreMFASession(ctx, sessionID, mfaSession)

	// Mock MFA failures
	mockFB.finalizeMFASignInFunc = func(ctx context.Context, pending, enrollment, code string) (*firebase.FinalizeMFAResponse, error) {
		return nil, assert.AnError
	}

	// Attempt 1
	req1 := httptest.NewRequest(http.MethodPost, "/mfa-verify", nil)
	w1 := httptest.NewRecorder()
	handlers.HandleMFAVerify(w1, req1, sessionID, "wrong1")
	assert.Equal(t, http.StatusBadRequest, w1.Code)

	// Attempt 2
	req2 := httptest.NewRequest(http.MethodPost, "/mfa-verify", nil)
	w2 := httptest.NewRecorder()
	handlers.HandleMFAVerify(w2, req2, sessionID, "wrong2")
	assert.Equal(t, http.StatusBadRequest, w2.Code)

	// Attempt 3
	req3 := httptest.NewRequest(http.MethodPost, "/mfa-verify", nil)
	w3 := httptest.NewRecorder()
	handlers.HandleMFAVerify(w3, req3, sessionID, "wrong3")
	assert.Equal(t, http.StatusBadRequest, w3.Code)

	// Attempt 4 should be blocked (max 3 attempts)
	req4 := httptest.NewRequest(http.MethodPost, "/mfa-verify", nil)
	w4 := httptest.NewRecorder()
	handlers.HandleMFAVerify(w4, req4, sessionID, "wrong4")
	assert.Equal(t, http.StatusForbidden, w4.Code)

	var resp map[string]interface{}
	json.NewDecoder(w4.Body).Decode(&resp)
	assert.Equal(t, "too_many_attempts", resp["error"])

	// Session should be consumed to prevent further attempts
	consumed, _ := stateManager.GetMFASession(ctx, sessionID)
	assert.Nil(t, consumed, "MFA session should be consumed after max attempts")
}

func TestHandleMFAVerify_SessionNotFound(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/mfa-verify", nil)
	w := httptest.NewRecorder()

	handlers.HandleMFAVerify(w, req, "non-existent-session", "123456")

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, false, resp["success"])
	assert.Contains(t, resp["error_description"].(string), "expired or invalid")
}

func TestHandleMFAVerify_UIDValidation(t *testing.T) {
	handlers, stateManager, mockFB := testHandlers(t)
	ctx := context.Background()

	// Setup OAuth state
	oauthState := state.NewOAuthState(
		"oauth-uid-check",
		"challenge",
		"S256",
		"https://app.example.com/callback",
		"test-client",
		"openid",
		"",
		"google.com",
	)
	stateManager.StoreOAuthState(ctx, oauthState)

	// Setup MFA session with specific UID
	mfaSession := state.NewMFASession(
		"pending",
		"enrollment",
		"oauth-uid-check",
		"User",
		"original-uid-123", // Original UID
		"user@test.com",
		nil,
	)
	sessionID, _ := stateManager.GenerateMFASessionID()
	stateManager.StoreMFASession(ctx, sessionID, mfaSession)

	// Mock Firebase returning different UID (tampering attempt)
	mockFB.finalizeMFASignInFunc = func(ctx context.Context, pending, enrollment, code string) (*firebase.FinalizeMFAResponse, error) {
		return &firebase.FinalizeMFAResponse{
			LocalID:      "different-uid-456", // Different UID!
			IDToken:      "token",
			RefreshToken: "refresh",
			ExpiresIn:    "3600",
		}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/mfa-verify", nil)
	w := httptest.NewRecorder()

	handlers.HandleMFAVerify(w, req, sessionID, "123456")

	// Should detect UID mismatch and reject
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, false, resp["success"])
	assert.Contains(t, resp["error_description"], "invalid")
}

// ===== HandleCallback with MFA Tests =====

func TestHandleCallback_MFARequired(t *testing.T) {
	handlers, stateManager, mockFB := testHandlers(t)
	ctx := context.Background()

	// Setup OAuth state
	oauthState := state.NewOAuthState(
		"oauth-with-mfa",
		"challenge",
		"S256",
		"https://app.example.com/callback",
		"test-client",
		"openid",
		"",
		"google.com",
	)
	stateManager.StoreOAuthState(ctx, oauthState)

	// Store state mappings
	fbState := "fb-mfa-state"
	sessionID := "session-mfa"
	stateManager.StoreSelectionSession(ctx, "oauth:session:oauth-with-mfa", map[string]string{"firebase_state": fbState})
	stateManager.StoreSelectionSession(ctx, "oauth:state:"+fbState, map[string]string{"oauth_state": "oauth-with-mfa"})
	stateManager.StoreSelectionSession(ctx, "oauth:fbsession:"+fbState, map[string]string{"session_id": sessionID})

	// Mock Firebase requiring MFA
	mockFB.signInWithIdpFunc = func(ctx context.Context, requestURI, postBody, sid, providerId string) (*firebase.SignInWithIdpResponse, error) {
		return nil, &firebase.MFARequiredError{
			MFAPendingCredential: "mfa-pending-cred",
			MFAEnrollmentID:      "mfa-enrollment-id",
			DisplayName:          "Test User",
			LocalID:              "test-uid",
			Email:                "user@example.com",
			PendingToken:         "pending-token",
		}
	}

	callbackURL := "/oauth/callback?state=" + fbState + "&code=test"
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	w := httptest.NewRecorder()

	handlers.HandleCallback(w, req)

	// Should redirect to MFA challenge page
	assert.Equal(t, http.StatusFound, w.Code)

	location := w.Header().Get("Location")
	assert.Contains(t, location, "/oauth/mfa-challenge")
	assert.Contains(t, location, "session=")

	// Verify MFA session was created
	// Extract session ID from redirect
	redirectURL, _ := url.Parse(location)
	mfaSessionID := redirectURL.Query().Get("session")
	assert.NotEmpty(t, mfaSessionID)

	mfaSession, _ := stateManager.GetMFASession(ctx, mfaSessionID)
	require.NotNil(t, mfaSession)
	assert.Equal(t, "user@example.com", mfaSession.Email)
	assert.Equal(t, "test-uid", mfaSession.LocalID)
	assert.Equal(t, "oauth-with-mfa", mfaSession.OAuthState)
}

// ===== Metadata Endpoint Tests =====

func TestHandleProtectedResourceMetadata(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handlers.HandleProtectedResourceMetadata(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var metadata map[string]interface{}
	json.NewDecoder(w.Body).Decode(&metadata)

	assert.NotEmpty(t, metadata["resource"])
	assert.NotEmpty(t, metadata["authorization_servers"])
}

func TestHandleAuthorizationServerMetadata(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	handlers.HandleAuthorizationServerMetadata(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var metadata map[string]interface{}
	json.NewDecoder(w.Body).Decode(&metadata)

	assert.NotEmpty(t, metadata["issuer"])
	assert.NotEmpty(t, metadata["authorization_endpoint"])
	assert.NotEmpty(t, metadata["token_endpoint"])
	assert.Contains(t, metadata["grant_types_supported"], "authorization_code")
	assert.Contains(t, metadata["response_types_supported"], "code")
	assert.Contains(t, metadata["code_challenge_methods_supported"], "S256")
}

// ===== Provider Normalization Tests =====

func TestNormalizeProvider(t *testing.T) {
	handlers, _, _ := testHandlers(t)

	tests := []struct {
		input    string
		expected string
	}{
		{"google", "google.com"},
		{"google.com", "google.com"},
		{"microsoft", "microsoft.com"},
		{"microsoft.com", "microsoft.com"},
		{"unknown", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := handlers.normalizeProvider(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ===== Concurrent Access Tests (Security) =====

func TestHandleAuthorize_ConcurrentRequests(t *testing.T) {
	handlers, stateManager, _ := testHandlers(t)
	ctx := context.Background()

	const numRequests = 50

	verifier := "test-verifier-123456789012345678901234567890"
	challenge := generatePKCEChallenge(verifier)

	// Launch concurrent authorize requests
	type result struct {
		statusCode int
		state      string
	}
	results := make(chan result, numRequests)

	for i := 0; i < numRequests; i++ {
		go func(id int) {
			stateParam := "state-" + string(rune(id))

			params := url.Values{}
			params.Set("response_type", "code")
			params.Set("client_id", "test-client")
			params.Set("redirect_uri", "https://app.example.com/callback")
			params.Set("state", stateParam)
			params.Set("code_challenge", challenge)
			params.Set("code_challenge_method", "S256")
			params.Set("provider", "google")

			req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
			w := httptest.NewRecorder()

			handlers.HandleAuthorize(w, req)

			results <- result{
				statusCode: w.Code,
				state:      stateParam,
			}
		}(i)
	}

	// Collect results
	successCount := 0
	statesSeen := make(map[string]bool)

	for i := 0; i < numRequests; i++ {
		res := <-results
		if res.statusCode == http.StatusFound {
			successCount++
			statesSeen[res.state] = true

			// Verify state was stored correctly
			stored, _ := stateManager.GetOAuthState(ctx, res.state)
			assert.NotNil(t, stored, "State should be stored: %s", res.state)
		}
	}

	// All should succeed
	assert.Equal(t, numRequests, successCount, "All concurrent requests should succeed")
	assert.Len(t, statesSeen, numRequests, "All states should be unique")
}

func TestHandleToken_ConcurrentCodeExchange(t *testing.T) {
	handlers, stateManager, _ := testHandlers(t)
	ctx := context.Background()

	verifier := "test-verifier-123456789012345678901234567890"
	challenge := generatePKCEChallenge(verifier)

	// Store one authorization code
	authCode := state.NewAuthorizationCode(
		"concurrent-code",
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

	// Try to exchange it concurrently (simulating race attack)
	const attempts = 10
	results := make(chan int, attempts)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "concurrent-code")
	form.Set("redirect_uri", "https://app.example.com/callback")
	form.Set("client_id", "test-client")
	form.Set("code_verifier", verifier)

	for i := 0; i < attempts; i++ {
		go func() {
			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			handlers.HandleToken(w, req)

			results <- w.Code
		}()
	}

	// Collect results
	successCount := 0
	for i := 0; i < attempts; i++ {
		code := <-results
		if code == http.StatusOK {
			successCount++
		}
	}

	// Only ONE should succeed (single-use code)
	assert.Equal(t, 1, successCount, "Only one concurrent exchange should succeed")
}
