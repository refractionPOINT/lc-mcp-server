package token

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/firebase"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockFirebaseClient implements firebase.ClientInterface for testing
type mockFirebaseClient struct {
	refreshIDTokenFunc func(ctx context.Context, refreshToken string) (string, int64, error)
}

func newMockFirebaseClient() *mockFirebaseClient {
	return &mockFirebaseClient{
		refreshIDTokenFunc: func(ctx context.Context, refreshToken string) (string, int64, error) {
			// Default: return new token with 1 hour expiry
			expiresAt := time.Now().Add(1 * time.Hour).Unix()
			return "refreshed-firebase-id-token", expiresAt, nil
		},
	}
}

func (m *mockFirebaseClient) RefreshIDToken(ctx context.Context, refreshToken string) (string, int64, error) {
	return m.refreshIDTokenFunc(ctx, refreshToken)
}

func (m *mockFirebaseClient) CreateAuthURI(ctx context.Context, providerID, redirectURI string, scopes []string) (sessionID, authURI string, err error) {
	return "session-id", "https://auth.example.com", nil
}

func (m *mockFirebaseClient) SignInWithIdp(ctx context.Context, requestURI, queryString, sessionID, providerID string) (*firebase.SignInWithIdpResponse, error) {
	return &firebase.SignInWithIdpResponse{
		LocalID:      "test-uid",
		IDToken:      "id-token",
		RefreshToken: "refresh-token",
		ExpiresIn:    "3600",
	}, nil
}

func (m *mockFirebaseClient) ValidateProviderCallback(fullRequestURI string) (string, error) {
	return "callback-query", nil
}

func (m *mockFirebaseClient) FinalizeMFASignIn(ctx context.Context, mfaPendingCredential, mfaEnrollmentID, verificationCode string) (*firebase.FinalizeMFAResponse, error) {
	return &firebase.FinalizeMFAResponse{
		LocalID:      "test-uid",
		IDToken:      "mfa-id-token",
		RefreshToken: "mfa-refresh-token",
		ExpiresIn:    "3600",
	}, nil
}

func setupTestManager(t *testing.T) (*Manager, *state.Manager, *mockFirebaseClient) {
	t.Helper()

	stateManager, _ := setupTestStateManager(t)
	mockFB := newMockFirebaseClient()

	manager := NewManager(stateManager, mockFB, testLogger())

	return manager, stateManager, mockFB
}

// ===== CreateTokenResponse Tests =====

func TestCreateTokenResponse_Success(t *testing.T) {
	manager, _, _ := setupTestManager(t)
	ctx := context.Background()

	uid := "user-123"
	firebaseIDToken := "firebase-id-token"
	firebaseRefreshToken := "firebase-refresh-token"
	firebaseExpiresAt := time.Now().Add(1 * time.Hour).Unix()
	scope := "openid email profile"

	response, err := manager.CreateTokenResponse(ctx, uid, firebaseIDToken, firebaseRefreshToken, firebaseExpiresAt, scope)

	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, state.TokenTTL, response.ExpiresIn)
	assert.Equal(t, scope, response.Scope)
}

// ===== RefreshAccessToken Tests =====

func TestRefreshAccessToken_Success(t *testing.T) {
	manager, stateManager, mockFB := setupTestManager(t)
	ctx := context.Background()

	// First create initial tokens
	initial, err := manager.CreateTokenResponse(ctx, "user-123", "firebase-id", "firebase-refresh", time.Now().Add(1*time.Hour).Unix(), "openid email")
	require.NoError(t, err)

	// Configure mock Firebase
	firebaseRefreshCalled := false
	mockFB.refreshIDTokenFunc = func(ctx context.Context, refreshToken string) (string, int64, error) {
		firebaseRefreshCalled = true
		return "new-firebase-id-token", time.Now().Add(1 * time.Hour).Unix(), nil
	}

	// Execute refresh
	refreshed, err := manager.RefreshAccessToken(ctx, initial.RefreshToken)

	require.NoError(t, err)
	assert.NotNil(t, refreshed)
	assert.NotEqual(t, initial.AccessToken, refreshed.AccessToken, "Should issue NEW access token")
	assert.NotEqual(t, initial.RefreshToken, refreshed.RefreshToken, "Should rotate refresh token")
	assert.True(t, firebaseRefreshCalled)

	// SECURITY: Verify old refresh token is revoked
	oldRefreshData, err := stateManager.GetRefreshTokenData(ctx, initial.RefreshToken)
	assert.NoError(t, err)
	assert.Nil(t, oldRefreshData, "Old refresh token should be revoked")
}

func TestRefreshAccessToken_RefreshTokenNotFound(t *testing.T) {
	manager, _, _ := setupTestManager(t)
	ctx := context.Background()

	response, err := manager.RefreshAccessToken(ctx, "non-existent-refresh-token")

	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Contains(t, err.Error(), "invalid or expired refresh token")
}

func TestRefreshAccessToken_FirebaseRefreshFails(t *testing.T) {
	manager, _, mockFB := setupTestManager(t)
	ctx := context.Background()

	// Create initial tokens
	initial, err := manager.CreateTokenResponse(ctx, "user-123", "fb-id", "fb-refresh", time.Now().Add(1*time.Hour).Unix(), "openid")
	require.NoError(t, err)

	// Mock Firebase to fail
	mockFB.refreshIDTokenFunc = func(ctx context.Context, refreshToken string) (string, int64, error) {
		return "", 0, errors.New("Firebase API error")
	}

	response, err := manager.RefreshAccessToken(ctx, initial.RefreshToken)

	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Contains(t, err.Error(), "failed to refresh Firebase token")
}

// ===== RevokeToken Tests =====

func TestRevokeToken_AccessToken(t *testing.T) {
	manager, stateManager, _ := setupTestManager(t)
	ctx := context.Background()

	// Create tokens
	tokens, err := manager.CreateTokenResponse(ctx, "user-123", "fb-id", "fb-refresh", time.Now().Add(1*time.Hour).Unix(), "openid")
	require.NoError(t, err)

	// Revoke access token
	err = manager.RevokeToken(ctx, tokens.AccessToken, "access_token")

	assert.NoError(t, err, "Revoke should always succeed per OAuth 2.0 spec")

	// Verify token is revoked
	tokenData, err := stateManager.GetAccessTokenData(ctx, tokens.AccessToken)
	assert.NoError(t, err)
	assert.Nil(t, tokenData)
}

func TestRevokeToken_RefreshToken(t *testing.T) {
	manager, stateManager, _ := setupTestManager(t)
	ctx := context.Background()

	// Create tokens
	tokens, err := manager.CreateTokenResponse(ctx, "user-123", "fb-id", "fb-refresh", time.Now().Add(1*time.Hour).Unix(), "openid")
	require.NoError(t, err)

	// Revoke refresh token
	err = manager.RevokeToken(ctx, tokens.RefreshToken, "refresh_token")

	assert.NoError(t, err)

	// Verify token is revoked
	refreshData, err := stateManager.GetRefreshTokenData(ctx, tokens.RefreshToken)
	assert.NoError(t, err)
	assert.Nil(t, refreshData)
}

func TestRevokeToken_NonExistentToken(t *testing.T) {
	manager, _, _ := setupTestManager(t)
	ctx := context.Background()

	// Per OAuth 2.0 spec, revocation of non-existent token should succeed
	err := manager.RevokeToken(ctx, "non-existent-token", "")

	assert.NoError(t, err, "Revoke should always succeed per OAuth 2.0 spec")
}

// ===== IntrospectToken Tests =====

func TestIntrospectToken_ActiveToken(t *testing.T) {
	manager, _, _ := setupTestManager(t)
	ctx := context.Background()

	// Create active token
	tokens, err := manager.CreateTokenResponse(ctx, "user-123", "fb-id", "fb-refresh", time.Now().Add(1*time.Hour).Unix(), "openid email profile")
	require.NoError(t, err)

	response, err := manager.IntrospectToken(ctx, tokens.AccessToken)

	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.True(t, response.Active)
	assert.Equal(t, "openid email profile", response.Scope)
	assert.Equal(t, "mcp", response.ClientID)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, "user-123", response.Sub)
}

func TestIntrospectToken_NonExistentToken(t *testing.T) {
	manager, _, _ := setupTestManager(t)
	ctx := context.Background()

	response, err := manager.IntrospectToken(ctx, "non-existent-token")

	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.False(t, response.Active)
	assert.Empty(t, response.Scope)
	assert.Empty(t, response.Sub)
}

// ===== Security and Compliance Tests =====

func TestRefreshAccessToken_TokenRotation(t *testing.T) {
	// SECURITY TEST: Ensure token rotation prevents reuse
	manager, _, _ := setupTestManager(t)
	ctx := context.Background()

	// Create initial tokens
	initial, err := manager.CreateTokenResponse(ctx, "user-123", "fb-id", "fb-refresh", time.Now().Add(1*time.Hour).Unix(), "openid")
	require.NoError(t, err)

	// First refresh should succeed
	refreshed1, err1 := manager.RefreshAccessToken(ctx, initial.RefreshToken)
	assert.NoError(t, err1)
	assert.NotNil(t, refreshed1)

	// Second refresh with same token should fail (token rotated)
	refreshed2, err2 := manager.RefreshAccessToken(ctx, initial.RefreshToken)
	assert.Error(t, err2, "Refresh token should be invalid after first use (rotation)")
	assert.Nil(t, refreshed2)
}

func TestIntrospectToken_RFC7662Compliance(t *testing.T) {
	t.Run("inactive tokens return minimal response", func(t *testing.T) {
		manager, _, _ := setupTestManager(t)
		ctx := context.Background()

		resp, err := manager.IntrospectToken(ctx, "non-existent")

		require.NoError(t, err)
		assert.False(t, resp.Active)
		// Per RFC 7662, when active=false, other fields SHOULD be omitted
		assert.Empty(t, resp.Scope)
		assert.Empty(t, resp.Sub)
	})
}

func TestTokenResponse_OAuth2Compliance(t *testing.T) {
	t.Run("token type is Bearer", func(t *testing.T) {
		manager, _, _ := setupTestManager(t)
		ctx := context.Background()

		tokens, err := manager.CreateTokenResponse(ctx, "user", "fb-id", "fb-refresh", time.Now().Add(1*time.Hour).Unix(), "openid")

		require.NoError(t, err)
		assert.Equal(t, "Bearer", tokens.TokenType, "Token type must be 'Bearer' per RFC 6749")
	})
}
