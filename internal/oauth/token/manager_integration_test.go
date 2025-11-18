package token

import (
	"context"
	"errors"
	"log/slog"
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

// mockJWTExchange creates a mock JWT exchange function for testing
func mockJWTExchange(jwt string, shouldError error) JWTExchangeFunc {
	return func(firebaseIDToken, oid string, logger *slog.Logger) (string, error) {
		if shouldError != nil {
			return "", shouldError
		}
		return jwt, nil
	}
}

func setupTestManager(t *testing.T) (*Manager, *state.Manager, *mockFirebaseClient) {
	t.Helper()

	stateManager, _ := setupTestStateManager(t)
	mockFB := newMockFirebaseClient()

	manager := NewManager(stateManager, mockFB, testLogger())
	// Set default mock JWT exchange that returns a valid JWT
	manager.WithJWTExchange(mockJWTExchange("mock-limacharlie-jwt", nil))

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

// ===== Token Extension Security Tests =====

func TestTokenExtension_TrackingFields(t *testing.T) {
	t.Run("new tokens have zero extension count", func(t *testing.T) {
		manager, stateManager, _ := setupTestManager(t)
		ctx := context.Background()

		tokens, err := manager.CreateTokenResponse(ctx, "user-123", "fb-id", "fb-refresh", time.Now().Add(1*time.Hour).Unix(), "openid")
		require.NoError(t, err)

		tokenData, err := stateManager.GetAccessTokenData(ctx, tokens.AccessToken)
		require.NoError(t, err)
		require.NotNil(t, tokenData)

		assert.Equal(t, 0, tokenData.ExtensionCount, "New token should have zero extensions")
		assert.Equal(t, int64(0), tokenData.LastExtendedAt, "New token should not have LastExtendedAt set")
	})
}

func TestTokenExtension_LimitsEnforced(t *testing.T) {
	t.Run("token at max extensions is rejected during grace period", func(t *testing.T) {
		manager, stateManager, _ := setupTestManager(t)
		ctx := context.Background()

		// Create token and manually set it to max extensions
		uid := "user-max-extensions"
		tokenData := state.NewAccessTokenData(
			"maxed-out-token",
			uid,
			"fb-id",
			"fb-refresh",
			time.Now().Add(1*time.Hour).Unix(),
			"openid",
			state.TokenTTL,
		)
		// Set to max extensions and make it expired (but in grace period)
		tokenData.ExtensionCount = state.MaxTokenExtensions
		tokenData.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix() // Expired 1 hour ago

		err := stateManager.StoreAccessToken(ctx, tokenData)
		require.NoError(t, err)

		// Attempt to validate should fail due to extension limit
		result, err := manager.ValidateAccessToken(ctx, "maxed-out-token", true)

		require.NoError(t, err)
		assert.False(t, result.Valid, "Token at max extensions should be rejected")
		assert.Contains(t, result.Error, "extension limit reached")
	})

	t.Run("token below max extensions can be extended", func(t *testing.T) {
		manager, stateManager, mockFB := setupTestManager(t)
		ctx := context.Background()

		// Mock Firebase to return valid tokens
		mockFB.refreshIDTokenFunc = func(ctx context.Context, refreshToken string) (string, int64, error) {
			return "new-fb-id-token", time.Now().Add(1 * time.Hour).Unix(), nil
		}

		// Create token with one less than max extensions
		tokenData := state.NewAccessTokenData(
			"almost-maxed-token",
			"user",
			"fb-id",
			"fb-refresh",
			time.Now().Add(1*time.Hour).Unix(),
			"openid",
			state.TokenTTL,
		)
		tokenData.ExtensionCount = state.MaxTokenExtensions - 1
		tokenData.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix() // Expired 1 hour ago

		err := stateManager.StoreAccessToken(ctx, tokenData)
		require.NoError(t, err)

		// Validation should succeed and increment extension count
		result, err := manager.ValidateAccessToken(ctx, "almost-maxed-token", true)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Valid, "Token below max extensions should be extended successfully")
		assert.True(t, result.Refreshed, "Token should be marked as refreshed")
		assert.Equal(t, "user", result.UID)
		assert.Equal(t, "new-fb-id-token", result.FirebaseIDToken)
		assert.Equal(t, "mock-limacharlie-jwt", result.LimaCharlieJWT)

		// Verify extension count was incremented
		updatedToken, err := stateManager.GetAccessTokenData(ctx, "almost-maxed-token")
		require.NoError(t, err)
		require.NotNil(t, updatedToken)
		assert.Equal(t, state.MaxTokenExtensions, updatedToken.ExtensionCount, "Extension count should now be at max")
		assert.NotEqual(t, int64(0), updatedToken.LastExtendedAt, "LastExtendedAt should be set")
		// Verify token expiration was extended
		assert.Greater(t, updatedToken.ExpiresAt, time.Now().Unix(), "Token should have future expiration")
	})
}

func TestTokenExtension_CountIncrementsOnExtension(t *testing.T) {
	manager, stateManager, mockFB := setupTestManager(t)
	ctx := context.Background()

	// Mock Firebase to return valid tokens
	mockFB.refreshIDTokenFunc = func(ctx context.Context, refreshToken string) (string, int64, error) {
		return "refreshed-fb-id-token", time.Now().Add(1 * time.Hour).Unix(), nil
	}

	// Create initial token
	tokens, err := manager.CreateTokenResponse(ctx, "user", "fb-id", "fb-refresh", time.Now().Add(1*time.Hour).Unix(), "openid")
	require.NoError(t, err)

	// Check initial extension count
	tokenData, err := stateManager.GetAccessTokenData(ctx, tokens.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, 0, tokenData.ExtensionCount, "Initial extension count should be 0")
	assert.Equal(t, int64(0), tokenData.LastExtendedAt, "LastExtendedAt should not be set initially")

	// Set token to be expiring soon (within refresh buffer)
	tokenData.ExpiresAt = time.Now().Add(30 * time.Minute).Unix() // Less than 1 hour buffer
	err = stateManager.StoreAccessToken(ctx, tokenData)
	require.NoError(t, err)

	// Validate token - should proactively extend it
	result, err := manager.ValidateAccessToken(ctx, tokens.AccessToken, true)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Valid, "Token should be valid after extension")
	assert.True(t, result.Refreshed, "Token should be marked as refreshed")

	// Verify extension count was incremented
	updatedToken, err := stateManager.GetAccessTokenData(ctx, tokens.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, 1, updatedToken.ExtensionCount, "Extension count should be incremented to 1")
	assert.NotEqual(t, int64(0), updatedToken.LastExtendedAt, "LastExtendedAt should now be set")
	assert.Greater(t, updatedToken.ExpiresAt, tokenData.ExpiresAt, "Token expiration should be extended")
}

func TestTokenExtension_MaxExtensionsConstant(t *testing.T) {
	t.Run("max extensions is reasonable", func(t *testing.T) {
		// With 1-day TTL, 30 extensions = 30 days max lifetime
		// This matches the Firebase refresh token validity
		assert.Equal(t, 30, state.MaxTokenExtensions)
		assert.Equal(t, 86400, state.TokenTTL, "TokenTTL should be 1 day (86400 seconds)")

		maxLifetime := state.TokenTTL * state.MaxTokenExtensions
		assert.Equal(t, 2592000, maxLifetime, "Max token lifetime should match refresh token TTL (30 days)")
	})
}

func TestTokenGracePeriod_Constants(t *testing.T) {
	t.Run("grace period supports reasonable inactivity", func(t *testing.T) {
		// Grace period should be 23 hours (82800 seconds) to balance security and UX
		assert.Equal(t, 82800, state.TokenGracePeriod, "Grace period should be 23 hours")
	})

	t.Run("token refresh buffer is reasonable", func(t *testing.T) {
		// Refresh buffer should proactively extend before expiration
		assert.Equal(t, 3600, state.TokenRefreshBuffer, "Token refresh buffer should be 1 hour")
		assert.Less(t, state.TokenRefreshBuffer, state.TokenTTL, "Refresh buffer must be less than TTL")
	})
}

func TestTokenExtension_SecurityAuditFields(t *testing.T) {
	t.Run("extension tracking fields exist", func(t *testing.T) {
		tokenData := state.NewAccessTokenData(
			"audit-test-token",
			"user",
			"fb-id",
			"fb-refresh",
			time.Now().Add(1*time.Hour).Unix(),
			"openid",
			state.TokenTTL,
		)

		// Verify extension tracking fields are accessible
		assert.Equal(t, 0, tokenData.ExtensionCount, "ExtensionCount should be initialized")
		assert.Equal(t, int64(0), tokenData.LastExtendedAt, "LastExtendedAt should be initialized")

		// Simulate extension
		tokenData.ExtensionCount = 5
		tokenData.LastExtendedAt = time.Now().Unix()

		assert.Equal(t, 5, tokenData.ExtensionCount)
		assert.NotEqual(t, int64(0), tokenData.LastExtendedAt)
	})
}
