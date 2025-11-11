package state

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/refractionpoint/lc-mcp-go/internal/crypto"
	"github.com/refractionpoint/lc-mcp-go/internal/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create test logger
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Helper to generate valid encryption key
func generateEncryptionKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key)
}

// Helper to setup test manager with Redis and encryption
func setupTestManager(t *testing.T) (*Manager, *miniredis.Miniredis) {
	t.Helper()

	// Setup miniredis
	mr := miniredis.RunT(t)

	// Setup Redis client
	redisClient, err := redis.New(&redis.Config{
		URL: "redis://" + mr.Addr(),
	}, testLogger())
	require.NoError(t, err)

	// Setup encryption
	os.Setenv("REDIS_ENCRYPTION_KEY", generateEncryptionKey(t))
	defer os.Unsetenv("REDIS_ENCRYPTION_KEY")

	encryption, err := crypto.NewTokenEncryption(testLogger())
	require.NoError(t, err)

	// Create manager
	manager := NewManager(redisClient, encryption, testLogger())
	require.NotNil(t, manager)

	return manager, mr
}

// ===== State Token Tests (CSRF Protection) =====

func TestGenerateState(t *testing.T) {
	manager, _ := setupTestManager(t)

	t.Run("generates valid state token", func(t *testing.T) {
		state, err := manager.GenerateState()
		assert.NoError(t, err)
		assert.NotEmpty(t, state)

		// Verify it's base64 URL encoded
		decoded, err := base64.URLEncoding.DecodeString(state)
		assert.NoError(t, err)
		assert.Len(t, decoded, 32) // 32 bytes = 256 bits
	})

	t.Run("generates unique tokens", func(t *testing.T) {
		tokens := make(map[string]bool)
		for i := 0; i < 100; i++ {
			state, err := manager.GenerateState()
			require.NoError(t, err)
			if tokens[state] {
				t.Fatal("Duplicate state token generated")
			}
			tokens[state] = true
		}
	})
}

func TestOAuthStateLifecycle(t *testing.T) {
	manager, mr := setupTestManager(t)
	ctx := context.Background()

	t.Run("store and retrieve state", func(t *testing.T) {
		state := NewOAuthState(
			"state123",
			"challenge",
			"S256",
			"https://app.com/callback",
			"client-id",
			"openid profile",
			"",
			"google.com",
		)

		err := manager.StoreOAuthState(ctx, state)
		require.NoError(t, err)

		retrieved, err := manager.GetOAuthState(ctx, "state123")
		assert.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, state.State, retrieved.State)
		assert.Equal(t, state.Provider, retrieved.Provider)
		assert.Equal(t, state.RedirectURI, retrieved.RedirectURI)
	})

	t.Run("consume state (single-use)", func(t *testing.T) {
		state := NewOAuthState("state456", "", "", "https://app.com/cb", "client", "scope", "", "microsoft.com")
		err := manager.StoreOAuthState(ctx, state)
		require.NoError(t, err)

		// First consumption succeeds
		consumed, err := manager.ConsumeOAuthState(ctx, "state456")
		assert.NoError(t, err)
		require.NotNil(t, consumed)
		assert.Equal(t, "state456", consumed.State)

		// Second consumption returns nil (single-use)
		consumed2, err := manager.ConsumeOAuthState(ctx, "state456")
		assert.NoError(t, err)
		assert.Nil(t, consumed2)
	})

	t.Run("state expires after TTL", func(t *testing.T) {
		state := NewOAuthState("state789", "", "", "https://app.com/cb", "client", "scope", "", "github.com")
		err := manager.StoreOAuthState(ctx, state)
		require.NoError(t, err)

		// Fast forward past TTL
		mr.FastForward((StateTTL + 1) * time.Second)

		// State should be expired
		retrieved, err := manager.GetOAuthState(ctx, "state789")
		assert.NoError(t, err)
		assert.Nil(t, retrieved)
	})

	t.Run("non-existent state returns nil", func(t *testing.T) {
		retrieved, err := manager.GetOAuthState(ctx, "non-existent")
		assert.NoError(t, err)
		assert.Nil(t, retrieved)
	})
}

// SECURITY CRITICAL: Test CSRF replay attack prevention
func TestOAuthState_ReplayAttackPrevention(t *testing.T) {
	manager, _ := setupTestManager(t)
	ctx := context.Background()

	state := NewOAuthState("replay-test", "", "", "https://app.com/cb", "client", "scope", "", "google.com")
	err := manager.StoreOAuthState(ctx, state)
	require.NoError(t, err)

	// Launch concurrent attempts to consume the same state
	const goroutines = 50
	var wg sync.WaitGroup
	results := make(chan *OAuthState, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			consumed, err := manager.ConsumeOAuthState(ctx, "replay-test")
			if err == nil && consumed != nil {
				results <- consumed
			}
		}()
	}

	wg.Wait()
	close(results)

	// SECURITY: Only ONE goroutine should successfully consume the state
	var successCount int
	for range results {
		successCount++
	}

	assert.Equal(t, 1, successCount, "Only one consumer should succeed - prevents CSRF replay")
}

// ===== Authorization Code Tests =====

func TestGenerateAuthorizationCode(t *testing.T) {
	manager, _ := setupTestManager(t)

	t.Run("generates valid code", func(t *testing.T) {
		code, err := manager.GenerateAuthorizationCode()
		assert.NoError(t, err)
		assert.NotEmpty(t, code)

		decoded, err := base64.URLEncoding.DecodeString(code)
		assert.NoError(t, err)
		assert.Len(t, decoded, 32)
	})

	t.Run("generates unique codes", func(t *testing.T) {
		codes := make(map[string]bool)
		for i := 0; i < 100; i++ {
			code, err := manager.GenerateAuthorizationCode()
			require.NoError(t, err)
			assert.False(t, codes[code], "Duplicate authorization code generated")
			codes[code] = true
		}
	})
}

func TestAuthorizationCodeLifecycle(t *testing.T) {
	manager, mr := setupTestManager(t)
	ctx := context.Background()

	t.Run("store and consume code with encryption", func(t *testing.T) {
		code := NewAuthorizationCode(
			"code123",
			"state123",
			"user-id-123",
			"firebase-id-token-secret",
			"firebase-refresh-token-secret",
			time.Now().Add(1*time.Hour).Unix(),
			"https://app.com/callback",
			"client-id",
			"openid profile",
			nil,
			nil,
		)

		err := manager.StoreAuthorizationCode(ctx, code)
		require.NoError(t, err)

		// Consume code
		consumed, err := manager.ConsumeAuthorizationCode(ctx, "code123")
		assert.NoError(t, err)
		require.NotNil(t, consumed)
		assert.Equal(t, "code123", consumed.Code)
		assert.Equal(t, "user-id-123", consumed.UID)
		// Verify tokens are decrypted correctly
		assert.Equal(t, "firebase-id-token-secret", consumed.FirebaseIDToken)
		assert.Equal(t, "firebase-refresh-token-secret", consumed.FirebaseRefreshToken)
	})

	t.Run("code is single-use only", func(t *testing.T) {
		code := NewAuthorizationCode("code456", "state456", "user456", "id-token", "refresh-token",
			time.Now().Add(1*time.Hour).Unix(), "https://app.com/cb", "client", "scope", nil, nil)
		err := manager.StoreAuthorizationCode(ctx, code)
		require.NoError(t, err)

		// First consumption succeeds
		consumed1, err := manager.ConsumeAuthorizationCode(ctx, "code456")
		assert.NoError(t, err)
		require.NotNil(t, consumed1)

		// Second consumption fails (security critical)
		consumed2, err := manager.ConsumeAuthorizationCode(ctx, "code456")
		assert.NoError(t, err)
		assert.Nil(t, consumed2)
	})

	t.Run("code expires after TTL", func(t *testing.T) {
		code := NewAuthorizationCode("code789", "state789", "user789", "id", "refresh",
			time.Now().Add(1*time.Hour).Unix(), "https://app.com/cb", "client", "scope", nil, nil)
		err := manager.StoreAuthorizationCode(ctx, code)
		require.NoError(t, err)

		// Fast forward past CodeTTL
		mr.FastForward((CodeTTL + 1) * time.Second)

		consumed, err := manager.ConsumeAuthorizationCode(ctx, "code789")
		assert.NoError(t, err)
		assert.Nil(t, consumed)
	})

	t.Run("PKCE parameters are preserved", func(t *testing.T) {
		challenge := "challenge123"
		method := "S256"
		code := NewAuthorizationCode("code-pkce", "state", "user", "id", "refresh",
			time.Now().Add(1*time.Hour).Unix(), "https://app.com/cb", "client", "scope", &challenge, &method)

		err := manager.StoreAuthorizationCode(ctx, code)
		require.NoError(t, err)

		consumed, err := manager.ConsumeAuthorizationCode(ctx, "code-pkce")
		assert.NoError(t, err)
		require.NotNil(t, consumed)
		assert.NotNil(t, consumed.CodeChallenge)
		assert.Equal(t, challenge, *consumed.CodeChallenge)
		assert.NotNil(t, consumed.CodeChallengeMethod)
		assert.Equal(t, method, *consumed.CodeChallengeMethod)
	})
}

// SECURITY CRITICAL: Test authorization code reuse attack prevention
func TestAuthorizationCode_ReuseAttackPrevention(t *testing.T) {
	manager, _ := setupTestManager(t)
	ctx := context.Background()

	code := NewAuthorizationCode("reuse-test", "state", "user", "id-token", "refresh",
		time.Now().Add(1*time.Hour).Unix(), "https://app.com/cb", "client", "scope", nil, nil)
	err := manager.StoreAuthorizationCode(ctx, code)
	require.NoError(t, err)

	// Launch concurrent attempts to exchange the same authorization code
	const goroutines = 50
	var wg sync.WaitGroup
	results := make(chan *AuthorizationCode, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			consumed, err := manager.ConsumeAuthorizationCode(ctx, "reuse-test")
			if err == nil && consumed != nil {
				results <- consumed
			}
		}()
	}

	wg.Wait()
	close(results)

	// SECURITY: Only ONE goroutine should successfully exchange the code
	var successCount int
	for range results {
		successCount++
	}

	assert.Equal(t, 1, successCount, "Only one exchange should succeed - prevents code reuse attack")
}

// ===== Access Token Tests =====

func TestGenerateAccessToken(t *testing.T) {
	manager, _ := setupTestManager(t)

	t.Run("generates valid token", func(t *testing.T) {
		token, err := manager.GenerateAccessToken()
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		decoded, err := base64.URLEncoding.DecodeString(token)
		assert.NoError(t, err)
		assert.Len(t, decoded, 32)
	})

	t.Run("generates unique tokens", func(t *testing.T) {
		tokens := make(map[string]bool)
		for i := 0; i < 100; i++ {
			token, err := manager.GenerateAccessToken()
			require.NoError(t, err)
			assert.False(t, tokens[token], "Duplicate access token generated")
			tokens[token] = true
		}
	})
}

func TestAccessTokenLifecycle(t *testing.T) {
	manager, mr := setupTestManager(t)
	ctx := context.Background()

	t.Run("store and retrieve token with encryption", func(t *testing.T) {
		token := NewAccessTokenData(
			"at123",
			"user123",
			"firebase-id-token-secret",
			"firebase-refresh-token-secret",
			time.Now().Add(1*time.Hour).Unix(),
			"openid profile",
			3600,
		)

		err := manager.StoreAccessToken(ctx, token)
		require.NoError(t, err)

		retrieved, err := manager.GetAccessTokenData(ctx, "at123")
		assert.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, "user123", retrieved.UID)
		assert.Equal(t, "firebase-id-token-secret", retrieved.FirebaseIDToken)
		assert.Equal(t, "firebase-refresh-token-secret", retrieved.FirebaseRefreshToken)
	})

	t.Run("expired token returns nil", func(t *testing.T) {
		token := NewAccessTokenData("at456", "user456", "id", "refresh",
			time.Now().Add(1*time.Hour).Unix(), "scope", 1)
		err := manager.StoreAccessToken(ctx, token)
		require.NoError(t, err)

		// Fast forward past expiration
		mr.FastForward(2 * time.Second)

		retrieved, err := manager.GetAccessTokenData(ctx, "at456")
		assert.NoError(t, err)
		assert.Nil(t, retrieved)
	})

	t.Run("revoke access token", func(t *testing.T) {
		token := NewAccessTokenData("at789", "user789", "id", "refresh",
			time.Now().Add(1*time.Hour).Unix(), "scope", 3600)
		err := manager.StoreAccessToken(ctx, token)
		require.NoError(t, err)

		// Revoke token
		err = manager.RevokeAccessToken(ctx, "at789")
		assert.NoError(t, err)

		// Verify token is gone
		retrieved, err := manager.GetAccessTokenData(ctx, "at789")
		assert.NoError(t, err)
		assert.Nil(t, retrieved)
	})

	t.Run("update Firebase tokens", func(t *testing.T) {
		token := NewAccessTokenData("at-update", "user", "old-id-token", "refresh",
			time.Now().Add(1*time.Hour).Unix(), "scope", 3600)
		err := manager.StoreAccessToken(ctx, token)
		require.NoError(t, err)

		// Update Firebase tokens
		newExpiresAt := time.Now().Add(2 * time.Hour).Unix()
		err = manager.UpdateAccessTokenFirebaseTokens(ctx, "at-update", "new-id-token", newExpiresAt)
		assert.NoError(t, err)

		// Verify update
		retrieved, err := manager.GetAccessTokenData(ctx, "at-update")
		assert.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, "new-id-token", retrieved.FirebaseIDToken)
		assert.Equal(t, newExpiresAt, retrieved.FirebaseExpiresAt)
	})
}

// ===== Refresh Token Tests =====

func TestRefreshTokenLifecycle(t *testing.T) {
	manager, _ := setupTestManager(t)
	ctx := context.Background()

	t.Run("store and retrieve refresh token", func(t *testing.T) {
		token := NewRefreshTokenData("rt123", "at123", "user123", "fb-refresh-secret", "scope")

		err := manager.StoreRefreshToken(ctx, token)
		require.NoError(t, err)

		retrieved, err := manager.GetRefreshTokenData(ctx, "rt123")
		assert.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, "user123", retrieved.UID)
		assert.Equal(t, "fb-refresh-secret", retrieved.FirebaseRefreshToken)
	})

	t.Run("revoke refresh token", func(t *testing.T) {
		token := NewRefreshTokenData("rt456", "at456", "user456", "fb-refresh", "scope")
		err := manager.StoreRefreshToken(ctx, token)
		require.NoError(t, err)

		err = manager.RevokeRefreshToken(ctx, "rt456")
		assert.NoError(t, err)

		retrieved, err := manager.GetRefreshTokenData(ctx, "rt456")
		assert.NoError(t, err)
		assert.Nil(t, retrieved)
	})
}

// To be continued in manager_test_part2.go due to size...
