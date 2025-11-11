package state

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===== MFA Session Tests (Security Critical) =====

func TestMFASessionLifecycle(t *testing.T) {
	manager, mr := setupTestManager(t)
	ctx := context.Background()

	t.Run("store and retrieve MFA session with encryption", func(t *testing.T) {
		sessionID, err := manager.GenerateMFASessionID()
		require.NoError(t, err)

		session := NewMFASession(
			"mfa-pending-credential",
			"enrollment-id",
			"oauth-state-123",
			"John Doe",
			"local-id-123",
			"john@example.com",
			nil,
		)

		err = manager.StoreMFASession(ctx, sessionID, session)
		require.NoError(t, err)

		// Retrieve session
		retrieved, err := manager.GetMFASession(ctx, sessionID)
		assert.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, "John Doe", retrieved.DisplayName)
		assert.Equal(t, "john@example.com", retrieved.Email)
		assert.Equal(t, "oauth-state-123", retrieved.OAuthState)
		assert.Equal(t, 0, retrieved.AttemptCount)
	})

	t.Run("consume MFA session (single-use)", func(t *testing.T) {
		sessionID, err := manager.GenerateMFASessionID()
		require.NoError(t, err)

		session := NewMFASession("cred", "enroll", "state", "User", "local", "email@test.com", nil)
		err = manager.StoreMFASession(ctx, sessionID, session)
		require.NoError(t, err)

		// First consumption succeeds
		consumed, err := manager.ConsumeMFASession(ctx, sessionID)
		assert.NoError(t, err)
		require.NotNil(t, consumed)

		// Second consumption returns nil
		consumed2, err := manager.ConsumeMFASession(ctx, sessionID)
		assert.NoError(t, err)
		assert.Nil(t, consumed2)
	})

	t.Run("MFA session expires after TTL", func(t *testing.T) {
		sessionID, err := manager.GenerateMFASessionID()
		require.NoError(t, err)

		session := NewMFASession("cred", "enroll", "state", "User", "local", "email", nil)
		err = manager.StoreMFASession(ctx, sessionID, session)
		require.NoError(t, err)

		// Fast forward past MFA TTL
		mr.FastForward((MFATTL + 1) * time.Second)

		// Session should be expired
		retrieved, err := manager.GetMFASession(ctx, sessionID)
		assert.NoError(t, err)
		assert.Nil(t, retrieved)
	})
}

// SECURITY CRITICAL: Test MFA attempt limiting
func TestMFAAttemptLimiting(t *testing.T) {
	manager, _ := setupTestManager(t)
	ctx := context.Background()

	sessionID, err := manager.GenerateMFASessionID()
	require.NoError(t, err)

	session := NewMFASession("cred", "enroll", "state", "User", "local", "email", nil)
	err = manager.StoreMFASession(ctx, sessionID, session)
	require.NoError(t, err)

	t.Run("increment MFA attempts atomically", func(t *testing.T) {
		// First attempt
		count, err := manager.IncrementMFAAttempts(ctx, sessionID)
		assert.NoError(t, err)
		assert.Equal(t, 1, count)

		// Second attempt
		count, err = manager.IncrementMFAAttempts(ctx, sessionID)
		assert.NoError(t, err)
		assert.Equal(t, 2, count)

		// Third attempt
		count, err = manager.IncrementMFAAttempts(ctx, sessionID)
		assert.NoError(t, err)
		assert.Equal(t, 3, count)

		// Verify count is at max
		count, err = manager.GetMFAAttemptCount(ctx, sessionID)
		assert.NoError(t, err)
		assert.Equal(t, 3, count)
	})

	t.Run("attempt counter is atomic (no race conditions)", func(t *testing.T) {
		newSessionID, err := manager.GenerateMFASessionID()
		require.NoError(t, err)

		newSession := NewMFASession("cred", "enroll", "state", "User", "local", "email", nil)
		err = manager.StoreMFASession(ctx, newSessionID, newSession)
		require.NoError(t, err)

		// Launch concurrent increments
		const goroutines = 10
		done := make(chan int, goroutines)

		for i := 0; i < goroutines; i++ {
			go func() {
				count, err := manager.IncrementMFAAttempts(ctx, newSessionID)
				if err == nil {
					done <- count
				}
			}()
		}

		// Collect all counts
		counts := make(map[int]bool)
		for i := 0; i < goroutines; i++ {
			count := <-done
			// Each goroutine should get a unique count
			if counts[count] {
				t.Errorf("Duplicate count %d - race condition detected!", count)
			}
			counts[count] = true
		}

		// Final count should be exactly goroutines
		finalCount, err := manager.GetMFAAttemptCount(ctx, newSessionID)
		assert.NoError(t, err)
		assert.Equal(t, goroutines, finalCount)
	})

	t.Run("cannot increment attempts for non-existent session", func(t *testing.T) {
		_, err := manager.IncrementMFAAttempts(ctx, "non-existent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

// SECURITY: Test MFA session integrity (tampering detection)
func TestMFASessionIntegrity(t *testing.T) {
	manager, mr := setupTestManager(t)
	ctx := context.Background()

	sessionID, err := manager.GenerateMFASessionID()
	require.NoError(t, err)

	session := NewMFASession("cred", "enroll", "state", "User", "local", "email", nil)
	err = manager.StoreMFASession(ctx, sessionID, session)
	require.NoError(t, err)

	// Attempt to tamper with the encrypted MFA session in Redis
	// Get the encrypted data
	key := MFAPrefix + sessionID
	encryptedData, err := manager.redis.Get(ctx, key)
	require.NoError(t, err)
	require.NotEmpty(t, encryptedData)

	// Tamper with one character in the encrypted data
	tamperedData := encryptedData[:len(encryptedData)-1] + "X"
	err = manager.redis.Set(ctx, key, tamperedData, time.Duration(MFATTL)*time.Second)
	require.NoError(t, err)

	// Attempt to retrieve - should fail due to integrity check
	retrieved, err := manager.GetMFASession(ctx, sessionID)
	assert.Error(t, err)
	assert.Nil(t, retrieved)
	assert.Contains(t, err.Error(), "integrity check failed")

	// Same for consumption
	mr.Set(key, tamperedData)
	consumed, err := manager.ConsumeMFASession(ctx, sessionID)
	assert.Error(t, err)
	assert.Nil(t, consumed)
	assert.Contains(t, err.Error(), "integrity check failed")
}

// ===== Client Registration Tests =====

func TestClientRegistrationLifecycle(t *testing.T) {
	manager, _ := setupTestManager(t)
	ctx := context.Background()

	t.Run("generate and store client registration", func(t *testing.T) {
		clientID, err := manager.GenerateClientID()
		assert.NoError(t, err)
		assert.NotEmpty(t, clientID)
		assert.Contains(t, clientID, "mcp_")

		client := NewClientRegistration(
			clientID,
			"Test App",
			[]string{"https://app.com/callback", "https://app.com/callback2"},
		)

		err = manager.StoreClientRegistration(ctx, client)
		require.NoError(t, err)

		// Retrieve client
		retrieved, err := manager.GetClientRegistration(ctx, clientID)
		assert.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, "Test App", retrieved.ClientName)
		assert.Len(t, retrieved.RedirectURIs, 2)
	})

	t.Run("client registration has no expiration", func(t *testing.T) {
		clientID, err := manager.GenerateClientID()
		require.NoError(t, err)

		client := NewClientRegistration(clientID, "Persistent App", []string{"https://app.com/cb"})
		err = manager.StoreClientRegistration(ctx, client)
		require.NoError(t, err)

		// Client should persist (no TTL)
		retrieved, err := manager.GetClientRegistration(ctx, clientID)
		assert.NoError(t, err)
		assert.NotNil(t, retrieved)
	})

	t.Run("non-existent client returns nil", func(t *testing.T) {
		retrieved, err := manager.GetClientRegistration(ctx, "non-existent")
		assert.NoError(t, err)
		assert.Nil(t, retrieved)
	})
}

// ===== Provider Selection Tests =====

func TestSelectionSessionLifecycle(t *testing.T) {
	manager, mr := setupTestManager(t)
	ctx := context.Background()

	t.Run("store and consume selection session", func(t *testing.T) {
		sessionID, err := manager.GenerateSelectionSessionID()
		require.NoError(t, err)

		params := map[string]string{
			"response_type": "code",
			"client_id":     "test-client",
			"redirect_uri":  "https://app.com/callback",
			"scope":         "openid profile",
			"state":         "state123",
		}

		err = manager.StoreSelectionSession(ctx, sessionID, params)
		require.NoError(t, err)

		// Consume session
		consumed, err := manager.ConsumeSelectionSession(ctx, sessionID)
		assert.NoError(t, err)
		require.NotNil(t, consumed)
		assert.Equal(t, "test-client", consumed["client_id"])
		assert.Equal(t, "openid profile", consumed["scope"])

		// Second consumption returns nil
		consumed2, err := manager.ConsumeSelectionSession(ctx, sessionID)
		assert.NoError(t, err)
		assert.Nil(t, consumed2)
	})

	t.Run("selection session expires", func(t *testing.T) {
		sessionID, err := manager.GenerateSelectionSessionID()
		require.NoError(t, err)

		params := map[string]string{"test": "value"}
		err = manager.StoreSelectionSession(ctx, sessionID, params)
		require.NoError(t, err)

		// Fast forward past SelectionTTL
		mr.FastForward((SelectionTTL + 1) * time.Second)

		consumed, err := manager.ConsumeSelectionSession(ctx, sessionID)
		assert.NoError(t, err)
		assert.Nil(t, consumed)
	})
}

// ===== Security Tests =====

func TestTokenUniqueness(t *testing.T) {
	manager, _ := setupTestManager(t)

	t.Run("all token types are unique", func(t *testing.T) {
		const iterations = 100

		// Test state tokens
		states := make(map[string]bool)
		for i := 0; i < iterations; i++ {
			token, err := manager.GenerateState()
			require.NoError(t, err)
			assert.False(t, states[token], "Duplicate state token")
			states[token] = true
		}

		// Test authorization codes
		codes := make(map[string]bool)
		for i := 0; i < iterations; i++ {
			code, err := manager.GenerateAuthorizationCode()
			require.NoError(t, err)
			assert.False(t, codes[code], "Duplicate authorization code")
			codes[code] = true
		}

		// Test access tokens
		accessTokens := make(map[string]bool)
		for i := 0; i < iterations; i++ {
			token, err := manager.GenerateAccessToken()
			require.NoError(t, err)
			assert.False(t, accessTokens[token], "Duplicate access token")
			accessTokens[token] = true
		}

		// Test refresh tokens
		refreshTokens := make(map[string]bool)
		for i := 0; i < iterations; i++ {
			token, err := manager.GenerateRefreshToken()
			require.NoError(t, err)
			assert.False(t, refreshTokens[token], "Duplicate refresh token")
			refreshTokens[token] = true
		}
	})
}

func TestEncryptionIntegrity(t *testing.T) {
	manager, _ := setupTestManager(t)
	ctx := context.Background()

	t.Run("authorization code tokens are encrypted at rest", func(t *testing.T) {
		code := NewAuthorizationCode("code-encrypted", "state", "user",
			"sensitive-id-token", "sensitive-refresh-token",
			time.Now().Add(1*time.Hour).Unix(), "https://app.com/cb", "client", "scope", nil, nil)

		err := manager.StoreAuthorizationCode(ctx, code)
		require.NoError(t, err)

		// Verify data in Redis is encrypted (not plaintext)
		key := CodePrefix + "code-encrypted"
		rawData, err := manager.redis.Get(ctx, key)
		require.NoError(t, err)
		require.NotEmpty(t, rawData)

		// Plaintext tokens should NOT appear in raw data
		assert.NotContains(t, rawData, "sensitive-id-token")
		assert.NotContains(t, rawData, "sensitive-refresh-token")
	})

	t.Run("access token Firebase tokens are encrypted at rest", func(t *testing.T) {
		token := NewAccessTokenData("at-encrypted", "user", "sensitive-firebase-id", "sensitive-firebase-refresh",
			time.Now().Add(1*time.Hour).Unix(), "scope", 3600)

		err := manager.StoreAccessToken(ctx, token)
		require.NoError(t, err)

		// Verify data in Redis is encrypted
		key := TokenPrefix + "at-encrypted"
		rawData, err := manager.redis.Get(ctx, key)
		require.NoError(t, err)
		require.NotEmpty(t, rawData)

		// Plaintext tokens should NOT appear
		assert.NotContains(t, rawData, "sensitive-firebase-id")
		assert.NotContains(t, rawData, "sensitive-firebase-refresh")
	})

	t.Run("refresh token is encrypted at rest", func(t *testing.T) {
		token := NewRefreshTokenData("rt-encrypted", "at", "user", "sensitive-firebase-refresh", "scope")

		err := manager.StoreRefreshToken(ctx, token)
		require.NoError(t, err)

		// Verify encryption
		key := RefreshPrefix + "rt-encrypted"
		rawData, err := manager.redis.Get(ctx, key)
		require.NoError(t, err)
		require.NotEmpty(t, rawData)

		assert.NotContains(t, rawData, "sensitive-firebase-refresh")
	})

	t.Run("MFA session is encrypted at rest", func(t *testing.T) {
		sessionID, err := manager.GenerateMFASessionID()
		require.NoError(t, err)

		session := NewMFASession("sensitive-credential", "enrollment", "state", "User", "local-id", "email@test.com", nil)
		err = manager.StoreMFASession(ctx, sessionID, session)
		require.NoError(t, err)

		// Verify entire session is encrypted
		key := MFAPrefix + sessionID
		rawData, err := manager.redis.Get(ctx, key)
		require.NoError(t, err)
		require.NotEmpty(t, rawData)

		// No plaintext fields should appear
		assert.NotContains(t, rawData, "sensitive-credential")
		assert.NotContains(t, rawData, "email@test.com")
		assert.NotContains(t, rawData, "local-id")
	})
}

func TestTTLConstants(t *testing.T) {
	t.Run("TTL constants are reasonable", func(t *testing.T) {
		assert.Equal(t, 600, StateTTL, "State TTL should be 10 minutes")
		assert.Equal(t, 300, CodeTTL, "Code TTL should be 5 minutes")
		assert.Equal(t, 3600, TokenTTL, "Token TTL should be 1 hour")
		assert.Equal(t, 2592000, RefreshTTL, "Refresh TTL should be 30 days")
		assert.Equal(t, 300, SelectionTTL, "Selection TTL should be 5 minutes")
		assert.Equal(t, 300, MFATTL, "MFA TTL should be 5 minutes")
		assert.Equal(t, 3, MaxMFAAttempts, "Max MFA attempts should be 3")
	})
}

func TestKeyPrefixConstants(t *testing.T) {
	t.Run("key prefixes are unique", func(t *testing.T) {
		prefixes := []string{
			StatePrefix,
			CodePrefix,
			TokenPrefix,
			RefreshPrefix,
			ClientPrefix,
			SelectionPrefix,
			MFAPrefix,
			SessionPrefix,
			FBSessionPrefix,
		}

		// Verify all prefixes are unique
		seen := make(map[string]bool)
		for _, prefix := range prefixes {
			assert.False(t, seen[prefix], "Duplicate key prefix: "+prefix)
			seen[prefix] = true
		}

		// Verify all have "oauth:" namespace
		for _, prefix := range prefixes {
			assert.Contains(t, prefix, "oauth:", "Prefix should be namespaced: "+prefix)
		}
	})
}
