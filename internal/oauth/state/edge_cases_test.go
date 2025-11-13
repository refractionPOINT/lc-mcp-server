package state

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===== Atomic Operations Tests (SECURITY CRITICAL) =====

func TestAtomicConsumeOAuthStateAndMappings(t *testing.T) {
	manager, mr := setupTestManager(t)
	ctx := context.Background()

	t.Run("atomically consumes all three keys", func(t *testing.T) {
		stateKey := StatePrefix + "test-state"
		sessionKey := SessionPrefix + "test-session"
		oauthStateKey := FBSessionPrefix + "test-oauth"

		// Store test data
		err := manager.redis.Set(ctx, stateKey, "state-data", time.Duration(StateTTL)*time.Second)
		require.NoError(t, err)
		err = manager.redis.Set(ctx, sessionKey, "session-data", time.Duration(StateTTL)*time.Second)
		require.NoError(t, err)
		err = manager.redis.Set(ctx, oauthStateKey, "oauth-data", time.Duration(StateTTL)*time.Second)
		require.NoError(t, err)

		// Atomically consume all three
		state, session, oauth, err := manager.AtomicConsumeOAuthStateAndMappings(ctx, stateKey, sessionKey, oauthStateKey)
		assert.NoError(t, err)
		assert.Equal(t, "state-data", state)
		assert.Equal(t, "session-data", session)
		assert.Equal(t, "oauth-data", oauth)

		// Verify all keys are deleted
		stateData, _ := manager.redis.Get(ctx, stateKey)
		assert.Empty(t, stateData)
		sessionData, _ := manager.redis.Get(ctx, sessionKey)
		assert.Empty(t, sessionData)
		oauthData, _ := manager.redis.Get(ctx, oauthStateKey)
		assert.Empty(t, oauthData)
	})

	t.Run("handles missing keys gracefully", func(t *testing.T) {
		stateKey := StatePrefix + "missing1"
		sessionKey := SessionPrefix + "missing2"
		oauthStateKey := FBSessionPrefix + "missing3"

		// Try to consume non-existent keys
		state, session, oauth, err := manager.AtomicConsumeOAuthStateAndMappings(ctx, stateKey, sessionKey, oauthStateKey)
		assert.NoError(t, err)
		assert.Empty(t, state)
		assert.Empty(t, session)
		assert.Empty(t, oauth)
	})

	t.Run("prevents TOCTOU race conditions", func(t *testing.T) {
		stateKey := StatePrefix + "race-test"
		sessionKey := SessionPrefix + "race-test"
		oauthStateKey := FBSessionPrefix + "race-test"

		// Store test data
		mr.Set(stateKey, "data")
		mr.Set(sessionKey, "data")
		mr.Set(oauthStateKey, "data")

		// Launch concurrent attempts to consume
		const goroutines = 20
		var wg sync.WaitGroup
		results := make(chan bool, goroutines)

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				state, session, oauth, err := manager.AtomicConsumeOAuthStateAndMappings(ctx, stateKey, sessionKey, oauthStateKey)
				if err == nil && state != "" && session != "" && oauth != "" {
					results <- true
				} else {
					results <- false
				}
			}()
		}

		wg.Wait()
		close(results)

		// SECURITY: Only ONE goroutine should successfully consume all three
		var successCount int
		for success := range results {
			if success {
				successCount++
			}
		}

		assert.Equal(t, 1, successCount, "Only one atomic consume should succeed - prevents TOCTOU")
	})
}

func TestConsumeOAuthStateMappings(t *testing.T) {
	manager, _ := setupTestManager(t)
	ctx := context.Background()

	t.Run("consumes OAuth state mappings successfully", func(t *testing.T) {
		firebaseState := "fb-state-123"

		// Store OAuth state mapping
		stateKey := SelectionPrefix + "oauth:state:" + firebaseState
		stateJSON := `{"oauth_state":"oauth-123"}`
		err := manager.redis.Set(ctx, stateKey, stateJSON, time.Duration(StateTTL)*time.Second)
		require.NoError(t, err)

		// Store session ID mapping
		sessionKey := SelectionPrefix + "oauth:fbsession:" + firebaseState
		sessionJSON := `{"session_id":"session-456"}`
		err = manager.redis.Set(ctx, sessionKey, sessionJSON, time.Duration(StateTTL)*time.Second)
		require.NoError(t, err)

		// Consume mappings
		oauthState, sessionID, err := manager.ConsumeOAuthStateMappings(ctx, firebaseState)
		assert.NoError(t, err)
		assert.Equal(t, "oauth-123", oauthState)
		assert.Equal(t, "session-456", sessionID)

		// Verify keys are deleted
		data, _ := manager.redis.Get(ctx, stateKey)
		assert.Empty(t, data)
		data, _ = manager.redis.Get(ctx, sessionKey)
		assert.Empty(t, data)
	})

	t.Run("fails when OAuth state mapping is missing", func(t *testing.T) {
		firebaseState := "fb-state-missing"

		// Only store session mapping, not OAuth state
		sessionKey := SelectionPrefix + "oauth:fbsession:" + firebaseState
		sessionJSON := `{"session_id":"session-789"}`
		err := manager.redis.Set(ctx, sessionKey, sessionJSON, time.Duration(StateTTL)*time.Second)
		require.NoError(t, err)

		// Should fail due to missing OAuth state
		oauthState, sessionID, err := manager.ConsumeOAuthStateMappings(ctx, firebaseState)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "incomplete")
		assert.Empty(t, oauthState)
		assert.Empty(t, sessionID)
	})

	t.Run("fails when session ID mapping is missing", func(t *testing.T) {
		firebaseState := "fb-state-no-session"

		// Only store OAuth state, not session
		stateKey := SelectionPrefix + "oauth:state:" + firebaseState
		stateJSON := `{"oauth_state":"oauth-999"}`
		err := manager.redis.Set(ctx, stateKey, stateJSON, time.Duration(StateTTL)*time.Second)
		require.NoError(t, err)

		// Should fail due to missing session
		oauthState, sessionID, err := manager.ConsumeOAuthStateMappings(ctx, firebaseState)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "incomplete")
		assert.Empty(t, oauthState)
		assert.Empty(t, sessionID)
	})

	t.Run("prevents race conditions on mapping consumption", func(t *testing.T) {
		firebaseState := "fb-state-race"

		// Store mappings
		stateKey := SelectionPrefix + "oauth:state:" + firebaseState
		stateJSON := `{"oauth_state":"oauth-race"}`
		err := manager.redis.Set(ctx, stateKey, stateJSON, time.Duration(StateTTL)*time.Second)
		require.NoError(t, err)

		sessionKey := SelectionPrefix + "oauth:fbsession:" + firebaseState
		sessionJSON := `{"session_id":"session-race"}`
		err = manager.redis.Set(ctx, sessionKey, sessionJSON, time.Duration(StateTTL)*time.Second)
		require.NoError(t, err)

		// Launch concurrent attempts
		const goroutines = 20
		var wg sync.WaitGroup
		results := make(chan bool, goroutines)

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				oauthState, sessionID, err := manager.ConsumeOAuthStateMappings(ctx, firebaseState)
				if err == nil && oauthState != "" && sessionID != "" {
					results <- true
				} else {
					results <- false
				}
			}()
		}

		wg.Wait()
		close(results)

		// SECURITY: Only ONE goroutine should succeed
		var successCount int
		for success := range results {
			if success {
				successCount++
			}
		}

		assert.Equal(t, 1, successCount, "Only one consume should succeed - prevents race")
	})

	t.Run("handles malformed JSON gracefully", func(t *testing.T) {
		firebaseState := "fb-state-malformed"

		// Store invalid JSON
		stateKey := SelectionPrefix + "oauth:state:" + firebaseState
		err := manager.redis.Set(ctx, stateKey, "invalid-json{{{", time.Duration(StateTTL)*time.Second)
		require.NoError(t, err)

		sessionKey := SelectionPrefix + "oauth:fbsession:" + firebaseState
		err = manager.redis.Set(ctx, sessionKey, `{"session_id":"valid"}`, time.Duration(StateTTL)*time.Second)
		require.NoError(t, err)

		// Should fail due to malformed JSON
		oauthState, sessionID, err := manager.ConsumeOAuthStateMappings(ctx, firebaseState)
		assert.Error(t, err)
		assert.Empty(t, oauthState)
		assert.Empty(t, sessionID)
	})
}

// ===== Error Handling and Edge Cases =====

func TestUpdateAccessTokenFirebaseTokens_EdgeCases(t *testing.T) {
	manager, _ := setupTestManager(t)
	ctx := context.Background()

	t.Run("fails gracefully for non-existent token", func(t *testing.T) {
		err := manager.UpdateAccessTokenFirebaseTokens(ctx, "non-existent", "new-token", time.Now().Unix())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("updates tokens with very long values", func(t *testing.T) {
		// Create token with short value
		token := NewAccessTokenData("at-long", "user", "short", "refresh",
			time.Now().Add(1*time.Hour).Unix(), "scope", 3600)
		err := manager.StoreAccessToken(ctx, token)
		require.NoError(t, err)

		// Update with very long token (simulate JWT)
		longToken := string(make([]byte, 2000))
		for i := range longToken {
			longToken = longToken[:i] + "a"
		}
		newExpiresAt := time.Now().Add(2 * time.Hour).Unix()

		err = manager.UpdateAccessTokenFirebaseTokens(ctx, "at-long", longToken, newExpiresAt)
		assert.NoError(t, err)

		// Verify update
		retrieved, err := manager.GetAccessTokenData(ctx, "at-long")
		assert.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Equal(t, longToken, retrieved.FirebaseIDToken)
	})

	t.Run("concurrent updates to same token", func(t *testing.T) {
		token := NewAccessTokenData("at-concurrent", "user", "initial", "refresh",
			time.Now().Add(1*time.Hour).Unix(), "scope", 3600)
		err := manager.StoreAccessToken(ctx, token)
		require.NoError(t, err)

		// Launch concurrent updates
		const goroutines = 10
		var wg sync.WaitGroup
		errors := make(chan error, goroutines)

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				newToken := fmt.Sprintf("token-%d", idx)
				err := manager.UpdateAccessTokenFirebaseTokens(ctx, "at-concurrent", newToken, time.Now().Unix())
				errors <- err
			}(i)
		}

		wg.Wait()
		close(errors)

		// At least some updates should succeed
		var successCount int
		for err := range errors {
			if err == nil {
				successCount++
			}
		}
		assert.Greater(t, successCount, 0, "Some updates should succeed")

		// Final token should be valid
		retrieved, err := manager.GetAccessTokenData(ctx, "at-concurrent")
		assert.NoError(t, err)
		assert.NotNil(t, retrieved)
	})
}

func TestRefreshTokenData_EdgeCases(t *testing.T) {
	manager, _ := setupTestManager(t)
	ctx := context.Background()

	t.Run("revoke non-existent refresh token succeeds", func(t *testing.T) {
		// Per OAuth 2.0 spec, revocation of non-existent token should succeed silently
		err := manager.RevokeRefreshToken(ctx, "non-existent")
		assert.NoError(t, err)
	})

	t.Run("get non-existent refresh token returns nil", func(t *testing.T) {
		retrieved, err := manager.GetRefreshTokenData(ctx, "non-existent")
		assert.NoError(t, err)
		assert.Nil(t, retrieved)
	})

	t.Run("handles refresh token with empty scope", func(t *testing.T) {
		token := NewRefreshTokenData("rt-empty-scope", "at", "user", "fb-refresh", "")
		err := manager.StoreRefreshToken(ctx, token)
		require.NoError(t, err)

		retrieved, err := manager.GetRefreshTokenData(ctx, "rt-empty-scope")
		assert.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Empty(t, retrieved.Scope)
	})
}

func TestClientRegistration_EdgeCases(t *testing.T) {
	manager, _ := setupTestManager(t)
	ctx := context.Background()

	t.Run("generates unique client IDs", func(t *testing.T) {
		ids := make(map[string]bool)
		for i := 0; i < 100; i++ {
			clientID, err := manager.GenerateClientID()
			require.NoError(t, err)
			assert.False(t, ids[clientID], "Duplicate client ID generated")
			assert.Contains(t, clientID, "mcp_")
			ids[clientID] = true
		}
	})

	t.Run("stores client with many redirect URIs", func(t *testing.T) {
		clientID, err := manager.GenerateClientID()
		require.NoError(t, err)

		// Create client with many URIs
		var redirectURIs []string
		for i := 0; i < 50; i++ {
			redirectURIs = append(redirectURIs, fmt.Sprintf("https://app%d.example.com/callback", i))
		}

		client := NewClientRegistration(clientID, "Multi-URI App", redirectURIs)
		err = manager.StoreClientRegistration(ctx, client)
		require.NoError(t, err)

		// Retrieve and verify
		retrieved, err := manager.GetClientRegistration(ctx, clientID)
		assert.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Len(t, retrieved.RedirectURIs, 50)
	})

	t.Run("handles client with empty name", func(t *testing.T) {
		clientID, err := manager.GenerateClientID()
		require.NoError(t, err)

		client := NewClientRegistration(clientID, "", []string{"https://app.com/cb"})
		err = manager.StoreClientRegistration(ctx, client)
		require.NoError(t, err)

		retrieved, err := manager.GetClientRegistration(ctx, clientID)
		assert.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Empty(t, retrieved.ClientName)
	})
}

// ===== Concurrent Stress Tests =====

func TestConcurrentTokenOperations(t *testing.T) {
	manager, _ := setupTestManager(t)
	ctx := context.Background()

	t.Run("concurrent access token operations", func(t *testing.T) {
		const goroutines = 50
		var wg sync.WaitGroup
		tokenIDs := make(chan string, goroutines)

		// Concurrent stores
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				tokenID := fmt.Sprintf("concurrent-at-%d", idx)
				token := NewAccessTokenData(tokenID, fmt.Sprintf("user-%d", idx), "id", "refresh",
					time.Now().Add(1*time.Hour).Unix(), "scope", 3600)
				err := manager.StoreAccessToken(ctx, token)
				if err == nil {
					tokenIDs <- tokenID
				}
			}(i)
		}

		wg.Wait()
		close(tokenIDs)

		// Verify all tokens were stored
		var storedCount int
		for tokenID := range tokenIDs {
			retrieved, err := manager.GetAccessTokenData(ctx, tokenID)
			if err == nil && retrieved != nil {
				storedCount++
			}
		}

		assert.Equal(t, goroutines, storedCount, "All concurrent stores should succeed")
	})

	t.Run("concurrent mixed operations", func(t *testing.T) {
		const goroutines = 30
		var wg sync.WaitGroup

		// Setup some initial tokens
		for i := 0; i < 10; i++ {
			tokenID := fmt.Sprintf("mixed-at-%d", i)
			token := NewAccessTokenData(tokenID, "user", "id", "refresh",
				time.Now().Add(1*time.Hour).Unix(), "scope", 3600)
			manager.StoreAccessToken(ctx, token)
		}

		// Mix of operations: store, get, update, revoke
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				switch idx % 4 {
				case 0: // Store
					tokenID := fmt.Sprintf("mixed-new-%d", idx)
					token := NewAccessTokenData(tokenID, "user", "id", "refresh",
						time.Now().Add(1*time.Hour).Unix(), "scope", 3600)
					manager.StoreAccessToken(ctx, token)
				case 1: // Get
					tokenID := fmt.Sprintf("mixed-at-%d", idx%10)
					manager.GetAccessTokenData(ctx, tokenID)
				case 2: // Update
					tokenID := fmt.Sprintf("mixed-at-%d", idx%10)
					manager.UpdateAccessTokenFirebaseTokens(ctx, tokenID, "new-token", time.Now().Unix())
				case 3: // Revoke
					tokenID := fmt.Sprintf("mixed-at-%d", idx%10)
					manager.RevokeAccessToken(ctx, tokenID)
				}
			}(i)
		}

		wg.Wait()
		// Test passes if no panics or deadlocks occur
	})
}

func TestSelectionSession_EdgeCases(t *testing.T) {
	manager, _ := setupTestManager(t)
	ctx := context.Background()

	t.Run("generates unique session IDs", func(t *testing.T) {
		ids := make(map[string]bool)
		for i := 0; i < 100; i++ {
			sessionID, err := manager.GenerateSelectionSessionID()
			require.NoError(t, err)
			assert.False(t, ids[sessionID], "Duplicate session ID generated")
			ids[sessionID] = true
		}
	})

	t.Run("handles empty params map", func(t *testing.T) {
		sessionID, err := manager.GenerateSelectionSessionID()
		require.NoError(t, err)

		params := map[string]string{}
		err = manager.StoreSelectionSession(ctx, sessionID, params)
		require.NoError(t, err)

		consumed, err := manager.ConsumeSelectionSession(ctx, sessionID)
		assert.NoError(t, err)
		assert.NotNil(t, consumed)
		assert.Empty(t, consumed)
	})

	t.Run("handles very large params map", func(t *testing.T) {
		sessionID, err := manager.GenerateSelectionSessionID()
		require.NoError(t, err)

		// Create large params map
		params := make(map[string]string)
		for i := 0; i < 100; i++ {
			params[fmt.Sprintf("param_%d", i)] = fmt.Sprintf("value_%d", i)
		}

		err = manager.StoreSelectionSession(ctx, sessionID, params)
		require.NoError(t, err)

		consumed, err := manager.ConsumeSelectionSession(ctx, sessionID)
		assert.NoError(t, err)
		require.NotNil(t, consumed)
		assert.Len(t, consumed, 100)
	})

	t.Run("consume non-existent session returns nil", func(t *testing.T) {
		consumed, err := manager.ConsumeSelectionSession(ctx, "non-existent")
		assert.NoError(t, err)
		assert.Nil(t, consumed)
	})
}

// ===== MFA Session Edge Cases =====

func TestMFASession_AdditionalEdgeCases(t *testing.T) {
	manager, _ := setupTestManager(t)
	ctx := context.Background()

	t.Run("generates unique MFA session IDs", func(t *testing.T) {
		ids := make(map[string]bool)
		for i := 0; i < 100; i++ {
			sessionID, err := manager.GenerateMFASessionID()
			require.NoError(t, err)
			assert.False(t, ids[sessionID], "Duplicate MFA session ID")
			ids[sessionID] = true
		}
	})

	t.Run("get non-existent MFA session returns nil", func(t *testing.T) {
		retrieved, err := manager.GetMFASession(ctx, "non-existent")
		assert.NoError(t, err)
		assert.Nil(t, retrieved)
	})

	t.Run("consume non-existent MFA session returns nil", func(t *testing.T) {
		consumed, err := manager.ConsumeMFASession(ctx, "non-existent")
		assert.NoError(t, err)
		assert.Nil(t, consumed)
	})

	t.Run("get attempt count for non-existent session returns 0", func(t *testing.T) {
		count, err := manager.GetMFAAttemptCount(ctx, "non-existent")
		assert.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("MFA session with nil pending token", func(t *testing.T) {
		sessionID, err := manager.GenerateMFASessionID()
		require.NoError(t, err)

		session := NewMFASession("cred", "enroll", "state", "User", "local", "email", nil)
		err = manager.StoreMFASession(ctx, sessionID, session)
		require.NoError(t, err)

		retrieved, err := manager.GetMFASession(ctx, sessionID)
		assert.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Nil(t, retrieved.PendingToken)
	})

	t.Run("MFA session with pending token", func(t *testing.T) {
		sessionID, err := manager.GenerateMFASessionID()
		require.NoError(t, err)

		pendingToken := "pending-token-value"
		session := NewMFASession("cred", "enroll", "state", "User", "local", "email", &pendingToken)
		err = manager.StoreMFASession(ctx, sessionID, session)
		require.NoError(t, err)

		retrieved, err := manager.GetMFASession(ctx, sessionID)
		assert.NoError(t, err)
		require.NotNil(t, retrieved)
		require.NotNil(t, retrieved.PendingToken)
		assert.Equal(t, pendingToken, *retrieved.PendingToken)
	})
}

// ===== Token Generation Stress Tests =====

func TestTokenGeneration_StressTest(t *testing.T) {
	manager, _ := setupTestManager(t)

	t.Run("generates tokens under heavy concurrent load", func(t *testing.T) {
		const goroutines = 100
		var wg sync.WaitGroup
		tokens := make(chan string, goroutines*4) // 4 types

		for i := 0; i < goroutines; i++ {
			// State tokens
			wg.Add(1)
			go func() {
				defer wg.Done()
				if token, err := manager.GenerateState(); err == nil {
					tokens <- token
				}
			}()

			// Authorization codes
			wg.Add(1)
			go func() {
				defer wg.Done()
				if code, err := manager.GenerateAuthorizationCode(); err == nil {
					tokens <- code
				}
			}()

			// Access tokens
			wg.Add(1)
			go func() {
				defer wg.Done()
				if token, err := manager.GenerateAccessToken(); err == nil {
					tokens <- token
				}
			}()

			// Refresh tokens
			wg.Add(1)
			go func() {
				defer wg.Done()
				if token, err := manager.GenerateRefreshToken(); err == nil {
					tokens <- token
				}
			}()
		}

		wg.Wait()
		close(tokens)

		// Verify all tokens are unique
		seen := make(map[string]bool)
		var count int
		for token := range tokens {
			assert.False(t, seen[token], "Duplicate token under concurrent load")
			seen[token] = true
			count++
		}

		assert.Equal(t, goroutines*4, count, "All tokens should be generated")
	})
}
