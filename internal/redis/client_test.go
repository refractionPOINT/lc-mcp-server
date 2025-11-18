package redis

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create test logger
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Helper to create test Redis client with miniredis
func setupTestRedis(t *testing.T) (*Client, *miniredis.Miniredis) {
	t.Helper()

	// Start miniredis
	mr := miniredis.RunT(t)

	// Create client
	cfg := &Config{
		URL: "redis://" + mr.Addr(),
	}

	client, err := New(cfg, testLogger())
	require.NoError(t, err)
	require.NotNil(t, client)

	return client, mr
}

// TestNew tests Redis client creation
func TestNew(t *testing.T) {
	t.Run("connects successfully", func(t *testing.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		cfg := &Config{
			URL: "redis://" + mr.Addr(),
		}

		client, err := New(cfg, testLogger())
		assert.NoError(t, err)
		assert.NotNil(t, client)

		// Test ping
		err = client.Ping(context.Background())
		assert.NoError(t, err)
	})

	t.Run("invalid URL rejected", func(t *testing.T) {
		cfg := &Config{
			URL: "invalid://url",
		}

		client, err := New(cfg, testLogger())
		assert.Error(t, err)
		assert.Nil(t, client)
	})

	t.Run("connection failure detected", func(t *testing.T) {
		cfg := &Config{
			URL: "redis://localhost:65535", // Invalid port
		}

		client, err := New(cfg, testLogger())
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "failed to connect")
	})
}

// TestGetSet tests basic get/set operations
func TestGetSet(t *testing.T) {
	client, _ := setupTestRedis(t)
	ctx := context.Background()

	t.Run("set and get value", func(t *testing.T) {
		err := client.Set(ctx, "test-key", "test-value", 0)
		require.NoError(t, err)

		val, err := client.Get(ctx, "test-key")
		assert.NoError(t, err)
		assert.Equal(t, "test-value", val)
	})

	t.Run("get non-existent key returns empty", func(t *testing.T) {
		val, err := client.Get(ctx, "non-existent")
		assert.NoError(t, err)
		assert.Empty(t, val)
	})

	t.Run("overwrite existing key", func(t *testing.T) {
		err := client.Set(ctx, "key", "value1", 0)
		require.NoError(t, err)

		err = client.Set(ctx, "key", "value2", 0)
		require.NoError(t, err)

		val, err := client.Get(ctx, "key")
		assert.NoError(t, err)
		assert.Equal(t, "value2", val)
	})
}

// TestSetEX tests set with expiration
func TestSetEX(t *testing.T) {
	client, mr := setupTestRedis(t)
	ctx := context.Background()

	t.Run("set with expiration", func(t *testing.T) {
		err := client.SetEX(ctx, "temp-key", "temp-value", 1)
		require.NoError(t, err)

		// Verify value exists
		val, err := client.Get(ctx, "temp-key")
		assert.NoError(t, err)
		assert.Equal(t, "temp-value", val)

		// Fast forward time
		mr.FastForward(2 * time.Second)

		// Verify value expired
		val, err = client.Get(ctx, "temp-key")
		assert.NoError(t, err)
		assert.Empty(t, val)
	})
}

// TestDelete tests key deletion
func TestDelete(t *testing.T) {
	client, _ := setupTestRedis(t)
	ctx := context.Background()

	t.Run("delete existing key", func(t *testing.T) {
		err := client.Set(ctx, "key-to-delete", "value", 0)
		require.NoError(t, err)

		err = client.Delete(ctx, "key-to-delete")
		assert.NoError(t, err)

		val, err := client.Get(ctx, "key-to-delete")
		assert.NoError(t, err)
		assert.Empty(t, val)
	})

	t.Run("delete non-existent key succeeds", func(t *testing.T) {
		err := client.Delete(ctx, "non-existent")
		assert.NoError(t, err)
	})

	t.Run("delete multiple keys", func(t *testing.T) {
		err := client.Set(ctx, "key1", "val1", 0)
		require.NoError(t, err)
		err = client.Set(ctx, "key2", "val2", 0)
		require.NoError(t, err)

		err = client.Delete(ctx, "key1", "key2")
		assert.NoError(t, err)

		val, _ := client.Get(ctx, "key1")
		assert.Empty(t, val)
		val, _ = client.Get(ctx, "key2")
		assert.Empty(t, val)
	})

	t.Run("Del is alias for Delete", func(t *testing.T) {
		err := client.Set(ctx, "key", "value", 0)
		require.NoError(t, err)

		err = client.Del(ctx, "key")
		assert.NoError(t, err)

		val, err := client.Get(ctx, "key")
		assert.NoError(t, err)
		assert.Empty(t, val)
	})
}

// TestIncr tests atomic increment
func TestIncr(t *testing.T) {
	client, _ := setupTestRedis(t)
	ctx := context.Background()

	t.Run("increment from zero", func(t *testing.T) {
		val, err := client.Incr(ctx, "counter")
		assert.NoError(t, err)
		assert.Equal(t, int64(1), val)
	})

	t.Run("multiple increments", func(t *testing.T) {
		key := "counter2"
		for i := 1; i <= 10; i++ {
			val, err := client.Incr(ctx, key)
			assert.NoError(t, err)
			assert.Equal(t, int64(i), val)
		}
	})
}

// TestExpire tests TTL and expiration
func TestExpire(t *testing.T) {
	client, mr := setupTestRedis(t)
	ctx := context.Background()

	t.Run("set expiration on existing key", func(t *testing.T) {
		err := client.Set(ctx, "key", "value", 0)
		require.NoError(t, err)

		err = client.Expire(ctx, "key", 1*time.Second)
		assert.NoError(t, err)

		// Check TTL
		ttl, err := client.TTL(ctx, "key")
		assert.NoError(t, err)
		assert.Greater(t, ttl, time.Duration(0))

		// Fast forward and verify expiration
		mr.FastForward(2 * time.Second)

		val, err := client.Get(ctx, "key")
		assert.NoError(t, err)
		assert.Empty(t, val)
	})
}

// TestExists tests key existence check
func TestExists(t *testing.T) {
	client, _ := setupTestRedis(t)
	ctx := context.Background()

	t.Run("check existing key", func(t *testing.T) {
		err := client.Set(ctx, "exists-key", "value", 0)
		require.NoError(t, err)

		count, err := client.Exists(ctx, "exists-key")
		assert.NoError(t, err)
		assert.Equal(t, int64(1), count)
	})

	t.Run("check non-existent key", func(t *testing.T) {
		count, err := client.Exists(ctx, "non-existent")
		assert.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})

	t.Run("check multiple keys", func(t *testing.T) {
		err := client.Set(ctx, "key1", "val1", 0)
		require.NoError(t, err)
		err = client.Set(ctx, "key2", "val2", 0)
		require.NoError(t, err)

		count, err := client.Exists(ctx, "key1", "key2", "key3")
		assert.NoError(t, err)
		assert.Equal(t, int64(2), count) // Only 2 exist
	})
}

// TestAtomicGetAndDelete tests atomic get-and-delete operation
// SECURITY CRITICAL: This prevents TOCTOU race conditions in OAuth
func TestAtomicGetAndDelete(t *testing.T) {
	client, _ := setupTestRedis(t)
	ctx := context.Background()

	t.Run("atomic get and delete existing key", func(t *testing.T) {
		err := client.Set(ctx, "oauth-code", "secret-code-123", 0)
		require.NoError(t, err)

		// Atomically get and delete
		val, err := client.AtomicGetAndDelete(ctx, "oauth-code")
		assert.NoError(t, err)
		assert.Equal(t, "secret-code-123", val)

		// Verify key is deleted
		val2, err := client.Get(ctx, "oauth-code")
		assert.NoError(t, err)
		assert.Empty(t, val2)
	})

	t.Run("atomic get and delete non-existent key", func(t *testing.T) {
		val, err := client.AtomicGetAndDelete(ctx, "non-existent")
		assert.NoError(t, err)
		assert.Empty(t, val)
	})

	t.Run("second call returns empty (single-use)", func(t *testing.T) {
		err := client.Set(ctx, "one-time-token", "token-value", 0)
		require.NoError(t, err)

		// First call succeeds
		val1, err := client.AtomicGetAndDelete(ctx, "one-time-token")
		assert.NoError(t, err)
		assert.Equal(t, "token-value", val1)

		// Second call returns empty
		val2, err := client.AtomicGetAndDelete(ctx, "one-time-token")
		assert.NoError(t, err)
		assert.Empty(t, val2)
	})
}

// TestAtomicGetAndDelete_RaceCondition tests atomicity under concurrent access
// SECURITY CRITICAL: Prevents authorization code reuse attack
func TestAtomicGetAndDelete_RaceCondition(t *testing.T) {
	client, _ := setupTestRedis(t)
	ctx := context.Background()

	// Set up a single-use code
	err := client.Set(ctx, "auth-code", "authorization-code-xyz", 0)
	require.NoError(t, err)

	// Launch multiple concurrent attempts to consume the code
	const goroutines = 100
	var wg sync.WaitGroup
	results := make(chan string, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			val, err := client.AtomicGetAndDelete(ctx, "auth-code")
			if err == nil {
				results <- val
			}
		}()
	}

	wg.Wait()
	close(results)

	// Collect results
	var successCount int
	var successValue string
	for val := range results {
		if val != "" {
			successCount++
			successValue = val
		}
	}

	// SECURITY: Only ONE goroutine should successfully get the value
	assert.Equal(t, 1, successCount, "Only one goroutine should get the code")
	assert.Equal(t, "authorization-code-xyz", successValue)
}

// TestAtomicMultiGetAndDelete tests multi-key atomic operation
func TestAtomicMultiGetAndDelete(t *testing.T) {
	client, _ := setupTestRedis(t)
	ctx := context.Background()

	t.Run("atomic multi-get and delete", func(t *testing.T) {
		// Set up multiple keys
		err := client.Set(ctx, "key1", "value1", 0)
		require.NoError(t, err)
		err = client.Set(ctx, "key2", "value2", 0)
		require.NoError(t, err)
		err = client.Set(ctx, "key3", "value3", 0)
		require.NoError(t, err)

		// Atomically get and delete all keys
		keys := []string{"key1", "key2", "key3"}
		values, err := client.AtomicMultiGetAndDelete(ctx, keys)
		assert.NoError(t, err)
		require.Len(t, values, 3)
		assert.Equal(t, "value1", values[0])
		assert.Equal(t, "value2", values[1])
		assert.Equal(t, "value3", values[2])

		// Verify all keys are deleted
		for _, key := range keys {
			val, err := client.Get(ctx, key)
			assert.NoError(t, err)
			assert.Empty(t, val)
		}
	})

	t.Run("mixed existent and non-existent keys", func(t *testing.T) {
		err := client.Set(ctx, "exists", "value", 0)
		require.NoError(t, err)

		keys := []string{"exists", "not-exists"}
		values, err := client.AtomicMultiGetAndDelete(ctx, keys)
		assert.NoError(t, err)
		require.Len(t, values, 2)
		assert.Equal(t, "value", values[0])
		assert.Empty(t, values[1])
	})

	t.Run("empty key list", func(t *testing.T) {
		values, err := client.AtomicMultiGetAndDelete(ctx, []string{})
		assert.NoError(t, err)
		assert.Empty(t, values)
	})
}

// TestAtomicMultiGetAndDelete_RaceCondition tests atomicity of multi-key operation
// SECURITY: Ensures all related OAuth state is consumed atomically
func TestAtomicMultiGetAndDelete_RaceCondition(t *testing.T) {
	client, _ := setupTestRedis(t)
	ctx := context.Background()

	// Set up OAuth state + session mapping
	err := client.Set(ctx, "oauth:state:xyz", "state-data", 0)
	require.NoError(t, err)
	err = client.Set(ctx, "oauth:session:xyz", "session-data", 0)
	require.NoError(t, err)

	// Launch concurrent attempts
	const goroutines = 50
	var wg sync.WaitGroup
	results := make(chan []string, goroutines)

	keys := []string{"oauth:state:xyz", "oauth:session:xyz"}

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			values, err := client.AtomicMultiGetAndDelete(ctx, keys)
			if err == nil {
				results <- values
			}
		}()
	}

	wg.Wait()
	close(results)

	// Count successful retrievals
	var successCount int
	for values := range results {
		if values[0] != "" || values[1] != "" {
			successCount++
			// If one is retrieved, both should be (atomic)
			assert.NotEmpty(t, values[0], "State should be retrieved")
			assert.NotEmpty(t, values[1], "Session should be retrieved")
		}
	}

	// SECURITY: Only ONE goroutine should successfully get the values
	assert.Equal(t, 1, successCount, "Only one goroutine should get the state")
}

// TestConcurrentOperations tests general thread safety
func TestConcurrentOperations(t *testing.T) {
	client, _ := setupTestRedis(t)
	ctx := context.Background()

	const goroutines = 50
	const iterations = 10

	var wg sync.WaitGroup
	errors := make(chan error, goroutines*iterations)

	// Concurrent writes
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				key := fmt.Sprintf("concurrent-key-%d", id)
				value := fmt.Sprintf("value-%d-%d", id, j)

				if err := client.Set(ctx, key, value, 0); err != nil {
					errors <- err
				}

				// Verify read
				if val, err := client.Get(ctx, key); err != nil {
					errors <- err
				} else if val != value {
					errors <- fmt.Errorf("value mismatch: expected %s, got %s", value, val)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	var errorList []error
	for err := range errors {
		errorList = append(errorList, err)
	}
	assert.Empty(t, errorList, "No errors should occur during concurrent operations")
}

// TestPing tests Redis connection health check
func TestPing(t *testing.T) {
	client, _ := setupTestRedis(t)
	ctx := context.Background()

	err := client.Ping(ctx)
	assert.NoError(t, err)
}

// TestHealth tests health check functionality
func TestHealth(t *testing.T) {
	client, _ := setupTestRedis(t)
	ctx := context.Background()

	health, err := client.Health(ctx)
	// miniredis doesn't support INFO stats, so we may get an error
	// but we still want to test that the function doesn't panic
	if err == nil {
		assert.NotNil(t, health)
		assert.Equal(t, true, health["healthy"])
	} else {
		// Expected with miniredis
		assert.Contains(t, err.Error(), "not supported")
	}
}

// TestClose tests client cleanup
func TestClose(t *testing.T) {
	client, mr := setupTestRedis(t)

	err := client.Close()
	assert.NoError(t, err)

	mr.Close()
}

// TestContextCancellation tests operation cancellation
func TestContextCancellation(t *testing.T) {
	client, _ := setupTestRedis(t)

	t.Run("cancelled context returns error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := client.Set(ctx, "key", "value", 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("timeout context returns error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()

		time.Sleep(10 * time.Millisecond) // Ensure timeout

		err := client.Set(ctx, "key", "value", 0)
		assert.Error(t, err)
	})
}

// TestLuaScriptsLoaded verifies Lua scripts are loaded
func TestLuaScriptsLoaded(t *testing.T) {
	client, _ := setupTestRedis(t)

	assert.NotNil(t, client.atomicGetAndDelete)
	assert.NotNil(t, client.atomicMultiGetAndDelete)
}

// TestOAuthWorkflow tests a realistic OAuth flow
func TestOAuthWorkflow(t *testing.T) {
	client, mr := setupTestRedis(t)
	ctx := context.Background()

	// 1. Store OAuth state (CSRF protection)
	stateToken := "state-abc123"
	err := client.SetEX(ctx, "oauth:state:"+stateToken, `{"redirect_uri":"https://app.com/callback"}`, 600)
	require.NoError(t, err)

	// 2. Store authorization code (short-lived)
	authCode := "code-xyz789"
	err = client.SetEX(ctx, "oauth:code:"+authCode, `{"user_id":"user123","state":"`+stateToken+`"}`, 300)
	require.NoError(t, err)

	// 3. Exchange authorization code (single-use)
	codeData, err := client.AtomicGetAndDelete(ctx, "oauth:code:"+authCode)
	assert.NoError(t, err)
	assert.Contains(t, codeData, "user123")

	// 4. Verify code cannot be reused
	codeData2, err := client.AtomicGetAndDelete(ctx, "oauth:code:"+authCode)
	assert.NoError(t, err)
	assert.Empty(t, codeData2)

	// 5. Consume state token
	stateData, err := client.AtomicGetAndDelete(ctx, "oauth:state:"+stateToken)
	assert.NoError(t, err)
	assert.Contains(t, stateData, "redirect_uri")

	// 6. Store access token with expiration
	accessToken := "at_1234567890"
	err = client.SetEX(ctx, "oauth:token:"+accessToken, `{"user_id":"user123"}`, 3600)
	require.NoError(t, err)

	// 7. Verify token exists
	count, err := client.Exists(ctx, "oauth:token:"+accessToken)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// 8. Fast forward time - verify token expires
	mr.FastForward(3601 * time.Second)
	tokenData, err := client.Get(ctx, "oauth:token:"+accessToken)
	assert.NoError(t, err)
	assert.Empty(t, tokenData)
}
