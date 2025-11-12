package ratelimit

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/refractionpoint/lc-mcp-go/internal/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create test logger
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Helper to setup test limiter with miniredis
func setupTestLimiter(t *testing.T) (*Limiter, *miniredis.Miniredis) {
	t.Helper()

	// Setup miniredis
	mr := miniredis.RunT(t)

	// Setup Redis client
	redisClient, err := redis.New(&redis.Config{
		URL: "redis://" + mr.Addr(),
	}, testLogger())
	require.NoError(t, err)

	// Create limiter
	limiter := NewLimiter(redisClient, testLogger())
	require.NotNil(t, limiter)

	return limiter, mr
}

func TestNewLimiter(t *testing.T) {
	t.Run("creates new limiter successfully", func(t *testing.T) {
		limiter, _ := setupTestLimiter(t)
		assert.NotNil(t, limiter)
		assert.NotNil(t, limiter.redis)
		assert.NotNil(t, limiter.logger)
	})
}

func TestAllow_BasicRateLimiting(t *testing.T) {
	limiter, _ := setupTestLimiter(t)
	ctx := context.Background()

	cfg := Config{
		MaxRequests: 3,
		Window:      time.Minute,
	}

	t.Run("allows requests under limit", func(t *testing.T) {
		key := "test-user-1"

		// First request - should be allowed
		allowed, err := limiter.Allow(ctx, key, cfg)
		assert.NoError(t, err)
		assert.True(t, allowed, "First request should be allowed")

		// Second request - should be allowed
		allowed, err = limiter.Allow(ctx, key, cfg)
		assert.NoError(t, err)
		assert.True(t, allowed, "Second request should be allowed")

		// Third request - should be allowed (at limit)
		allowed, err = limiter.Allow(ctx, key, cfg)
		assert.NoError(t, err)
		assert.True(t, allowed, "Third request should be allowed")
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		key := "test-user-2"

		// Make 3 requests (at limit)
		for i := 0; i < 3; i++ {
			allowed, err := limiter.Allow(ctx, key, cfg)
			assert.NoError(t, err)
			assert.True(t, allowed)
		}

		// Fourth request - should be blocked
		allowed, err := limiter.Allow(ctx, key, cfg)
		assert.NoError(t, err)
		assert.False(t, allowed, "Request over limit should be blocked")

		// Fifth request - should still be blocked
		allowed, err = limiter.Allow(ctx, key, cfg)
		assert.NoError(t, err)
		assert.False(t, allowed, "Request over limit should be blocked")
	})

	t.Run("different keys have separate limits", func(t *testing.T) {
		key1 := "test-user-3"
		key2 := "test-user-4"

		// Exhaust limit for key1
		for i := 0; i < 3; i++ {
			allowed, err := limiter.Allow(ctx, key1, cfg)
			assert.NoError(t, err)
			assert.True(t, allowed)
		}

		// key1 should be blocked
		allowed, err := limiter.Allow(ctx, key1, cfg)
		assert.NoError(t, err)
		assert.False(t, allowed)

		// key2 should still be allowed
		allowed, err = limiter.Allow(ctx, key2, cfg)
		assert.NoError(t, err)
		assert.True(t, allowed, "Different key should have separate limit")
	})
}

func TestAllow_WindowExpiration(t *testing.T) {
	limiter, mr := setupTestLimiter(t)
	ctx := context.Background()

	cfg := Config{
		MaxRequests: 2,
		Window:      5 * time.Second,
	}

	t.Run("limit resets after window expires", func(t *testing.T) {
		key := "test-user-expiry"

		// Make 2 requests (at limit)
		for i := 0; i < 2; i++ {
			allowed, err := limiter.Allow(ctx, key, cfg)
			assert.NoError(t, err)
			assert.True(t, allowed)
		}

		// Third request should be blocked
		allowed, err := limiter.Allow(ctx, key, cfg)
		assert.NoError(t, err)
		assert.False(t, allowed)

		// Fast forward past the window
		mr.FastForward(6 * time.Second)

		// Should be allowed again after window expiration
		allowed, err = limiter.Allow(ctx, key, cfg)
		assert.NoError(t, err)
		assert.True(t, allowed, "Requests should be allowed after window expires")
	})
}

func TestAllow_ConcurrentRequests(t *testing.T) {
	limiter, _ := setupTestLimiter(t)
	ctx := context.Background()

	cfg := Config{
		MaxRequests: 10,
		Window:      time.Minute,
	}

	t.Run("handles concurrent requests correctly", func(t *testing.T) {
		key := "test-concurrent"
		const goroutines = 20

		var wg sync.WaitGroup
		allowedCount := make(chan bool, goroutines)

		// Launch concurrent requests
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				allowed, err := limiter.Allow(ctx, key, cfg)
				assert.NoError(t, err)
				allowedCount <- allowed
			}()
		}

		wg.Wait()
		close(allowedCount)

		// Count how many were allowed
		var allowed, blocked int
		for result := range allowedCount {
			if result {
				allowed++
			} else {
				blocked++
			}
		}

		// Should allow exactly MaxRequests
		assert.Equal(t, cfg.MaxRequests, allowed, "Should allow exactly MaxRequests")
		assert.Equal(t, goroutines-cfg.MaxRequests, blocked, "Should block requests over limit")
	})
}

func TestAllow_FailOpen(t *testing.T) {
	limiter, mr := setupTestLimiter(t)
	ctx := context.Background()

	cfg := Config{
		MaxRequests: 1,
		Window:      time.Minute,
	}

	t.Run("fails open when Redis is unavailable", func(t *testing.T) {
		key := "test-fail-open"

		// Close miniredis to simulate Redis failure
		mr.Close()

		// Request should be allowed despite Redis being down (fail open)
		allowed, err := limiter.Allow(ctx, key, cfg)
		assert.Error(t, err, "Should return error when Redis is unavailable")
		assert.True(t, allowed, "CRITICAL: Should fail open and allow request when Redis is down")

		// Multiple requests should all be allowed (no rate limiting when Redis is down)
		for i := 0; i < 5; i++ {
			allowed, err := limiter.Allow(ctx, key, cfg)
			assert.Error(t, err)
			assert.True(t, allowed, "Should continue to fail open")
		}
	})
}

// Reset tests - now fixed to use SCAN+DEL pattern via DeleteByPattern
func TestReset(t *testing.T) {

	limiter, _ := setupTestLimiter(t)
	ctx := context.Background()

	cfg := Config{
		MaxRequests: 2,
		Window:      time.Minute,
	}

	t.Run("reset clears rate limit for key", func(t *testing.T) {
		key := "test-reset"

		// Exhaust limit
		for i := 0; i < 2; i++ {
			allowed, err := limiter.Allow(ctx, key, cfg)
			assert.NoError(t, err)
			assert.True(t, allowed)
		}

		// Should be blocked
		allowed, err := limiter.Allow(ctx, key, cfg)
		assert.NoError(t, err)
		assert.False(t, allowed)

		// Reset the limit
		err = limiter.Reset(ctx, key)
		assert.NoError(t, err)

		// Should be allowed again after reset
		allowed, err = limiter.Allow(ctx, key, cfg)
		assert.NoError(t, err)
		assert.True(t, allowed, "Requests should be allowed after reset")
	})

	t.Run("reset only affects specified key", func(t *testing.T) {
		key1 := "test-reset-1"
		key2 := "test-reset-2"

		// Exhaust limits for both keys
		for i := 0; i < 2; i++ {
			limiter.Allow(ctx, key1, cfg)
			limiter.Allow(ctx, key2, cfg)
		}

		// Both should be blocked
		allowed1, _ := limiter.Allow(ctx, key1, cfg)
		allowed2, _ := limiter.Allow(ctx, key2, cfg)
		assert.False(t, allowed1)
		assert.False(t, allowed2)

		// Reset only key1
		err := limiter.Reset(ctx, key1)
		assert.NoError(t, err)

		// key1 should be allowed, key2 still blocked
		allowed1, err = limiter.Allow(ctx, key1, cfg)
		assert.NoError(t, err)
		assert.True(t, allowed1, "Reset key should be allowed")

		allowed2, err = limiter.Allow(ctx, key2, cfg)
		assert.NoError(t, err)
		assert.False(t, allowed2, "Non-reset key should still be blocked")
	})
}

func TestDefaultConfigs(t *testing.T) {
	t.Run("default configs are defined", func(t *testing.T) {
		assert.NotEmpty(t, DefaultConfigs)

		// Verify critical OAuth endpoints have configs
		assert.Contains(t, DefaultConfigs, "oauth_authorize")
		assert.Contains(t, DefaultConfigs, "oauth_token")
		assert.Contains(t, DefaultConfigs, "oauth_callback")
		assert.Contains(t, DefaultConfigs, "mcp_request")
		assert.Contains(t, DefaultConfigs, "default")
	})

	t.Run("default configs have reasonable values", func(t *testing.T) {
		for name, cfg := range DefaultConfigs {
			assert.Greater(t, cfg.MaxRequests, 0, "Config %s should have positive MaxRequests", name)
			assert.Greater(t, cfg.Window, time.Duration(0), "Config %s should have positive Window", name)
		}
	})

	t.Run("OAuth endpoints have appropriate limits", func(t *testing.T) {
		// OAuth endpoints should have lower limits than MCP requests
		oauthTokenCfg := DefaultConfigs["oauth_token"]
		mcpCfg := DefaultConfigs["mcp_request"]

		assert.Less(t, oauthTokenCfg.MaxRequests, mcpCfg.MaxRequests,
			"OAuth token endpoint should have stricter limits than MCP requests")
	})
}

func TestAllow_EdgeCases(t *testing.T) {
	limiter, _ := setupTestLimiter(t)
	ctx := context.Background()

	t.Run("handles zero max requests", func(t *testing.T) {
		cfg := Config{
			MaxRequests: 0,
			Window:      time.Minute,
		}

		allowed, err := limiter.Allow(ctx, "test-zero", cfg)
		assert.NoError(t, err)
		assert.False(t, allowed, "Should block all requests when MaxRequests is 0")
	})

	t.Run("handles very short windows", func(t *testing.T) {
		cfg := Config{
			MaxRequests: 1,
			Window:      2 * time.Second, // Must be >= 1 second to avoid divide by zero
		}

		// This tests the bucket key generation works with short windows
		allowed, err := limiter.Allow(ctx, "test-short-window", cfg)
		assert.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("rejects sub-second windows", func(t *testing.T) {
		cfg := Config{
			MaxRequests: 10,
			Window:      500 * time.Millisecond, // Sub-second window
		}

		// Should return error for invalid window
		allowed, err := limiter.Allow(ctx, "test-subsecond", cfg)
		assert.Error(t, err, "Should error with sub-second window")
		assert.Contains(t, err.Error(), "must be >= 1 second")
		// Should still allow request (fail open)
		assert.True(t, allowed, "Should fail open even with invalid config")
	})

	t.Run("handles empty key", func(t *testing.T) {
		cfg := Config{
			MaxRequests: 1,
			Window:      time.Minute,
		}

		// Empty key should still work (will use "ratelimit::timestamp" as Redis key)
		allowed, err := limiter.Allow(ctx, "", cfg)
		assert.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("handles very large limits", func(t *testing.T) {
		cfg := Config{
			MaxRequests: 1_000_000,
			Window:      time.Hour,
		}

		allowed, err := limiter.Allow(ctx, "test-large", cfg)
		assert.NoError(t, err)
		assert.True(t, allowed)
	})
}

// Benchmark rate limiting performance
func BenchmarkAllow(b *testing.B) {
	// Setup
	mr := miniredis.RunT(&testing.T{})
	defer mr.Close()

	redisClient, _ := redis.New(&redis.Config{
		URL: "redis://" + mr.Addr(),
	}, testLogger())

	limiter := NewLimiter(redisClient, testLogger())
	ctx := context.Background()
	cfg := Config{
		MaxRequests: 1000,
		Window:      time.Minute,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.Allow(ctx, "bench-key", cfg)
	}
}

// Benchmark concurrent rate limiting
func BenchmarkAllowConcurrent(b *testing.B) {
	mr := miniredis.RunT(&testing.T{})
	defer mr.Close()

	redisClient, _ := redis.New(&redis.Config{
		URL: "redis://" + mr.Addr(),
	}, testLogger())

	limiter := NewLimiter(redisClient, testLogger())
	ctx := context.Background()
	cfg := Config{
		MaxRequests: 1000,
		Window:      time.Minute,
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			limiter.Allow(ctx, "bench-key-concurrent", cfg)
		}
	})
}
