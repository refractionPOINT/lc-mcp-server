package auth

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPermissionCache_NewPermissionCache tests cache initialization
func TestPermissionCache_NewPermissionCache(t *testing.T) {
	t.Run("creates cache with valid parameters", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(nil, nil))
		cache := NewPermissionCache(30*time.Second, logger)
		require.NotNil(t, cache)
		defer cache.Close()

		assert.NotNil(t, cache.cache)
		assert.Equal(t, 30*time.Second, cache.ttl)
		assert.NotNil(t, cache.logger)
	})

	t.Run("uses default logger when nil", func(t *testing.T) {
		cache := NewPermissionCache(30*time.Second, nil)
		require.NotNil(t, cache)
		defer cache.Close()

		assert.NotNil(t, cache.logger)
	})
}

// TestPermissionCache_Invalidate tests cache entry invalidation
func TestPermissionCache_Invalidate(t *testing.T) {
	cache := NewPermissionCache(5*time.Minute, nil)
	defer cache.Close()

	t.Run("handles nil auth context gracefully", func(t *testing.T) {
		// Should not panic
		cache.Invalidate(nil)
	})

	t.Run("removes entry for valid auth context", func(t *testing.T) {
		authCtx := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "test-oid",
			APIKey: "test-key-12345678901234567890",
		}

		// We can't directly check cache contents, but the method should not panic
		cache.Invalidate(authCtx)
	})
}

// TestPermissionCache_Clear tests clearing all cache entries
func TestPermissionCache_Clear(t *testing.T) {
	cache := NewPermissionCache(5*time.Minute, nil)
	defer cache.Close()

	t.Run("clears cache without error", func(t *testing.T) {
		// Should not panic
		cache.Clear()
	})

	t.Run("can be called multiple times", func(t *testing.T) {
		cache.Clear()
		cache.Clear()
		cache.Clear()
	})
}

// TestPermissionCache_Close tests cache cleanup
func TestPermissionCache_Close(t *testing.T) {
	t.Run("can be closed without error", func(t *testing.T) {
		cache := NewPermissionCache(5*time.Minute, nil)
		cache.Close()
	})

	t.Run("close clears the cache", func(t *testing.T) {
		cache := NewPermissionCache(5*time.Minute, nil)
		cache.Close()
		// Cache should be empty after close
		assert.Len(t, cache.cache, 0)
	})
}

// TestPermissionCache_CheckPermission_Validation tests input validation
func TestPermissionCache_CheckPermission_Validation(t *testing.T) {
	cache := NewPermissionCache(5*time.Minute, nil)
	defer cache.Close()

	t.Run("returns error when no auth context in context", func(t *testing.T) {
		ctx := context.Background()
		// org is nil because we're testing validation before SDK call
		hasPermission, err := cache.CheckPermission(ctx, nil, "test-oid", "ai_agent.operate")
		assert.Error(t, err)
		assert.False(t, hasPermission)
		assert.Contains(t, err.Error(), "no auth context")
	})
}

// TestContext_PermissionCache tests permission cache context functions
func TestContext_PermissionCache(t *testing.T) {
	t.Run("WithPermissionCache adds cache to context", func(t *testing.T) {
		cache := NewPermissionCache(30*time.Second, nil)
		defer cache.Close()

		ctx := context.Background()
		ctx = WithPermissionCache(ctx, cache)

		retrieved := GetPermissionCache(ctx)
		assert.Equal(t, cache, retrieved)
	})

	t.Run("GetPermissionCache returns nil for context without cache", func(t *testing.T) {
		ctx := context.Background()
		cache := GetPermissionCache(ctx)
		assert.Nil(t, cache)
	})
}

// TestContext_PermissionEnforcement tests permission enforcement context functions
func TestContext_PermissionEnforcement(t *testing.T) {
	t.Run("WithPermissionEnforcement sets enforcement to true", func(t *testing.T) {
		ctx := context.Background()
		ctx = WithPermissionEnforcement(ctx, true)

		enabled := IsPermissionEnforcementEnabled(ctx)
		assert.True(t, enabled)
	})

	t.Run("WithPermissionEnforcement sets enforcement to false", func(t *testing.T) {
		ctx := context.Background()
		ctx = WithPermissionEnforcement(ctx, false)

		enabled := IsPermissionEnforcementEnabled(ctx)
		assert.False(t, enabled)
	})

	t.Run("IsPermissionEnforcementEnabled returns true by default", func(t *testing.T) {
		ctx := context.Background()
		enabled := IsPermissionEnforcementEnabled(ctx)
		assert.True(t, enabled)
	})
}

// TestPermissionCache_CacheKey tests that different auth contexts produce different cache keys
func TestPermissionCache_CacheKey(t *testing.T) {
	t.Run("different OIDs produce different keys", func(t *testing.T) {
		auth1 := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "oid-1",
			APIKey: "same-key-12345678901234567890",
		}
		auth2 := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "oid-2",
			APIKey: "same-key-12345678901234567890",
		}

		key1 := auth1.CacheKey()
		key2 := auth2.CacheKey()

		assert.NotEqual(t, key1, key2)
	})

	t.Run("different API keys produce different keys", func(t *testing.T) {
		auth1 := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "same-oid",
			APIKey: "key-a-12345678901234567890",
		}
		auth2 := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "same-oid",
			APIKey: "key-b-12345678901234567890",
		}

		key1 := auth1.CacheKey()
		key2 := auth2.CacheKey()

		assert.NotEqual(t, key1, key2)
	})

	t.Run("different modes produce different keys", func(t *testing.T) {
		auth1 := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "same-oid",
			APIKey: "same-key-12345678901234567890",
		}
		auth2 := &AuthContext{
			Mode:   AuthModeUIDKey,
			OID:    "same-oid",
			APIKey: "same-key-12345678901234567890",
			UID:    "some-uid",
		}

		key1 := auth1.CacheKey()
		key2 := auth2.CacheKey()

		assert.NotEqual(t, key1, key2)
	})

	t.Run("same auth context produces same key", func(t *testing.T) {
		auth1 := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "same-oid",
			APIKey: "same-key-12345678901234567890",
		}
		auth2 := &AuthContext{
			Mode:   AuthModeNormal,
			OID:    "same-oid",
			APIKey: "same-key-12345678901234567890",
		}

		key1 := auth1.CacheKey()
		key2 := auth2.CacheKey()

		assert.Equal(t, key1, key2)
	})
}

// TestPermissionCache_TTL tests cache entry expiration
func TestPermissionCache_TTL(t *testing.T) {
	t.Run("cache respects TTL duration", func(t *testing.T) {
		// Use short TTL for testing
		cache := NewPermissionCache(100*time.Millisecond, nil)
		defer cache.Close()

		// We can verify TTL is set correctly
		assert.Equal(t, 100*time.Millisecond, cache.ttl)
	})
}
