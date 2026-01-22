package auth

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// PermissionCache caches WhoAmI responses to avoid repeated API calls
// for permission verification. Each cache entry is keyed by credential
// hash to prevent cross-contamination between different API keys/JWTs.
type PermissionCache struct {
	mu     sync.RWMutex
	cache  map[string]*cachedPermission
	ttl    time.Duration
	logger *slog.Logger
}

// cachedPermission holds a cached WhoAmI response with timestamp
type cachedPermission struct {
	whoAmI   lc.WhoAmIJsonResponse
	cachedAt time.Time
}

// NewPermissionCache creates a new permission cache with the given TTL
func NewPermissionCache(ttl time.Duration, logger *slog.Logger) *PermissionCache {
	if logger == nil {
		logger = slog.Default()
	}
	return &PermissionCache{
		cache:  make(map[string]*cachedPermission),
		ttl:    ttl,
		logger: logger,
	}
}

// CheckPermission verifies if the current credentials have the specified
// permission for the given organization. It caches WhoAmI responses to
// minimize API calls.
//
// Parameters:
//   - ctx: Context containing auth credentials
//   - org: Organization to check permissions against
//   - oid: Target organization ID
//   - permission: Permission name to check (e.g., "ai_agent.operate")
//
// Returns:
//   - bool: true if the permission is granted, false otherwise
//   - error: any error encountered during the check
func (c *PermissionCache) CheckPermission(ctx context.Context, org *lc.Organization, oid, permission string) (bool, error) {
	// Get auth context to generate cache key
	authCtx, err := FromContext(ctx)
	if err != nil {
		return false, fmt.Errorf("no auth context: %w", err)
	}

	cacheKey := authCtx.CacheKey()

	// Try to get from cache first
	c.mu.RLock()
	cached, ok := c.cache[cacheKey]
	if ok && time.Since(cached.cachedAt) < c.ttl {
		c.mu.RUnlock()
		hasPermission := cached.whoAmI.HasPermissionForOrg(oid, permission)
		c.logger.Debug("Permission check (cached)",
			"oid", oid,
			"permission", permission,
			"granted", hasPermission)
		return hasPermission, nil
	}
	c.mu.RUnlock()

	// Cache miss or expired - fetch fresh WhoAmI
	c.logger.Debug("Fetching WhoAmI for permission check",
		"oid", oid,
		"permission", permission)

	whoAmI, err := org.WhoAmI()
	if err != nil {
		return false, fmt.Errorf("failed to fetch permissions: %w", err)
	}

	// Update cache
	c.mu.Lock()
	c.cache[cacheKey] = &cachedPermission{
		whoAmI:   whoAmI,
		cachedAt: time.Now(),
	}
	c.mu.Unlock()

	hasPermission := whoAmI.HasPermissionForOrg(oid, permission)
	c.logger.Debug("Permission check (fresh)",
		"oid", oid,
		"permission", permission,
		"granted", hasPermission)

	return hasPermission, nil
}

// Invalidate removes a specific entry from the cache
func (c *PermissionCache) Invalidate(authCtx *AuthContext) {
	if authCtx == nil {
		return
	}
	cacheKey := authCtx.CacheKey()

	c.mu.Lock()
	delete(c.cache, cacheKey)
	c.mu.Unlock()

	c.logger.Debug("Permission cache entry invalidated")
}

// Clear removes all entries from the cache
func (c *PermissionCache) Clear() {
	c.mu.Lock()
	c.cache = make(map[string]*cachedPermission)
	c.mu.Unlock()

	c.logger.Debug("Permission cache cleared")
}

// cleanup removes expired entries from the cache
// This can be called periodically to prevent memory growth
func (c *PermissionCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.cache {
		if now.Sub(entry.cachedAt) >= c.ttl {
			delete(c.cache, key)
		}
	}
}

// Close stops the cache and cleans up resources
func (c *PermissionCache) Close() {
	c.Clear()
}
