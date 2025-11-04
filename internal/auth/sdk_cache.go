package auth

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"log/slog"
)

// CachedSDK holds a cached SDK instance with metadata
// NOTE: We only cache the Client, not the Organization, to prevent
// Spout reuse issues. Organization objects are lightweight wrappers
// that can be created on-demand from the Client.
type CachedSDK struct {
	Client    *lc.Client
	CreatedAt time.Time
	LastUsed  time.Time
	CacheKey  string // For debugging purposes
}

// SDKCache is a thread-safe cache for SDK instances
// CRITICAL: This cache MUST be credential-isolated to prevent multi-tenant leaks
type SDKCache struct {
	mu            sync.RWMutex
	cache         map[string]*CachedSDK
	ttl           time.Duration
	maxSize       int // Maximum number of cached SDK instances
	logger        *slog.Logger
	cancelCleanup context.CancelFunc // For stopping the cleanup goroutine
	metrics       struct {
		hits      uint64
		misses    uint64
		evictions uint64
	}
}

const (
	// DefaultMaxCacheSize is the default maximum number of cached SDK instances
	// This prevents memory exhaustion in multi-tenant scenarios
	DefaultMaxCacheSize = 1000
)

// NewSDKCache creates a new SDK cache with the specified TTL
func NewSDKCache(ttl time.Duration, logger *slog.Logger) *SDKCache {
	if logger == nil {
		logger = slog.Default()
	}

	// Create cancellable context for cleanup goroutine
	ctx, cancel := context.WithCancel(context.Background())

	cache := &SDKCache{
		cache:         make(map[string]*CachedSDK),
		ttl:           ttl,
		maxSize:       DefaultMaxCacheSize,
		logger:        logger,
		cancelCleanup: cancel,
	}

	// Start cleanup goroutine with context
	go cache.cleanupLoop(ctx)

	return cache
}

// GetOrCreate retrieves a cached SDK instance or creates a new one
// CRITICAL: The cache key is based on credentials to ensure isolation
func (c *SDKCache) GetOrCreate(ctx context.Context, auth *AuthContext) (*lc.Organization, error) {
	if auth == nil {
		return nil, fmt.Errorf("auth context is nil")
	}

	if err := auth.Validate(); err != nil {
		return nil, fmt.Errorf("invalid auth context: %w", err)
	}

	cacheKey := auth.CacheKey()

	// Try to get from cache (read lock)
	c.mu.RLock()
	cached, exists := c.cache[cacheKey]
	c.mu.RUnlock()

	if exists {
		// Check if cache TTL expired
		if time.Since(cached.CreatedAt) < c.ttl {
			// CRITICAL: If using JWT, also check if token expired
			// This prevents expired JWTs from being extended by cache TTL
			if auth.JWTToken != "" {
				tokenExpiry, err := GetJWTExpirationTime(auth.JWTToken)
				if err != nil {
					// Can't read expiration - invalidate cache and create new
					c.mu.Lock()
					delete(c.cache, cacheKey)
					c.mu.Unlock()
					atomic.AddUint64(&c.metrics.evictions, 1)
					c.logger.Warn("Invalidated cache entry: unable to parse JWT expiration")
				} else if time.Now().After(tokenExpiry) {
					// JWT expired - invalidate cache entry
					c.mu.Lock()
					delete(c.cache, cacheKey)
					c.mu.Unlock()
					atomic.AddUint64(&c.metrics.evictions, 1)
					// // 					c.logger.WithFields(map[string]interface{}{
					// 						"cache_key":        cacheKey[:8] + "...",
					// 						"expired_at":       tokenExpiry.Format(time.RFC3339),
					// 						"age_since_expiry": time.Since(tokenExpiry),
					// 					}).Info("Invalidated cache entry: JWT token expired")

					// Return error to force re-authentication
					return nil, fmt.Errorf("JWT token expired at %s", tokenExpiry.Format(time.RFC3339))
				}
			}

			// Cache is valid and token (if present) hasn't expired
			// Update last used time
			c.mu.Lock()
			cached.LastUsed = time.Now()
			c.mu.Unlock()

			// Increment hit counter atomically
			atomic.AddUint64(&c.metrics.hits, 1)

			// // 			c.logger.WithFields(map[string]interface{}{
			// 				"cache_key": cacheKey[:8] + "...", // Reduced to 8 chars per security review
			// 				"mode":      auth.Mode.String(),
			// 				"age":       time.Since(cached.CreatedAt),
			// 			}).Debug("SDK cache hit")

			// CRITICAL FIX: Always create fresh Organization from cached Client
			// This prevents Spout reuse issues. When WithInvestigationID() creates
			// a shallow copy, it shares the Spout pointer. If the Spout was initialized
			// with a different investigation ID, responses will be filtered incorrectly
			// at the WebSocket level and never arrive, causing 10-minute timeouts.
			// Creating a fresh Organization ensures no stale Spout is attached.
			org, err := lc.NewOrganization(cached.Client)
			if err != nil {
				return nil, fmt.Errorf("failed to create organization from cached client: %w", err)
			}
			return org, nil
		}

		// Expired, remove from cache
		c.mu.Lock()
		delete(c.cache, cacheKey)
		c.mu.Unlock()

		// Increment eviction counter atomically
		atomic.AddUint64(&c.metrics.evictions, 1)

		// // 		c.logger.WithFields(map[string]interface{}{
		// 			"cache_key": cacheKey[:8] + "...",
		// 			"age":       time.Since(cached.CreatedAt),
		// 		}).Debug("SDK cache entry expired")
	}

	// Cache miss - create new SDK instance
	atomic.AddUint64(&c.metrics.misses, 1)

	// // 	c.logger.WithFields(map[string]interface{}{
	// 		"cache_key": cacheKey[:8] + "...",
	// 		"mode":      auth.Mode.String(),
	// 	}).Debug("SDK cache miss - creating new client")

	// Create new client
	opts := auth.GetClientOptions()

	// Create client with appropriate loaders
	var client *lc.Client
	var err error

	// Use environment loader if we have environment set (for OAuth mode)
	if auth.Environment != "" {
		client, err = lc.NewClientFromLoader(
			opts,
			nil, // logger - SDK uses its own
			&lc.EnvironmentClientOptionLoader{},
			lc.NewFileClientOptionLoader(""),
		)
	} else {
		// Use direct client creation for API key mode
		client, err = lc.NewClient(opts, nil)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create SDK client: %w", err)
	}

	// Cache the client instance (NOT the organization)
	// Organization will be created fresh on each request to prevent Spout reuse
	cached = &CachedSDK{
		Client:    client,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
		CacheKey:  cacheKey,
	}

	c.mu.Lock()
	// Check if cache is full and evict LRU entry if needed
	if len(c.cache) >= c.maxSize {
		c.evictOldestLocked()
	}
	c.cache[cacheKey] = cached
	c.mu.Unlock()

	// // 	c.logger.WithFields(map[string]interface{}{
	// 		"cache_key": cacheKey[:8] + "...",
	// 		"mode":      auth.Mode.String(),
	// 	}).Info("Created and cached new SDK client")

	// Create fresh Organization from the newly cached client
	org, err := lc.NewOrganization(client)
	if err != nil {
		return nil, fmt.Errorf("failed to create organization: %w", err)
	}

	return org, nil
}

// InvalidateAll clears all cached SDK instances
func (c *SDKCache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*CachedSDK)
	c.logger.Info("Invalidated all SDK cache entries")
}

// Invalidate removes a specific cache entry
func (c *SDKCache) Invalidate(auth *AuthContext) {
	if auth == nil {
		return
	}

	cacheKey := auth.CacheKey()

	c.mu.Lock()
	delete(c.cache, cacheKey)
	c.mu.Unlock()

	c.logger.Debug("Invalidated SDK cache entry")
}

// GetStats returns cache statistics
func (c *SDKCache) GetStats() map[string]interface{} {
	c.mu.RLock()
	size := len(c.cache)
	c.mu.RUnlock()

	// Read metrics atomically
	return map[string]interface{}{
		"size":      size,
		"hits":      atomic.LoadUint64(&c.metrics.hits),
		"misses":    atomic.LoadUint64(&c.metrics.misses),
		"evictions": atomic.LoadUint64(&c.metrics.evictions),
		"ttl":       c.ttl.String(),
		"max_size":  c.maxSize,
	}
}

// evictOldestLocked removes the least recently used entry from the cache
// MUST be called with c.mu write lock held
func (c *SDKCache) evictOldestLocked() {
	if len(c.cache) == 0 {
		return
	}

	// Find the entry with the oldest LastUsed time
	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, cached := range c.cache {
		if first || cached.LastUsed.Before(oldestTime) {
			oldestKey = key
			oldestTime = cached.LastUsed
			first = false
		}
	}

	// Remove the oldest entry
	if oldestKey != "" {
		delete(c.cache, oldestKey)
		atomic.AddUint64(&c.metrics.evictions, 1)

		// // 		c.logger.WithFields(map[string]interface{}{
		// 			"cache_key": oldestKey[:8] + "...",
		// 			"age":       time.Since(oldestTime),
		// 			"reason":    "cache_full",
		// 		}).Debug("Evicted LRU cache entry")
	}
}

// Close stops the cleanup goroutine and releases resources
func (c *SDKCache) Close() {
	if c.cancelCleanup != nil {
		c.cancelCleanup()
	}
	c.logger.Debug("SDK cache cleanup goroutine stopped")
}

// cleanupLoop periodically removes expired entries
func (c *SDKCache) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(c.ttl / 2) // Cleanup at half TTL interval
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Context cancelled, exit cleanup loop
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

// cleanup removes expired entries from the cache
func (c *SDKCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	expired := 0

	for key, cached := range c.cache {
		if now.Sub(cached.CreatedAt) >= c.ttl {
			delete(c.cache, key)
			expired++
		}
	}

	if expired > 0 {
		// Increment evictions counter atomically
		atomic.AddUint64(&c.metrics.evictions, uint64(expired))

		// // 		c.logger.WithFields(map[string]interface{}{
		// 			"expired":         expired,
		// 			"remaining":       len(c.cache),
		// 			"total_evictions": atomic.LoadUint64(&c.metrics.evictions),
		// 		}).Debug("Cleaned up expired SDK cache entries")
	}
}

// GetFromContext is a convenience method that extracts auth from context
// and retrieves/creates the SDK instance
func (c *SDKCache) GetFromContext(ctx context.Context) (*lc.Organization, error) {
	auth, err := FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth from context: %w", err)
	}

	return c.GetOrCreate(ctx, auth)
}
