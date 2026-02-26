package ai

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

const (
	// cacheTTL is the time-to-live for cached AI responses.
	cacheTTL = 24 * time.Hour
	// cacheCleanupInterval is how often expired entries are purged.
	cacheCleanupInterval = 1 * time.Hour
	// cacheMaxEntries is the maximum number of entries before oldest are evicted.
	cacheMaxEntries = 1000
)

// cacheEntry holds a compressed AI response and its expiry time.
type cacheEntry struct {
	compressed []byte
	expiresAt  time.Time
}

// aiCache is a simple in-memory cache for AI responses keyed by SHA256.
type aiCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	stopCh  chan struct{}
}

// globalCache is the singleton cache instance, initialized once.
var (
	globalCache     *aiCache
	globalCacheOnce sync.Once
)

// getCache returns the singleton cache instance.
func getCache() *aiCache {
	globalCacheOnce.Do(func() {
		globalCache = &aiCache{
			entries: make(map[string]cacheEntry),
			stopCh:  make(chan struct{}),
		}
		go globalCache.cleanupLoop()
	})
	return globalCache
}

// cleanupLoop periodically removes expired entries.
func (c *aiCache) cleanupLoop() {
	ticker := time.NewTicker(cacheCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.evictExpired()
		case <-c.stopCh:
			return
		}
	}
}

// evictExpired removes all entries past their TTL.
func (c *aiCache) evictExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	removed := 0
	for k, v := range c.entries {
		if now.After(v.expiresAt) {
			delete(c.entries, k)
			removed++
		}
	}
	if removed > 0 {
		slog.Debug("AI cache cleanup", "removed", removed, "remaining", len(c.entries))
	}
}

// buildCacheKey creates a SHA256 hex string from all geminiResponse inputs.
// Null bytes separate fields to prevent collisions between different inputs
// (e.g. systemPrompt="ab",model="cd" vs systemPrompt="abc",model="d").
func buildCacheKey(messages []map[string]interface{}, systemPrompt string, modelName string, temperature float32) string {
	h := sha256.New()
	// Deterministic serialization: JSON encode messages then combine with other fields.
	msgBytes, err := json.Marshal(messages)
	if err != nil {
		// Fallback: use fmt representation (still deterministic for same input).
		msgBytes = []byte(fmt.Sprintf("%v", messages))
	}
	h.Write(msgBytes)
	h.Write([]byte{0})
	h.Write([]byte(systemPrompt))
	h.Write([]byte{0})
	h.Write([]byte(modelName))
	h.Write([]byte{0})
	h.Write([]byte(fmt.Sprintf("%f", temperature)))
	return hex.EncodeToString(h.Sum(nil))
}

// compressString gzip-compresses a string.
func compressString(s string) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(s)); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decompressString gzip-decompresses bytes back to a string.
func decompressString(data []byte) (string, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// get returns the cached response for the key, or ("", false) on miss.
func (c *aiCache) get(key string) (string, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expiresAt) {
		// Expired — treat as miss; cleanup loop will remove it.
		return "", false
	}
	val, err := decompressString(entry.compressed)
	if err != nil {
		slog.Warn("AI cache decompression failed", "key", key, "error", err)
		return "", false
	}
	return val, true
}

// set stores a compressed response in the cache.
// If the cache exceeds cacheMaxEntries, the oldest entry is evicted.
func (c *aiCache) set(key string, value string) {
	compressed, err := compressString(value)
	if err != nil {
		slog.Warn("AI cache compression failed", "key", key, "error", err)
		return
	}
	c.mu.Lock()
	c.entries[key] = cacheEntry{
		compressed: compressed,
		expiresAt:  time.Now().Add(cacheTTL),
	}
	// Evict oldest entries if we exceed the cap.
	if len(c.entries) > cacheMaxEntries {
		c.evictOldestLocked()
	}
	c.mu.Unlock()
	slog.Debug("AI cache store", "key", key, "raw_bytes", len(value), "compressed_bytes", len(compressed))
}

// evictOldestLocked removes the entry with the earliest expiry. Caller must hold c.mu.
func (c *aiCache) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, v := range c.entries {
		if first || v.expiresAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.expiresAt
			first = false
		}
	}
	if !first {
		delete(c.entries, oldestKey)
		slog.Debug("AI cache evicted oldest entry", "key", oldestKey, "entries", len(c.entries))
	}
}
