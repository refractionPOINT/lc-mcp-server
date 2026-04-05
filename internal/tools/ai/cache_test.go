package ai

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildCacheKey_Deterministic(t *testing.T) {
	messages := []map[string]interface{}{
		{
			"role": "user",
			"parts": []interface{}{
				map[string]interface{}{"text": "hello world"},
			},
		},
	}
	k1 := buildCacheKey(messages, "system", "model-a", 0.0)
	k2 := buildCacheKey(messages, "system", "model-a", 0.0)
	assert.Equal(t, k1, k2, "same inputs must produce the same key")
	assert.Len(t, k1, 64, "SHA256 hex should be 64 chars")
}

func TestBuildCacheKey_DifferentInputs(t *testing.T) {
	msgs := []map[string]interface{}{
		{"role": "user", "parts": []interface{}{map[string]interface{}{"text": "a"}}},
	}
	k1 := buildCacheKey(msgs, "sys", "model", 0.0)
	k2 := buildCacheKey(msgs, "sys", "model", 0.5)
	assert.NotEqual(t, k1, k2, "different temperature should produce different key")

	k3 := buildCacheKey(msgs, "other-sys", "model", 0.0)
	assert.NotEqual(t, k1, k3, "different system prompt should produce different key")

	k4 := buildCacheKey(msgs, "sys", "other-model", 0.0)
	assert.NotEqual(t, k1, k4, "different model should produce different key")

	msgs2 := []map[string]interface{}{
		{"role": "user", "parts": []interface{}{map[string]interface{}{"text": "b"}}},
	}
	k5 := buildCacheKey(msgs2, "sys", "model", 0.0)
	assert.NotEqual(t, k1, k5, "different messages should produce different key")
}

func TestCompressDecompress_RoundTrip(t *testing.T) {
	original := "This is a test response with some YAML content:\ndetect:\n  op: exists\n  path: /event/NEW_PROCESS"
	compressed, err := compressString(original)
	require.NoError(t, err)
	// gzip has overhead on small strings; just verify round-trip works.

	decompressed, err := decompressString(compressed)
	require.NoError(t, err)
	assert.Equal(t, original, decompressed)
}

func TestCompressDecompress_EmptyString(t *testing.T) {
	compressed, err := compressString("")
	require.NoError(t, err)

	decompressed, err := decompressString(compressed)
	require.NoError(t, err)
	assert.Equal(t, "", decompressed)
}

func TestAICache_SetAndGet(t *testing.T) {
	c := &aiCache{
		entries: make(map[string]cacheEntry),
		stopCh:  make(chan struct{}),
	}
	c.set("key1", "value1")

	val, ok := c.get("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)
}

func TestAICache_Miss(t *testing.T) {
	c := &aiCache{
		entries: make(map[string]cacheEntry),
		stopCh:  make(chan struct{}),
	}
	val, ok := c.get("nonexistent")
	assert.False(t, ok)
	assert.Equal(t, "", val)
}

func TestAICache_Expiry(t *testing.T) {
	c := &aiCache{
		entries: make(map[string]cacheEntry),
		stopCh:  make(chan struct{}),
	}

	// Manually insert an already-expired entry.
	compressed, err := compressString("expired-value")
	require.NoError(t, err)
	c.mu.Lock()
	c.entries["expired"] = cacheEntry{
		compressed: compressed,
		expiresAt:  time.Now().Add(-1 * time.Second),
	}
	c.mu.Unlock()

	val, ok := c.get("expired")
	assert.False(t, ok, "expired entry should be a cache miss")
	assert.Equal(t, "", val)
}

func TestAICache_EvictExpired(t *testing.T) {
	c := &aiCache{
		entries: make(map[string]cacheEntry),
		stopCh:  make(chan struct{}),
	}

	compressed, err := compressString("val")
	require.NoError(t, err)

	c.mu.Lock()
	c.entries["alive"] = cacheEntry{
		compressed: compressed,
		expiresAt:  time.Now().Add(1 * time.Hour),
	}
	c.entries["dead"] = cacheEntry{
		compressed: compressed,
		expiresAt:  time.Now().Add(-1 * time.Second),
	}
	c.mu.Unlock()

	c.evictExpired()

	c.mu.RLock()
	_, aliveOk := c.entries["alive"]
	_, deadOk := c.entries["dead"]
	c.mu.RUnlock()

	assert.True(t, aliveOk, "alive entry should remain")
	assert.False(t, deadOk, "dead entry should be evicted")
}

func TestAICache_Overwrite(t *testing.T) {
	c := &aiCache{
		entries: make(map[string]cacheEntry),
		stopCh:  make(chan struct{}),
	}
	c.set("key", "value1")
	c.set("key", "value2")

	val, ok := c.get("key")
	assert.True(t, ok)
	assert.Equal(t, "value2", val, "latest set should overwrite previous")
}

func TestAICache_MaxEntries(t *testing.T) {
	c := &aiCache{
		entries: make(map[string]cacheEntry),
		stopCh:  make(chan struct{}),
	}

	// Fill beyond cacheMaxEntries.
	for i := 0; i < cacheMaxEntries+50; i++ {
		c.set(fmt.Sprintf("key-%d", i), fmt.Sprintf("value-%d", i))
	}

	c.mu.RLock()
	count := len(c.entries)
	c.mu.RUnlock()
	assert.LessOrEqual(t, count, cacheMaxEntries, "cache should not exceed max entries")
}

func TestAICache_ConcurrentAccess(t *testing.T) {
	c := &aiCache{
		entries: make(map[string]cacheEntry),
		stopCh:  make(chan struct{}),
	}

	const goroutines = 50
	const ops = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				key := fmt.Sprintf("key-%d-%d", id, i)
				c.set(key, fmt.Sprintf("value-%d-%d", id, i))
				// Read back (may or may not hit depending on eviction).
				c.get(key)
				// Also trigger eviction path.
				c.evictExpired()
			}
		}(g)
	}

	wg.Wait()
	// If we get here without a race detector failure, concurrency is safe.
}

func TestBuildCacheKey_SeparatorPreventsCollision(t *testing.T) {
	msgs := []map[string]interface{}{
		{"role": "user", "parts": []interface{}{map[string]interface{}{"text": "q"}}},
	}
	// These should NOT collide thanks to null-byte separators.
	k1 := buildCacheKey(msgs, "ab", "cd", 0.0)
	k2 := buildCacheKey(msgs, "abc", "d", 0.0)
	assert.NotEqual(t, k1, k2, "different field boundaries must produce different keys")

	k3 := buildCacheKey(msgs, "a", "bcd", 0.0)
	assert.NotEqual(t, k1, k3)
	assert.NotEqual(t, k2, k3)
}

func TestAICache_LargeValue(t *testing.T) {
	c := &aiCache{
		entries: make(map[string]cacheEntry),
		stopCh:  make(chan struct{}),
	}

	// Simulate a large AI response (repeated text compresses well).
	large := ""
	for i := 0; i < 10000; i++ {
		large += "detect:\n  op: exists\n  path: /event/NEW_PROCESS\n"
	}

	c.set("large", large)
	val, ok := c.get("large")
	assert.True(t, ok)
	assert.Equal(t, large, val)

	// Verify compression is effective.
	c.mu.RLock()
	entry := c.entries["large"]
	c.mu.RUnlock()
	assert.Less(t, len(entry.compressed), len(large)/10, "gzip should compress repetitive text significantly")
}
