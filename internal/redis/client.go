package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"log/slog"
)

// Client wraps the Redis client with additional functionality
type Client struct {
	client *redis.Client
	logger *slog.Logger

	// Lua scripts for atomic operations
	atomicGetAndDelete      *redis.Script
	atomicMultiGetAndDelete *redis.Script
	incrWithWindow          *redis.Script
	claim                   *redis.Script
	getDeleteTombstone      *redis.Script
	writeUnlessGuarded      *redis.Script
	createAllUnlessGuarded  *redis.Script
}

// Config holds Redis configuration
type Config struct {
	URL string
	// MaxRetries overrides the command retry count when non-zero.
	// -1 disables retries (go-redis semantics), e.g. for fault-injection tests.
	MaxRetries int
}

// New creates a new Redis client
func New(cfg *Config, logger *slog.Logger) (*Client, error) {
	// Parse Redis URL
	opt, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid Redis URL: %w", err)
	}

	// Configure client with lenient timeouts for high-latency networks
	opt.DialTimeout = 30 * time.Second
	opt.ReadTimeout = 10 * time.Second
	opt.WriteTimeout = 10 * time.Second
	opt.PoolSize = 10
	opt.MinIdleConns = 2

	// Command retry settings
	opt.MaxRetries = 5
	if cfg.MaxRetries != 0 {
		opt.MaxRetries = cfg.MaxRetries
	}
	opt.MinRetryBackoff = 100 * time.Millisecond
	opt.MaxRetryBackoff = 3 * time.Second

	// Connection dialer retry settings (separate from command retries)
	opt.DialerRetries = 20
	opt.DialerRetryTimeout = 500 * time.Millisecond

	// Create client
	client := redis.NewClient(opt)

	c := &Client{
		client: client,
		logger: logger,
	}

	// Test connection with longer timeout to match dial settings
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// Load Lua scripts
	c.loadScripts()

	logger.Info("Redis client initialized")

	return c, nil
}

// loadScripts registers Lua scripts for atomic operations
func (c *Client) loadScripts() {
	// Atomic get-and-delete (single key)
	// SECURITY: Prevents TOCTOU race conditions
	c.atomicGetAndDelete = redis.NewScript(`
		local value = redis.call('GET', KEYS[1])
		if value then
			redis.call('DEL', KEYS[1])
		end
		return value
	`)

	// Atomic multi-key get-and-delete
	// Returns all values, then deletes all keys atomically
	c.atomicMultiGetAndDelete = redis.NewScript(`
		local results = {}
		for i, key in ipairs(KEYS) do
			results[i] = redis.call('GET', key)
		end
		redis.call('DEL', unpack(KEYS))
		return results
	`)

	// Atomic counter with a window: increments and, in the same step, gives the
	// key an expiry whenever it has none. A separate INCR then EXPIRE could
	// leave a counter without a TTL if the second command failed, and it would
	// then never reset.
	c.incrWithWindow = redis.NewScript(`
		local n = redis.call('INCR', KEYS[1])
		if redis.call('PTTL', KEYS[1]) < 0 then
			redis.call('PEXPIRE', KEYS[1], ARGV[1])
		end
		return n
	`)

	// Claim: take a record out of circulation and mark it claimed, in one step.
	// Returns {value, remaining ttl in ms}, or nothing when the key is absent,
	// so exactly one caller can claim a given record.
	c.claim = redis.NewScript(`
		local v = redis.call('GET', KEYS[1])
		if not v then
			return false
		end
		local ttl = redis.call('PTTL', KEYS[1])
		redis.call('DEL', KEYS[1])
		redis.call('SET', KEYS[2], '1', 'PX', ARGV[1])
		return {v, ttl}
	`)

	// Get-delete-tombstone: delete a record and leave a tombstone when there was
	// a record to delete, or when it is currently claimed by an operation in
	// flight (KEYS[2] exists). A token that never existed leaves nothing behind,
	// so unauthenticated callers cannot fill Redis with tombstones.
	c.getDeleteTombstone = redis.NewScript(`
		local v = redis.call('GET', KEYS[1])
		if v then
			redis.call('DEL', KEYS[1])
		end
		if v or redis.call('EXISTS', KEYS[2]) == 1 then
			redis.call('SET', KEYS[3], '1', 'PX', ARGV[1])
		end
		return v
	`)

	// Guarded single-key write: KEYS[1] is written (NX or XX per ARGV[3]) unless
	// any of the guard keys KEYS[2..] exists. Returns 1 written, 0 the NX/XX
	// condition failed, -1 blocked by a guard.
	c.writeUnlessGuarded = redis.NewScript(`
		for i = 2, #KEYS do
			if redis.call('EXISTS', KEYS[i]) == 1 then
				return -1
			end
		end
		if redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2], ARGV[3]) then
			return 1
		end
		return 0
	`)

	// Guarded multi-key create: KEYS is guards, then entries, then keys to
	// delete; ARGV[1] and ARGV[2] are the guard and entry counts, followed by a
	// value and a ttl in ms per entry. All entries are created (create-only) and
	// the delete keys removed, or nothing changes. Returns 1 done, 0 an entry
	// already exists, -1 blocked by a guard.
	c.createAllUnlessGuarded = redis.NewScript(`
		local ng = tonumber(ARGV[1])
		local ne = tonumber(ARGV[2])
		for i = 1, ng do
			if redis.call('EXISTS', KEYS[i]) == 1 then
				return -1
			end
		end
		for i = 1, ne do
			if redis.call('EXISTS', KEYS[ng + i]) == 1 then
				return 0
			end
		end
		for i = 1, ne do
			redis.call('SET', KEYS[ng + i], ARGV[1 + 2 * i], 'PX', ARGV[2 + 2 * i])
		end
		for i = ng + ne + 1, #KEYS do
			redis.call('DEL', KEYS[i])
		end
		return 1
	`)

	c.logger.Debug("Loaded atomic Redis Lua scripts")
}

// Get retrieves a value from Redis
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	val, err := c.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil
	}
	return val, err
}

// Set stores a value in Redis
func (c *Client) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return c.client.Set(ctx, key, value, expiration).Err()
}

// SetNX stores a value only if the key does not exist (SET NX) and reports
// whether it was stored. Use it for records whose id must never be overwritten.
// A zero expiration stores the key without one.
func (c *Client) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	if expiration < 0 {
		return false, fmt.Errorf("expiration must not be negative")
	}
	return c.client.SetNX(ctx, key, value, expiration).Result()
}

// SetXXKeepTTL overwrites a key only if it still exists (SET XX KEEPTTL),
// leaving its expiry unchanged, and reports whether it was updated. A record
// that was consumed or expired in the meantime is not resurrected.
func (c *Client) SetXXKeepTTL(ctx context.Context, key string, value interface{}) (bool, error) {
	res, err := c.client.SetArgs(ctx, key, value, redis.SetArgs{Mode: "XX", KeepTTL: true}).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return res == "OK", nil
}

// WriteResult is the outcome of a guarded write.
type WriteResult int

const (
	// WriteDone means the write happened.
	WriteDone WriteResult = iota
	// WriteConflict means the key was in the wrong state: it already existed
	// for a create-only write, or was missing for an update-only write.
	WriteConflict
	// WriteBlocked means a guard key (a revocation marker) exists.
	WriteBlocked
)

func writeResultFrom(n int64) (WriteResult, error) {
	switch n {
	case 1:
		return WriteDone, nil
	case 0:
		return WriteConflict, nil
	case -1:
		return WriteBlocked, nil
	}
	return WriteConflict, fmt.Errorf("unexpected script result %d", n)
}

func ttlMillis(d time.Duration) (int64, error) {
	ms := d.Milliseconds()
	if ms < 1 {
		return 0, fmt.Errorf("expiration must be positive")
	}
	return ms, nil
}

// CreateUnlessGuarded stores value under key only if the key is free and none
// of the guard keys exists, in one atomic step. The expiration must be positive.
func (c *Client) CreateUnlessGuarded(ctx context.Context, key, value string, expiration time.Duration, guards ...string) (WriteResult, error) {
	return c.writeGuarded(ctx, "NX", key, value, expiration, guards)
}

// UpdateUnlessGuarded overwrites key, with the given expiration, only if it
// still exists and none of the guard keys exists, in one atomic step. A record
// that was deleted (revoked) or expired in the meantime is never re-created.
// The expiration must be positive.
func (c *Client) UpdateUnlessGuarded(ctx context.Context, key, value string, expiration time.Duration, guards ...string) (WriteResult, error) {
	return c.writeGuarded(ctx, "XX", key, value, expiration, guards)
}

func (c *Client) writeGuarded(ctx context.Context, mode, key, value string, expiration time.Duration, guards []string) (WriteResult, error) {
	ms, err := ttlMillis(expiration)
	if err != nil {
		return WriteConflict, err
	}
	keys := append([]string{key}, guards...)
	n, err := c.writeUnlessGuarded.Run(ctx, c.client, keys, value, ms, mode).Int64()
	if err != nil {
		return WriteConflict, err
	}
	return writeResultFrom(n)
}

// Entry is a key/value to create with an expiration.
type Entry struct {
	Key   string
	Value string
	TTL   time.Duration
}

// CreateAllUnlessGuarded atomically creates every entry (create-only) and
// deletes the delete keys, unless a guard key exists or an entry already
// exists, in which case nothing changes.
func (c *Client) CreateAllUnlessGuarded(ctx context.Context, entries []Entry, deleteKeys []string, guards []string) (WriteResult, error) {
	keys := make([]string, 0, len(guards)+len(entries)+len(deleteKeys))
	keys = append(keys, guards...)
	args := []interface{}{len(guards), len(entries)}
	for _, e := range entries {
		ms, err := ttlMillis(e.TTL)
		if err != nil {
			return WriteConflict, err
		}
		keys = append(keys, e.Key)
		args = append(args, e.Value, ms)
	}
	keys = append(keys, deleteKeys...)
	n, err := c.createAllUnlessGuarded.Run(ctx, c.client, keys, args...).Int64()
	if err != nil {
		return WriteConflict, err
	}
	return writeResultFrom(n)
}

// ClaimAndDelete atomically takes key out of circulation: it returns its value
// and remaining TTL, deletes it, and sets markerKey for markerTTL, so a single
// caller wins. found is false when the key did not exist.
func (c *Client) ClaimAndDelete(ctx context.Context, key, markerKey string, markerTTL time.Duration) (value string, remaining time.Duration, found bool, err error) {
	ms, err := ttlMillis(markerTTL)
	if err != nil {
		return "", 0, false, err
	}
	res, err := c.claim.Run(ctx, c.client, []string{key, markerKey}, ms).Result()
	if err == redis.Nil {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	arr, ok := res.([]interface{})
	if !ok || len(arr) != 2 {
		return "", 0, false, fmt.Errorf("unexpected claim result")
	}
	v, ok := arr[0].(string)
	ttl, ok2 := arr[1].(int64)
	if !ok || !ok2 {
		return "", 0, false, fmt.Errorf("unexpected claim result")
	}
	return v, time.Duration(ttl) * time.Millisecond, true, nil
}

// GetDeleteAndTombstone deletes key and returns its value (found=false if it did
// not exist). It sets tombstoneKey for tombstoneTTL when the key existed, or
// when claimMarkerKey exists (the record is being operated on right now).
func (c *Client) GetDeleteAndTombstone(ctx context.Context, key, claimMarkerKey, tombstoneKey string, tombstoneTTL time.Duration) (value string, found bool, err error) {
	ms, err := ttlMillis(tombstoneTTL)
	if err != nil {
		return "", false, err
	}
	res, err := c.getDeleteTombstone.Run(ctx, c.client, []string{key, claimMarkerKey, tombstoneKey}, ms).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	v, ok := res.(string)
	if !ok {
		return "", false, nil
	}
	return v, true, nil
}

// SetEX stores a value with expiration time
func (c *Client) SetEX(ctx context.Context, key string, value interface{}, seconds int) error {
	return c.client.Set(ctx, key, value, time.Duration(seconds)*time.Second).Err()
}

// Delete removes a key from Redis
func (c *Client) Delete(ctx context.Context, keys ...string) error {
	return c.client.Del(ctx, keys...).Err()
}

// Del is an alias for Delete
func (c *Client) Del(ctx context.Context, keys ...string) error {
	return c.Delete(ctx, keys...)
}

// Incr increments a key's value atomically and returns the new value
func (c *Client) Incr(ctx context.Context, key string) (int64, error) {
	return c.client.Incr(ctx, key).Result()
}

// IncrWithWindow atomically increments a counter and makes sure it expires
// within window: a new counter gets the window as its TTL, and an existing
// counter that somehow has no TTL gets one. It returns the new value.
func (c *Client) IncrWithWindow(ctx context.Context, key string, window time.Duration) (int64, error) {
	if window <= 0 {
		return 0, fmt.Errorf("window must be positive")
	}
	return c.incrWithWindow.Run(ctx, c.client, []string{key}, window.Milliseconds()).Int64()
}

// Expire sets a timeout on a key
func (c *Client) Expire(ctx context.Context, key string, expiration time.Duration) error {
	return c.client.Expire(ctx, key, expiration).Err()
}

// Exists checks if keys exist
func (c *Client) Exists(ctx context.Context, keys ...string) (int64, error) {
	return c.client.Exists(ctx, keys...).Result()
}

// TTL gets the remaining time to live of a key
func (c *Client) TTL(ctx context.Context, key string) (time.Duration, error) {
	return c.client.TTL(ctx, key).Result()
}

// AtomicGetAndDelete atomically gets and deletes a key (single-use consumption)
// SECURITY: Prevents TOCTOU race conditions where multiple requests could reuse the same value
func (c *Client) AtomicGetAndDelete(ctx context.Context, key string) (string, error) {
	result, err := c.atomicGetAndDelete.Run(ctx, c.client, []string{key}).Result()
	if err != nil {
		// redis.Nil means the key didn't exist, which is not an error for this operation
		if err == redis.Nil {
			return "", nil
		}
		return "", err
	}

	if result == nil {
		return "", nil
	}

	// Convert result to string
	if str, ok := result.(string); ok {
		return str, nil
	}

	return "", nil
}

// AtomicMultiGetAndDelete atomically gets and deletes multiple keys
// Returns values in same order as keys
func (c *Client) AtomicMultiGetAndDelete(ctx context.Context, keys []string) ([]string, error) {
	if len(keys) == 0 {
		return []string{}, nil
	}

	result, err := c.atomicMultiGetAndDelete.Run(ctx, c.client, keys).Result()
	if err != nil {
		return nil, err
	}

	// Convert results to string slice
	results, ok := result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type from Lua script")
	}

	strResults := make([]string, len(results))
	for i, r := range results {
		if r == nil {
			strResults[i] = ""
		} else if str, ok := r.(string); ok {
			strResults[i] = str
		}
	}

	return strResults, nil
}

// Ping checks if Redis is reachable
func (c *Client) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// Health returns health information about Redis
func (c *Client) Health(ctx context.Context) (map[string]interface{}, error) {
	info, err := c.client.Info(ctx, "stats").Result()
	if err != nil {
		return nil, err
	}

	// Parse basic stats from info string
	// For now, just return ping status
	err = c.Ping(ctx)
	healthy := err == nil

	return map[string]interface{}{
		"healthy": healthy,
		"info":    info,
	}, nil
}

// Close closes the Redis client
// DeleteByPattern deletes all keys matching a pattern using SCAN for safety
// This is safer than KEYS * which can block Redis on large datasets
func (c *Client) DeleteByPattern(ctx context.Context, pattern string) error {
	var cursor uint64
	var deletedCount int64

	for {
		// SCAN with pattern matching
		keys, nextCursor, err := c.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("failed to scan keys: %w", err)
		}

		// Delete matching keys in batches
		if len(keys) > 0 {
			deleted, err := c.client.Del(ctx, keys...).Result()
			if err != nil {
				return fmt.Errorf("failed to delete keys: %w", err)
			}
			deletedCount += deleted
		}

		// Check if scan is complete
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	c.logger.Debug("Deleted keys by pattern", "pattern", pattern, "count", deletedCount)
	return nil
}

func (c *Client) Close() error {
	return c.client.Close()
}
