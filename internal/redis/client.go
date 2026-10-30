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
	createOnly              *redis.Script
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

	// Create-only that survives its own retry: stores the value if the key is
	// free, and also answers "stored" when the key already holds exactly this
	// value (see CreateOnly). KEYS[1] is the key, ARGV[1] the value, ARGV[2] the
	// expiry in milliseconds (0 for none). The type check keeps a key of another
	// type a plain conflict instead of a script error.
	c.createOnly = redis.NewScript(`
		local ok
		if tonumber(ARGV[2]) > 0 then
			ok = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', ARGV[2])
		else
			ok = redis.call('SET', KEYS[1], ARGV[1], 'NX')
		end
		if ok then
			return 1
		end
		if redis.call('TYPE', KEYS[1]).ok == 'string' and redis.call('GET', KEYS[1]) == ARGV[1] then
			return 1
		end
		return 0
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
// whether it was stored. A zero expiration stores the key without one.
//
// A command whose reply was lost is sent again by the client library, and the
// repeat of a SET NX that already took effect reports "not stored" even though
// the caller's own value is there. Records that one writer creates under a
// random id should use CreateOnly instead.
func (c *Client) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	if expiration < 0 {
		return false, fmt.Errorf("expiration must not be negative")
	}
	return c.client.SetNX(ctx, key, value, expiration).Result()
}

// CreateOnly stores value under key only if the key is free, and reports whether
// the key now holds exactly value: true when it was created or already held this
// value, false when it holds something else (it is never overwritten). A zero
// expiration stores the key without one; an existing key keeps the expiry it has.
//
// It is one atomic script, so it is safe to run twice with the same arguments, as
// the client library does when a reply is lost: the repeat of a create that took
// effect finds its own value and still answers true. Another writer can only be
// mistaken for the same one if it writes the very same value, which for the
// records created this way (they carry random ids) is the same record.
func (c *Client) CreateOnly(ctx context.Context, key, value string, expiration time.Duration) (bool, error) {
	if expiration < 0 {
		return false, fmt.Errorf("expiration must not be negative")
	}
	ms := expiration.Milliseconds()
	if expiration > 0 && ms == 0 {
		ms = 1
	}
	n, err := c.createOnly.Run(ctx, c.client, []string{key}, value, ms).Int64()
	if err != nil {
		return false, err
	}
	return n == 1, nil
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

// Script is a Lua script that Redis runs atomically. Callers that build key
// names inside the script (instead of receiving every key in KEYS) need a
// standalone or primary/replica Redis, not a cluster.
type Script struct {
	script *redis.Script
}

// NewScript prepares a Lua script for Run.
func NewScript(src string) *Script {
	return &Script{script: redis.NewScript(src)}
}

// Run executes the script (EVALSHA, falling back to EVAL when the server has
// not loaded it yet) and returns the raw reply: int64, string or []interface{}.
//
// A command that fails on the network is retried by the client with the same
// arguments, and the failed attempt may already have been executed. Scripts must
// therefore be safe to run twice with the same arguments and answer the second
// run like the first.
func (c *Client) Run(ctx context.Context, s *Script, keys []string, args ...interface{}) (interface{}, error) {
	return s.script.Run(ctx, c.client, keys, args...).Result()
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
