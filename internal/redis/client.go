package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// Client wraps the Redis client with additional functionality
type Client struct {
	client *redis.Client
	logger *logrus.Logger

	// Lua scripts for atomic operations
	atomicGetAndDelete      *redis.Script
	atomicMultiGetAndDelete *redis.Script
}

// Config holds Redis configuration
type Config struct {
	URL string
}

// New creates a new Redis client
func New(cfg *Config, logger *logrus.Logger) (*Client, error) {
	// Parse Redis URL
	opt, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid Redis URL: %w", err)
	}

	// Configure client
	opt.DialTimeout = 5 * time.Second
	opt.ReadTimeout = 3 * time.Second
	opt.WriteTimeout = 3 * time.Second
	opt.PoolSize = 10
	opt.MinIdleConns = 2
	opt.MaxRetries = 3

	// Create client
	client := redis.NewClient(opt)

	c := &Client{
		client: client,
		logger: logger,
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// Load Lua scripts
	c.loadScripts()

	logger.WithField("url", cfg.URL).Info("Redis client initialized")

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

// SetEX stores a value with expiration time
func (c *Client) SetEX(ctx context.Context, key string, value interface{}, seconds int) error {
	return c.client.Set(ctx, key, value, time.Duration(seconds)*time.Second).Err()
}

// Delete removes a key from Redis
func (c *Client) Delete(ctx context.Context, keys ...string) error {
	return c.client.Del(ctx, keys...).Err()
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
func (c *Client) Close() error {
	return c.client.Close()
}
