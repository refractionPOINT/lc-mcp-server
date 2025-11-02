package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/redis"
	"log/slog"
)

// Limiter implements Redis-based rate limiting using token bucket algorithm
type Limiter struct {
	redis  *redis.Client
	logger *slog.Logger
}

// Config holds rate limit configuration for an endpoint
type Config struct {
	MaxRequests int           // Maximum requests allowed
	Window      time.Duration // Time window for the limit
}

// NewLimiter creates a new rate limiter
func NewLimiter(redisClient *redis.Client, logger *slog.Logger) *Limiter {
	return &Limiter{
		redis:  redisClient,
		logger: logger,
	}
}

// Allow checks if a request should be allowed based on rate limits
// Returns true if allowed, false if rate limit exceeded
func (l *Limiter) Allow(ctx context.Context, key string, cfg Config) (bool, error) {
	// Use Redis INCR and EXPIRE for simple rate limiting
	// This implements a fixed window counter

	// Generate Redis key with timestamp bucket
	bucketKey := fmt.Sprintf("ratelimit:%s:%d", key, time.Now().Unix()/int64(cfg.Window.Seconds()))

	// Increment counter
	count, err := l.redis.Incr(ctx, bucketKey)
	if err != nil {
		// On Redis error, allow the request (fail open)
		l.logger.Warn("Rate limit check failed, allowing request")
		return true, err
	}

	// Set expiration on first increment
	if count == 1 {
		if err := l.redis.Expire(ctx, bucketKey, cfg.Window); err != nil {
			l.logger.Warn("Failed to set rate limit expiration")
		}
	}

	// Check if limit exceeded
	allowed := count <= int64(cfg.MaxRequests)

	if !allowed {
		l.logger.Info("Rate limit exceeded")
	}

	return allowed, nil
}

// Reset clears rate limit for a key
func (l *Limiter) Reset(ctx context.Context, key string) error {
	// Delete all keys matching the pattern
	pattern := fmt.Sprintf("ratelimit:%s:*", key)
	return l.redis.Del(ctx, pattern)
}

// DefaultConfigs provides default rate limit configurations for different endpoint types
var DefaultConfigs = map[string]Config{
	"oauth_authorize": {
		MaxRequests: 100,
		Window:      time.Minute,
	},
	"oauth_token": {
		MaxRequests: 50,
		Window:      time.Minute,
	},
	"oauth_callback": {
		MaxRequests: 100,
		Window:      time.Minute,
	},
	"mcp_request": {
		MaxRequests: 1000,
		Window:      time.Minute,
	},
	"default": {
		MaxRequests: 100,
		Window:      time.Minute,
	},
}
