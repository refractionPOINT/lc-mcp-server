package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Generation counters order publication of a cached value against its
// invalidation across replicas. A writer reads the generation before it starts
// work, and publishes only if the generation is unchanged; an invalidation
// bumps the generation, so any result computed before it can no longer be
// published. Both steps are single Lua scripts, hence atomic.
//
// Generations are random values, not counters: a counter that expired and was
// recreated would restart at the same numbers, so a writer holding the old
// value could match the new key and publish what was invalidated after it
// read. A fresh random value never repeats.

// publishIfGeneration: KEYS[1] is the generation key, KEYS[2..] the keys to
// write. ARGV[1] is the generation the caller read ("" for absent), ARGV[2] the
// generation key's TTL in ms, ARGV[3] the new generation, then one (value, ttl
// ms) pair per written key. On a match it replaces the generation (so an older
// in-flight writer can't overwrite what was just published) and writes; it
// returns 1, else 0.
var publishIfGeneration = redis.NewScript(`
	local cur = redis.call('GET', KEYS[1])
	if cur == false then cur = '' end
	if cur ~= ARGV[1] then
		return 0
	end
	redis.call('SET', KEYS[1], ARGV[3], 'PX', ARGV[2])
	for i = 2, #KEYS do
		redis.call('SET', KEYS[i], ARGV[2 * i], 'PX', ARGV[2 * i + 1])
	end
	return 1
`)

// bumpGeneration: KEYS[1] is the generation key, KEYS[2..1+ARGV[2]] are deleted
// and any further keys only get their expiry reset to ARGV[3] ms if they
// exist. ARGV[1] is the generation key's TTL in ms, ARGV[4] the new generation.
var bumpGeneration = redis.NewScript(`
	redis.call('SET', KEYS[1], ARGV[4], 'PX', ARGV[1])
	local ndel = tonumber(ARGV[2])
	for i = 2, #KEYS do
		if i <= 1 + ndel then
			redis.call('DEL', KEYS[i])
		else
			redis.call('PEXPIRE', KEYS[i], ARGV[3])
		end
	end
	return 1
`)

// PublishIfGeneration atomically checks that genKey still holds expectedGen
// ("" meaning absent) and, if so, replaces it with a fresh value (with a TTL
// of genTTL) and
// writes keys[i]=values[i] with ttls[i]. It reports whether it wrote.
func (c *Client) PublishIfGeneration(ctx context.Context, genKey, expectedGen string, genTTL time.Duration, keys, values []string, ttls []time.Duration) (bool, error) {
	if len(keys) != len(values) || len(keys) != len(ttls) {
		return false, fmt.Errorf("keys, values and ttls must have the same length")
	}
	if genTTL <= 0 {
		return false, fmt.Errorf("generation ttl must be positive")
	}
	next, err := newGeneration()
	if err != nil {
		return false, err
	}
	argv := []interface{}{expectedGen, genTTL.Milliseconds(), next}
	for i := range keys {
		if ttls[i] <= 0 {
			return false, fmt.Errorf("ttl must be positive")
		}
		argv = append(argv, values[i], ttls[i].Milliseconds())
	}
	n, err := publishIfGeneration.Run(ctx, c.client, append([]string{genKey}, keys...), argv...).Int64()
	return n == 1, err
}

// BumpGeneration atomically replaces genKey with a fresh value (with a TTL of genTTL), deletes
// the del keys and resets the expiry of the touch keys that exist to touchTTL.
func (c *Client) BumpGeneration(ctx context.Context, genKey string, genTTL time.Duration, del, touch []string, touchTTL time.Duration) error {
	if genTTL <= 0 || (len(touch) > 0 && touchTTL <= 0) {
		return fmt.Errorf("ttl must be positive")
	}
	next, err := newGeneration()
	if err != nil {
		return err
	}
	keys := append(append([]string{genKey}, del...), touch...)
	return bumpGeneration.Run(ctx, c.client, keys, genTTL.Milliseconds(), len(del), touchTTL.Milliseconds(), next).Err()
}

// newGeneration returns a fresh, never-repeating generation value.
func newGeneration() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate generation: %w", err)
	}
	return hex.EncodeToString(b), nil
}
