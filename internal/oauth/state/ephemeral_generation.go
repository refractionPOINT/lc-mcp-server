package state

import (
	"context"
	"time"
)

// PublishDocIfGeneration writes docKey (and, when knownKey is not empty,
// knownKey) only if genKey still holds expectedGen, bumping genKey in the same
// atomic step. It reports whether it wrote. See redis.Client.PublishIfGeneration.
func (m *Manager) PublishDocIfGeneration(ctx context.Context, genKey, expectedGen string, genTTL time.Duration,
	docKey, doc string, docTTL time.Duration, knownKey string, knownTTL time.Duration) (bool, error) {
	keys, values, ttls := []string{docKey}, []string{doc}, []time.Duration{docTTL}
	if knownKey != "" {
		keys, values, ttls = append(keys, knownKey), append(values, "1"), append(ttls, knownTTL)
	}
	return m.redis.PublishIfGeneration(ctx, genKey, expectedGen, genTTL, keys, values, ttls)
}

// InvalidateDoc atomically bumps genKey and deletes docKey. knownKey is deleted
// too when dropKnown is set, otherwise its expiry is reset to knownTTL if it
// exists.
func (m *Manager) InvalidateDoc(ctx context.Context, genKey string, genTTL time.Duration,
	docKey, knownKey string, dropKnown bool, knownTTL time.Duration) error {
	if dropKnown {
		return m.redis.BumpGeneration(ctx, genKey, genTTL, []string{docKey, knownKey}, nil, 0)
	}
	return m.redis.BumpGeneration(ctx, genKey, genTTL, []string{docKey}, []string{knownKey}, knownTTL)
}
