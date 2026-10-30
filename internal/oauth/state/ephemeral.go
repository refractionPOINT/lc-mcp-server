package state

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Key prefixes for short-lived data that is not part of the main OAuth state
// machine (client metadata document cache, selection acknowledgements).
const (
	SelectionAckPrefix = "oauth:selack:"
)

// SelectionAckTTL bounds how long a provider-selection acknowledgement stays valid.
const SelectionAckTTL = 5 * time.Minute

// GetEphemeral reads a short-lived value; "" means absent. The caller supplies
// the full key (including its own prefix).
func (m *Manager) GetEphemeral(ctx context.Context, key string) (string, error) {
	return m.redis.Get(ctx, key)
}

// SetEphemeral stores a short-lived value. ttl must be positive.
func (m *Manager) SetEphemeral(ctx context.Context, key, value string, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("ephemeral values require a positive ttl")
	}
	return m.redis.Set(ctx, key, value, ttl)
}

// ConsumeEphemeral atomically reads and deletes a short-lived value.
func (m *Manager) ConsumeEphemeral(ctx context.Context, key string) (string, error) {
	return m.redis.AtomicGetAndDelete(ctx, key)
}

// IncrEphemeral increments a counter whose window starts when it is created.
// The increment and the expiry are applied atomically, so a counter can never
// be left without a TTL.
func (m *Manager) IncrEphemeral(ctx context.Context, key string, window time.Duration) (int64, error) {
	return m.redis.IncrWithWindow(ctx, key, window)
}

// GetSelectionSession reads a provider-selection session without consuming it
// (used to render the page; the session is consumed when a provider is picked).
func (m *Manager) GetSelectionSession(ctx context.Context, sessionID string) (map[string]string, error) {
	data, err := m.redis.Get(ctx, SelectionPrefix+sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get selection session: %w", err)
	}
	if data == "" {
		return nil, nil
	}
	var params map[string]string
	if err := json.Unmarshal([]byte(data), &params); err != nil {
		return nil, fmt.Errorf("failed to unmarshal selection session: %w", err)
	}
	return params, nil
}
