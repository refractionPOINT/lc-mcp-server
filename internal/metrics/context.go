package metrics

import "context"

// contextKey is an unexported type for context keys to prevent collisions
type contextKey string

const metricsManagerKey contextKey = "metrics_manager"

// WithManager adds a metrics Manager to the context
func WithManager(ctx context.Context, mgr *Manager) context.Context {
	return context.WithValue(ctx, metricsManagerKey, mgr)
}

// GetManager retrieves the metrics Manager from the context
// Returns nil if no manager is found
func GetManager(ctx context.Context) *Manager {
	if mgr, ok := ctx.Value(metricsManagerKey).(*Manager); ok {
		return mgr
	}
	return nil
}
