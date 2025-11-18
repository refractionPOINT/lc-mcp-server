package gcs

import (
	"context"
)

// contextKey is a private type for context keys
type contextKey int

const (
	// gcsManagerKey is the context key for the GCS manager
	gcsManagerKey contextKey = iota
)

// WithGCSManager adds a GCS manager to the context
func WithGCSManager(ctx context.Context, mgr *Manager) context.Context {
	return context.WithValue(ctx, gcsManagerKey, mgr)
}

// GetGCSManager retrieves the GCS manager from the context
func GetGCSManager(ctx context.Context) *Manager {
	if mgr, ok := ctx.Value(gcsManagerKey).(*Manager); ok {
		return mgr
	}
	return nil
}

// MaybeWrapResult wraps a result using GCS if a manager is available in the context
// This is a convenience function for tools to use
func MaybeWrapResult(ctx context.Context, data interface{}, toolName string) (interface{}, error) {
	mgr := GetGCSManager(ctx)
	if mgr == nil {
		// No GCS manager, return data as-is
		return data, nil
	}

	// Use GCS manager to potentially wrap the result
	return mgr.WrapResult(ctx, data, toolName)
}
