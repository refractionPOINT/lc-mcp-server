package tools

import (
	"context"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

// contextKey is a type for context keys to avoid collisions
type contextKey string

const (
	// orgClientKey is the context key for storing OrganizationClient (for testing)
	orgClientKey contextKey = "org-client"
	// clientKey is the context key for storing the raw Client (for testing)
	clientKey contextKey = "lc-client"
)

// GetOrganization retrieves or creates an Organization instance from context
// This is a shared helper used by all tools to get the SDK organization client
func GetOrganization(ctx context.Context) (*lc.Organization, error) {
	cache, err := auth.GetSDKCache(ctx)
	if err != nil {
		return nil, err
	}
	return cache.GetFromContext(ctx)
}

// GetClient retrieves or creates a raw *lc.Client from context.
// This is used for user-level operations like group management that don't require
// an Organization wrapper. Use GetOrganization for org-scoped operations.
func GetClient(ctx context.Context) (*lc.Client, error) {
	// First check if a mock client was injected (for testing)
	if mockClient := ctx.Value(clientKey); mockClient != nil {
		if client, ok := mockClient.(*lc.Client); ok {
			return client, nil
		}
	}

	cache, err := auth.GetSDKCache(ctx)
	if err != nil {
		return nil, err
	}
	return cache.GetClientFromContext(ctx)
}

// WithClient adds a *lc.Client to the context for testing
// This allows tests to inject mock clients without needing SDK credentials
func WithClient(ctx context.Context, client *lc.Client) context.Context {
	return context.WithValue(ctx, clientKey, client)
}

// GetOrganizationClient retrieves an OrganizationClient from context (for testing)
// or falls back to GetOrganization for production code
func GetOrganizationClient(ctx context.Context) (OrganizationClient, error) {
	// First check if a mock organization client was injected (for testing)
	if mockOrg := ctx.Value(orgClientKey); mockOrg != nil {
		if org, ok := mockOrg.(OrganizationClient); ok {
			return org, nil
		}
	}

	// Fall back to real organization
	return GetOrganization(ctx)
}

// WithOrganizationClient adds an OrganizationClient to the context for testing
// This allows tests to inject mock organizations without needing SDK credentials
func WithOrganizationClient(ctx context.Context, org OrganizationClient) context.Context {
	return context.WithValue(ctx, orgClientKey, org)
}
