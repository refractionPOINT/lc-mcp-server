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
