package tools

import (
	"context"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
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
