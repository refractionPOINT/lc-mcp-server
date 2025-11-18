package config

import (
	"context"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// getOrganization retrieves the organization from the context
func getOrganization(ctx context.Context) (*lc.Organization, error) {
	return tools.GetOrganization(ctx)
}
