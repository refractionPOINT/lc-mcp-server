package config

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterGetOrgURLs()
}

// RegisterGetOrgURLs registers the get_org_urls tool
func RegisterGetOrgURLs() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_org_urls",
		Description: "Get organization URLs including geo-dependent domains for webhooks, DNS, and API endpoints",
		Profile:     "fleet_management",
		RequiresOID: true,
		Schema: mcp.NewTool("get_org_urls",
			mcp.WithDescription("Get organization URLs including geo-dependent domains for webhooks, DNS, and API endpoints"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get organization URLs
			urls, err := org.GetURLs()
			if err != nil {
				return tools.ErrorResultf("failed to get organization URLs: %v", err), nil
			}

			return tools.SuccessResult(urls), nil
		},
	})
}
