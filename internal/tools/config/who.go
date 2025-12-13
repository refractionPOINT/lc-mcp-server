package config

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterWhoAmI()
}

// RegisterWhoAmI registers the who_am_i tool
func RegisterWhoAmI() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "who_am_i",
		Description: "Get the current API identity and permissions for the authenticated user or API key",
		Profile:     "core",
		RequiresOID: true, // Need an org context to get the client
		Schema: mcp.NewTool("who_am_i",
			mcp.WithDescription("Get the current API identity and permissions for the authenticated user or API key"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get who am I info via the organization's client
			who, err := org.WhoAmI()
			if err != nil {
				return tools.ErrorResultf("failed to get identity: %v", err), nil
			}

			result := map[string]interface{}{}
			if who.Identity != nil {
				result["ident"] = *who.Identity
			}
			if who.Organizations != nil {
				result["orgs"] = *who.Organizations
			}
			if who.Permissions != nil {
				result["perms"] = *who.Permissions
			}
			if who.UserPermissions != nil {
				result["user_perms"] = *who.UserPermissions
			}

			return tools.SuccessResult(result), nil
		},
	})
}
