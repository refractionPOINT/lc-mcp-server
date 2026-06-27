package config

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterGetInstallationKey()
}

// RegisterGetInstallationKey registers the get_installation_key tool
func RegisterGetInstallationKey() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_installation_key",
		Description: "Get one installation key by IID",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_installation_key",
			mcp.WithDescription("Get one installation key by IID"),
			mcp.WithString("iid",
				mcp.Required(),
				mcp.Description("Installation key ID to retrieve")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			iid, ok := args["iid"].(string)
			if !ok || iid == "" {
				return tools.ErrorResult("iid parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			key, err := org.InstallationKey(iid)
			if err != nil {
				return tools.ErrorResultf("failed to get installation key '%s': %v", iid, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"key": key,
			}), nil
		},
	})
}
