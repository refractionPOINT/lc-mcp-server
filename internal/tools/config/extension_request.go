package config

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterExtensionRequest()
}

// RegisterExtensionRequest registers the extension_request tool
func RegisterExtensionRequest() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "extension_request",
		Description: "Generic extension action escape-hatch",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("extension_request",
			mcp.WithDescription("Generic extension action escape-hatch"),
			mcp.WithString("extension_name",
				mcp.Required(),
				mcp.Description("Name of the extension to call")),
			mcp.WithString("action",
				mcp.Required(),
				mcp.Description("The extension action to invoke")),
			mcp.WithObject("data",
				mcp.Required(),
				mcp.Description("Action request data")),
			mcp.WithBoolean("impersonate",
				mcp.Description("Whether to impersonate the calling user")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["extension_name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("extension_name parameter is required"), nil
			}
			action, ok := args["action"].(string)
			if !ok || action == "" {
				return tools.ErrorResult("action parameter is required"), nil
			}
			data, ok := args["data"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("data parameter is required and must be an object"), nil
			}
			impersonate := false
			if v, ok := args["impersonate"].(bool); ok {
				impersonate = v
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp := lc.Dict{}
			if err := org.ExtensionRequest(&resp, name, action, lc.Dict(data), impersonate); err != nil {
				return tools.ErrorResultf("failed to call extension '%s' action '%s': %v", name, action, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"response": resp,
			}), nil
		},
	})
}
