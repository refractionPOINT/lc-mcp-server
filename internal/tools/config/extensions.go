package config

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register extension management tools
	// Note: Extension configuration (get/set/list/delete_extension_config) uses Hive
	// These tools manage extension subscriptions
	RegisterSubscribeToExtension()
	RegisterUnsubscribeFromExtension()
}

// RegisterSubscribeToExtension registers the subscribe_to_extension tool
func RegisterSubscribeToExtension() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "subscribe_to_extension",
		Description: "Subscribe to an extension",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("subscribe_to_extension",
			mcp.WithDescription("Subscribe to an extension"),
			mcp.WithString("extension_name",
				mcp.Required(),
				mcp.Description("Name of the extension to subscribe to")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			extensionName, ok := args["extension_name"].(string)
			if !ok || extensionName == "" {
				return tools.ErrorResult("extension_name parameter is required"), nil
			}

			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Subscribe to extension
			err = org.SubscribeToExtension(lc.ExtensionName(extensionName))
			if err != nil {
				return tools.ErrorResultf("failed to subscribe to extension: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully subscribed to extension '%s'", extensionName),
			}), nil
		},
	})
}

// RegisterUnsubscribeFromExtension registers the unsubscribe_from_extension tool
func RegisterUnsubscribeFromExtension() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "unsubscribe_from_extension",
		Description: "Unsubscribe from an extension",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("unsubscribe_from_extension",
			mcp.WithDescription("Unsubscribe from an extension"),
			mcp.WithString("extension_name",
				mcp.Required(),
				mcp.Description("Name of the extension to unsubscribe from")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			extensionName, ok := args["extension_name"].(string)
			if !ok || extensionName == "" {
				return tools.ErrorResult("extension_name parameter is required"), nil
			}

			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Unsubscribe from extension
			err = org.UnsubscribeFromExtension(lc.ExtensionName(extensionName))
			if err != nil {
				return tools.ErrorResultf("failed to unsubscribe from extension: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully unsubscribed from extension '%s'", extensionName),
			}), nil
		},
	})
}

// Note: The following tools would use Hive with "ext-config" partition:
// - list_extension_configs
// - get_extension_config
// - set_extension_config
// - delete_extension_config
// These are deferred as they require understanding of extension-specific configuration schemas
