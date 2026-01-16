package config

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register extension management tools
	// Note: Extension configuration (get/set/list/delete_extension_config) uses Hive
	// These tools manage extension subscriptions
	RegisterSubscribeToExtension()
	RegisterUnsubscribeFromExtension()
	RegisterListExtensionSubscriptions()
	RegisterGetExtensionSchema()
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
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			extensionName, ok := args["extension_name"].(string)
			if !ok || extensionName == "" {
				return tools.ErrorResult("extension_name parameter is required"), nil
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
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			extensionName, ok := args["extension_name"].(string)
			if !ok || extensionName == "" {
				return tools.ErrorResult("extension_name parameter is required"), nil
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

// RegisterListExtensionSubscriptions registers the list_extension_subscriptions tool
func RegisterListExtensionSubscriptions() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_extension_subscriptions",
		Description: "List all extension subscriptions for the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_extension_subscriptions",
			mcp.WithDescription("List all extension subscriptions for the organization"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			extensions, err := org.Extensions()
			if err != nil {
				return tools.ErrorResultf("failed to list extension subscriptions: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"subscriptions": extensions,
			}), nil
		},
	})
}

// RegisterGetExtensionSchema registers the get_extension_schema tool
func RegisterGetExtensionSchema() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_extension_schema",
		Description: "Get the configuration schema for an extension",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_extension_schema",
			mcp.WithDescription("Get the configuration schema definition for an extension"),
			mcp.WithString("extension_name",
				mcp.Required(),
				mcp.Description("Name of the extension to get the schema for")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			extensionName, ok := args["extension_name"].(string)
			if !ok || extensionName == "" {
				return tools.ErrorResult("extension_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			schema, err := org.GetExtensionSchema(lc.ExtensionName(extensionName))
			if err != nil {
				return tools.ErrorResultf("failed to get extension schema: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"extension_name": extensionName,
				"schema":         schema,
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
