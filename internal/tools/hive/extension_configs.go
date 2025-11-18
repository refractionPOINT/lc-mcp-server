package hive

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register extension config management tools
	RegisterListExtensionConfigs()
	RegisterGetExtensionConfig()
	RegisterSetExtensionConfig()
	RegisterDeleteExtensionConfig()
}

// RegisterListExtensionConfigs registers the list_extension_configs tool
func RegisterListExtensionConfigs() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_extension_configs",
		Description: "List all extension configurations",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_extension_configs",
			mcp.WithDescription("List all extension configurations"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for extension configs
			hive := lc.NewHiveClient(org)

			// List all extension configs
			configs, err := hive.List(lc.HiveArgs{
				HiveName:     "extension_config",
				PartitionKey: "global",
			})
			if err != nil {
				return tools.ErrorResultf("failed to list extension configs: %v", err), nil
			}

			// Convert to response format
			result := make(map[string]interface{})
			for name, data := range configs {
				result[name] = map[string]interface{}{
					"data":     data.Data,
					"enabled":  data.UsrMtd.Enabled,
					"tags":     data.UsrMtd.Tags,
					"comment":  data.UsrMtd.Comment,
					"metadata": data.SysMtd,
				}
			}

			return tools.SuccessResult(map[string]interface{}{
				"configs": result,
				"count":   len(result),
			}), nil
		},
	})
}

// RegisterGetExtensionConfig registers the get_extension_config tool
func RegisterGetExtensionConfig() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_extension_config",
		Description: "Get a specific extension configuration",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_extension_config",
			mcp.WithDescription("Get a specific extension configuration"),
			mcp.WithString("extension_name",
				mcp.Required(),
				mcp.Description("Name of the extension to retrieve config for")),
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

			// Create hive client for extension configs
			hive := lc.NewHiveClient(org)

			// Get extension config
			config, err := hive.Get(lc.HiveArgs{
				HiveName:     "extension_config",
				PartitionKey: "global",
				Key:          extensionName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get extension config '%s': %v", extensionName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"config": map[string]interface{}{
					"name":    extensionName,
					"data":    config.Data,
					"enabled": config.UsrMtd.Enabled,
					"tags":    config.UsrMtd.Tags,
					"comment": config.UsrMtd.Comment,
					"metadata": map[string]interface{}{
						"created_at":  config.SysMtd.CreatedAt,
						"created_by":  config.SysMtd.CreatedBy,
						"last_mod":    config.SysMtd.LastMod,
						"last_author": config.SysMtd.LastAuthor,
						"guid":        config.SysMtd.GUID,
					},
				},
			}), nil
		},
	})
}

// RegisterSetExtensionConfig registers the set_extension_config tool
func RegisterSetExtensionConfig() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_extension_config",
		Description: "Create or update an extension configuration",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_extension_config",
			mcp.WithDescription("Create or update an extension configuration"),
			mcp.WithString("extension_name",
				mcp.Required(),
				mcp.Description("Name of the extension")),
			mcp.WithObject("config_data",
				mcp.Required(),
				mcp.Description("Extension configuration data")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			extensionName, ok := args["extension_name"].(string)
			if !ok || extensionName == "" {
				return tools.ErrorResult("extension_name parameter is required"), nil
			}

			configData, ok := args["config_data"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("config_data parameter is required and must be an object"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for extension configs
			hive := lc.NewHiveClient(org)

			// Set extension config
			enabled := true
			_, err = hive.Add(lc.HiveArgs{
				HiveName:     "extension_config",
				PartitionKey: "global",
				Key:          extensionName,
				Data:         lc.Dict(configData),
				Enabled:      &enabled,
			})
			if err != nil {
				return tools.ErrorResultf("failed to set extension config '%s': %v", extensionName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated extension config '%s'", extensionName),
			}), nil
		},
	})
}

// RegisterDeleteExtensionConfig registers the delete_extension_config tool
func RegisterDeleteExtensionConfig() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_extension_config",
		Description: "Delete an extension configuration",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_extension_config",
			mcp.WithDescription("Delete an extension configuration"),
			mcp.WithString("extension_name",
				mcp.Required(),
				mcp.Description("Name of the extension config to delete")),
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

			// Create hive client for extension configs
			hive := lc.NewHiveClient(org)

			// Delete extension config
			_, err = hive.Remove(lc.HiveArgs{
				HiveName:     "extension_config",
				PartitionKey: "global",
				Key:          extensionName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to delete extension config '%s': %v", extensionName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted extension config '%s'", extensionName),
			}), nil
		},
	})
}
