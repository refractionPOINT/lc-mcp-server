package hive

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register external adapter management tools
	RegisterListExternalAdapters()
	RegisterGetExternalAdapter()
	RegisterSetExternalAdapter()
	RegisterDeleteExternalAdapter()
}

// RegisterListExternalAdapters registers the list_external_adapters tool
func RegisterListExternalAdapters() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_external_adapters",
		Description: "List all external adapter configurations",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_external_adapters",
			mcp.WithDescription("List all external adapter configurations"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for external adapters
			hive := lc.NewHiveClient(org)

			// List all external adapters
			adapters, err := hive.List(lc.HiveArgs{
				HiveName:     "external_adapter",
				PartitionKey: "global",
			})
			if err != nil {
				return tools.ErrorResultf("failed to list external adapters: %v", err), nil
			}

			// Convert to response format
			result := make(map[string]interface{})
			for name, data := range adapters {
				result[name] = map[string]interface{}{
					"data":     data.Data,
					"enabled":  data.UsrMtd.Enabled,
					"tags":     data.UsrMtd.Tags,
					"comment":  data.UsrMtd.Comment,
					"metadata": data.SysMtd,
				}
			}

			return tools.SuccessResult(map[string]interface{}{
				"adapters": result,
				"count":    len(result),
			}), nil
		},
	})
}

// RegisterGetExternalAdapter registers the get_external_adapter tool
func RegisterGetExternalAdapter() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_external_adapter",
		Description: "Get a specific external adapter configuration",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_external_adapter",
			mcp.WithDescription("Get a specific external adapter configuration"),
			mcp.WithString("adapter_name",
				mcp.Required(),
				mcp.Description("Name of the adapter to retrieve")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			adapterName, ok := args["adapter_name"].(string)
			if !ok || adapterName == "" {
				return tools.ErrorResult("adapter_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for external adapters
			hive := lc.NewHiveClient(org)

			// Get external adapter
			adapter, err := hive.Get(lc.HiveArgs{
				HiveName:     "external_adapter",
				PartitionKey: "global",
				Key:          adapterName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get external adapter '%s': %v", adapterName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"adapter": map[string]interface{}{
					"name":    adapterName,
					"data":    adapter.Data,
					"enabled": adapter.UsrMtd.Enabled,
					"tags":    adapter.UsrMtd.Tags,
					"comment": adapter.UsrMtd.Comment,
					"metadata": map[string]interface{}{
						"created_at":  adapter.SysMtd.CreatedAt,
						"created_by":  adapter.SysMtd.CreatedBy,
						"last_mod":    adapter.SysMtd.LastMod,
						"last_author": adapter.SysMtd.LastAuthor,
						"guid":        adapter.SysMtd.GUID,
					},
				},
			}), nil
		},
	})
}

// RegisterSetExternalAdapter registers the set_external_adapter tool
func RegisterSetExternalAdapter() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_external_adapter",
		Description: "Create or update an external adapter configuration",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_external_adapter",
			mcp.WithDescription("Create or update an external adapter configuration"),
			mcp.WithString("adapter_name",
				mcp.Required(),
				mcp.Description("Name for the adapter")),
			mcp.WithObject("adapter_config",
				mcp.Required(),
				mcp.Description("Adapter configuration data")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			adapterName, ok := args["adapter_name"].(string)
			if !ok || adapterName == "" {
				return tools.ErrorResult("adapter_name parameter is required"), nil
			}

			adapterConfig, ok := args["adapter_config"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("adapter_config parameter is required and must be an object"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for external adapters
			hive := lc.NewHiveClient(org)

			// Set external adapter
			enabled := true
			_, err = hive.Add(lc.HiveArgs{
				HiveName:     "external_adapter",
				PartitionKey: "global",
				Key:          adapterName,
				Data:         lc.Dict(adapterConfig),
				Enabled:      &enabled,
			})
			if err != nil {
				return tools.ErrorResultf("failed to set external adapter '%s': %v", adapterName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated external adapter '%s'", adapterName),
			}), nil
		},
	})
}

// RegisterDeleteExternalAdapter registers the delete_external_adapter tool
func RegisterDeleteExternalAdapter() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_external_adapter",
		Description: "Delete an external adapter configuration",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_external_adapter",
			mcp.WithDescription("Delete an external adapter configuration"),
			mcp.WithString("adapter_name",
				mcp.Required(),
				mcp.Description("Name of the adapter to delete")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			adapterName, ok := args["adapter_name"].(string)
			if !ok || adapterName == "" {
				return tools.ErrorResult("adapter_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for external adapters
			hive := lc.NewHiveClient(org)

			// Delete external adapter
			_, err = hive.Remove(lc.HiveArgs{
				HiveName:     "external_adapter",
				PartitionKey: "global",
				Key:          adapterName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to delete external adapter '%s': %v", adapterName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted external adapter '%s'", adapterName),
			}), nil
		},
	})
}
