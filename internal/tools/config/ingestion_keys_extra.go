package config

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterListIngestionKeys()
	RegisterCreateIngestionKey()
	RegisterDeleteIngestionKey()
}

// RegisterListIngestionKeys registers the list_ingestion_keys tool
func RegisterListIngestionKeys() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_ingestion_keys",
		Description: "List ingestion keys",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_ingestion_keys",
			mcp.WithDescription("List ingestion keys"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			keys, err := org.GetIngestionKeys()
			if err != nil {
				return tools.ErrorResultf("failed to list ingestion keys: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"keys":  keys,
				"count": len(keys),
			}), nil
		},
	})
}

// RegisterCreateIngestionKey registers the create_ingestion_key tool
func RegisterCreateIngestionKey() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "create_ingestion_key",
		Description: "Create an ingestion key",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("create_ingestion_key",
			mcp.WithDescription("Create an ingestion key"),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name for the ingestion key")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.SetIngestionKeys(name)
			if err != nil {
				return tools.ErrorResultf("failed to create ingestion key '%s': %v", name, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created ingestion key '%s'", name),
				"key":     resp,
			}), nil
		},
	})
}

// RegisterDeleteIngestionKey registers the delete_ingestion_key tool
func RegisterDeleteIngestionKey() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_ingestion_key",
		Description: "Delete an ingestion key",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_ingestion_key",
			mcp.WithDescription("Delete an ingestion key"),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name of the ingestion key to delete")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			if _, err := org.DelIngestionKeys(name); err != nil {
				return tools.ErrorResultf("failed to delete ingestion key '%s': %v", name, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted ingestion key '%s'", name),
			}), nil
		},
	})
}
