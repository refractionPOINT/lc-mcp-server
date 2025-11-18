package config

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register installation key management tools
	RegisterListInstallationKeys()
	RegisterCreateInstallationKey()
	RegisterDeleteInstallationKey()
}

// RegisterListInstallationKeys registers the list_installation_keys tool
func RegisterListInstallationKeys() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_installation_keys",
		Description: "List all installation keys in the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_installation_keys",
			mcp.WithDescription("List all installation keys in the organization"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// List installation keys
			keys, err := org.InstallationKeys()
			if err != nil {
				return tools.ErrorResultf("failed to list installation keys: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"keys":  keys,
				"count": len(keys),
			}), nil
		},
	})
}

// RegisterCreateInstallationKey registers the create_installation_key tool
func RegisterCreateInstallationKey() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "create_installation_key",
		Description: "Create a new installation key for sensor deployment",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("create_installation_key",
			mcp.WithDescription("Create a new installation key for sensor deployment"),
			mcp.WithArray("tags",
				mcp.Required(),
				mcp.Description("Tags to automatically apply to sensors using this key")),
			mcp.WithString("description",
				mcp.Required(),
				mcp.Description("Description of the installation key")),
			mcp.WithNumber("quota",
				mcp.Description("Optional maximum number of sensors that can use this key")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			tagsRaw, ok := args["tags"].([]interface{})
			if !ok {
				return tools.ErrorResult("tags parameter is required and must be an array"), nil
			}

			// Convert to string slice
			tags := make([]string, 0, len(tagsRaw))
			for _, tag := range tagsRaw {
				if tagStr, ok := tag.(string); ok {
					tags = append(tags, tagStr)
				}
			}

			description, ok := args["description"].(string)
			if !ok || description == "" {
				return tools.ErrorResult("description parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Build installation key
			key := lc.InstallationKey{
				Tags:        tags,
				Description: description,
			}

			// Note: quota parameter is not supported by current SDK version
			// The InstallationKey struct doesn't have a Quota field

			// Create installation key
			iid, err := org.AddInstallationKey(key)
			if err != nil {
				return tools.ErrorResultf("failed to create installation key: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created installation key with IID: %s", iid),
				"iid":     iid,
			}), nil
		},
	})
}

// RegisterDeleteInstallationKey registers the delete_installation_key tool
func RegisterDeleteInstallationKey() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_installation_key",
		Description: "Delete an installation key",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_installation_key",
			mcp.WithDescription("Delete an installation key"),
			mcp.WithString("iid",
				mcp.Required(),
				mcp.Description("Installation key ID to delete")),
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

			// Delete installation key
			err = org.DelInstallationKey(iid)
			if err != nil {
				return tools.ErrorResultf("failed to delete installation key: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted installation key '%s'", iid),
			}), nil
		},
	})
}
