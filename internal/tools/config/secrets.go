package config

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register secret management tools
	RegisterListSecrets()
	RegisterGetSecret()
	RegisterSetSecret()
	RegisterDeleteSecret()
}

// RegisterListSecrets registers the list_secrets tool
func RegisterListSecrets() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_secrets",
		Description: "List all secret names (not values) in the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_secrets",
			mcp.WithDescription("List all secret names (not values) in the organization"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for secrets
			hive := lc.NewHiveClient(org)

			// List all secrets from the secret hive
			secrets, err := hive.List(lc.HiveArgs{
				HiveName:     "secret",
				PartitionKey: "global",
			})
			if err != nil {
				return tools.ErrorResultf("failed to list secrets: %v", err), nil
			}

			// Extract secret names (keys only, not values)
			secretNames := make([]string, 0, len(secrets))
			for name := range secrets {
				secretNames = append(secretNames, name)
			}

			return tools.SuccessResult(map[string]interface{}{
				"secrets": secretNames,
				"count":   len(secretNames),
			}), nil
		},
	})
}

// RegisterGetSecret registers the get_secret tool
func RegisterGetSecret() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_secret",
		Description: "Get a secret value (use with caution)",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_secret",
			mcp.WithDescription("Get a secret value (use with caution)"),
			mcp.WithString("secret_name",
				mcp.Required(),
				mcp.Description("Name of the secret to retrieve")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			secretName, ok := args["secret_name"].(string)
			if !ok || secretName == "" {
				return tools.ErrorResult("secret_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for secrets
			hive := lc.NewHiveClient(org)

			// Get secret value
			secret, err := hive.Get(lc.HiveArgs{
				HiveName:     "secret",
				PartitionKey: "global",
				Key:          secretName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get secret '%s': %v", secretName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"secret": map[string]interface{}{
					"name":  secretName,
					"value": secret.Data,
					"metadata": map[string]interface{}{
						"created_at":  secret.SysMtd.CreatedAt,
						"created_by":  secret.SysMtd.CreatedBy,
						"last_mod":    secret.SysMtd.LastMod,
						"last_author": secret.SysMtd.LastAuthor,
					},
				},
			}), nil
		},
	})
}

// RegisterSetSecret registers the set_secret tool
func RegisterSetSecret() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_secret",
		Description: "Store a secret securely",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_secret",
			mcp.WithDescription("Store a secret securely"),
			mcp.WithString("secret_name",
				mcp.Required(),
				mcp.Description("Name for the secret")),
			mcp.WithString("secret_value",
				mcp.Required(),
				mcp.Description("The secret value to store")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			secretName, ok := args["secret_name"].(string)
			if !ok || secretName == "" {
				return tools.ErrorResult("secret_name parameter is required"), nil
			}

			secretValue, ok := args["secret_value"].(string)
			if !ok || secretValue == "" {
				return tools.ErrorResult("secret_value parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for secrets
			hive := lc.NewHiveClient(org)

			// Set secret value
			enabled := true
			_, err = hive.Add(lc.HiveArgs{
				HiveName:     "secret",
				PartitionKey: "global",
				Key:          secretName,
				Data: lc.Dict{
					"value": secretValue,
				},
				Enabled: &enabled,
			})
			if err != nil {
				return tools.ErrorResultf("failed to set secret '%s': %v", secretName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully stored secret '%s'", secretName),
			}), nil
		},
	})
}

// RegisterDeleteSecret registers the delete_secret tool
func RegisterDeleteSecret() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_secret",
		Description: "Delete a secret",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_secret",
			mcp.WithDescription("Delete a secret"),
			mcp.WithString("secret_name",
				mcp.Required(),
				mcp.Description("Name of the secret to delete")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			secretName, ok := args["secret_name"].(string)
			if !ok || secretName == "" {
				return tools.ErrorResult("secret_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client for secrets
			hive := lc.NewHiveClient(org)

			// Delete secret
			_, err = hive.Remove(lc.HiveArgs{
				HiveName:     "secret",
				PartitionKey: "global",
				Key:          secretName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to delete secret '%s': %v", secretName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted secret '%s'", secretName),
			}), nil
		},
	})
}
