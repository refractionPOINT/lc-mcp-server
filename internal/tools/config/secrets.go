package config

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/hive"
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
			mcp.WithDescription("List secret names (not values) in the organization, one page at a time"),
			hive.WithListPagingParams(),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			listReq, err := hive.ParseListArgs(args, true)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Names only: the records are listed metadata-only, so the backend
			// never loads the secret values.
			names, next, err := hive.ListNames(hive.NewClient(org), "secret", org.GetOID(), listReq)
			if err != nil {
				return tools.ErrorResultf("failed to list secrets: %v", err), nil
			}

			resp := map[string]interface{}{
				"secrets":  names,
				"count":    len(names),
				"has_more": next != "",
			}
			if next != "" {
				resp["next_cursor"] = next
			}
			return tools.SuccessResult(resp), nil
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
			mcp.WithReadOnlyHintAnnotation(true),
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
			client := hive.NewClient(org)

			// Get secret value
			secret, err := client.Get(lc.HiveArgs{
				HiveName:     "secret",
				PartitionKey: org.GetOID(),
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
			mcp.WithDescription("Store a secret securely. Updating an existing secret preserves its metadata (enabled state, tags, comment) unless enabled/tags/comment are given."),
			mcp.WithString("secret_name",
				mcp.Required(),
				mcp.Description("Name for the secret")),
			mcp.WithString("secret_value",
				mcp.Required(),
				mcp.Description("The secret value to store")),
			hive.WithMetadataOverrideParams(),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
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

			overrides, err := hive.ParseMetadataOverrides(args)
			if err != nil {
				return tools.ErrorResultf("%v", err), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			warning, err := hive.SetRecord(org, hive.RecordWrite{
				HiveName: "secret",
				Key:      secretName,
				Data: lc.Dict{
					"secret": secretValue,
				},
				Overrides: overrides,
			})
			if err != nil {
				return tools.ErrorResultf("failed to set secret '%s': %v", secretName, err), nil
			}

			result := map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully stored secret '%s'", secretName),
			}
			if warning != "" {
				result["warning"] = warning
			}
			return tools.SuccessResult(result), nil
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
			mcp.WithDestructiveHintAnnotation(true),
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
			client := hive.NewClient(org)

			// Delete secret
			_, err = client.Remove(lc.HiveArgs{
				HiveName:     "secret",
				PartitionKey: org.GetOID(),
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
