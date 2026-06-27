package config

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterGetQuotaUsage()
	RegisterSetOrgQuota()
	RegisterGetBillingStatus()
	RegisterListBillingPlans()
	RegisterGetOrgValue()
	RegisterSetOrgValue()
	RegisterRenameOrg()
	RegisterDeleteOrg()
	RegisterResolveARL()
	RegisterListAvailableExtensions()
	RegisterReKeyExtension()
}

// RegisterGetQuotaUsage registers the get_quota_usage tool
func RegisterGetQuotaUsage() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_quota_usage",
		Description: "Get enforced/weighted quota usage",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_quota_usage",
			mcp.WithDescription("Get enforced/weighted quota usage"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			usage, err := org.GetQuotaUsage()
			if err != nil {
				return tools.ErrorResultf("failed to get quota usage: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"usage": usage,
			}), nil
		},
	})
}

// RegisterSetOrgQuota registers the set_org_quota tool
func RegisterSetOrgQuota() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_org_quota",
		Description: "Set the org sensor quota",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_org_quota",
			mcp.WithDescription("Set the org sensor quota"),
			mcp.WithNumber("quota",
				mcp.Required(),
				mcp.Description("The new sensor quota for the organization")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			quotaRaw, ok := args["quota"].(float64)
			if !ok {
				return tools.ErrorResult("quota parameter is required and must be a number"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			success, err := org.SetQuota(int64(quotaRaw))
			if err != nil {
				return tools.ErrorResultf("failed to set org quota: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": success,
				"quota":   int64(quotaRaw),
			}), nil
		},
	})
}

// RegisterGetBillingStatus registers the get_billing_status tool
func RegisterGetBillingStatus() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_billing_status",
		Description: "Get high-level billing status",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_billing_status",
			mcp.WithDescription("Get high-level billing status"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			status, err := org.GetBillingOrgStatus()
			if err != nil {
				return tools.ErrorResultf("failed to get billing status: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"status": status,
			}), nil
		},
	})
}

// RegisterListBillingPlans registers the list_billing_plans tool
func RegisterListBillingPlans() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_billing_plans",
		Description: "List available billing plans",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_billing_plans",
			mcp.WithDescription("List available billing plans"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			plans, err := org.GetBillingAvailablePlans()
			if err != nil {
				return tools.ErrorResultf("failed to list billing plans: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"plans": plans,
				"count": len(plans),
			}), nil
		},
	})
}

// RegisterGetOrgValue registers the get_org_value tool
func RegisterGetOrgValue() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_org_value",
		Description: "Get an org config value",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_org_value",
			mcp.WithDescription("Get an org config value"),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name of the org config value to retrieve")),
			mcp.WithReadOnlyHintAnnotation(true),
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

			info, err := org.OrgValueGet(name)
			if err != nil {
				return tools.ErrorResultf("failed to get org value '%s': %v", name, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"name":  info.Name,
				"value": info.Value,
			}), nil
		},
	})
}

// RegisterSetOrgValue registers the set_org_value tool
func RegisterSetOrgValue() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_org_value",
		Description: "Set an org config value",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_org_value",
			mcp.WithDescription("Set an org config value"),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name of the org config value to set")),
			mcp.WithString("value",
				mcp.Required(),
				mcp.Description("The value to set")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("name parameter is required"), nil
			}
			value, ok := args["value"].(string)
			if !ok {
				return tools.ErrorResult("value parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			if err := org.OrgValueSet(name, value); err != nil {
				return tools.ErrorResultf("failed to set org value '%s': %v", name, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully set org value '%s'", name),
			}), nil
		},
	})
}

// RegisterRenameOrg registers the rename_org tool
func RegisterRenameOrg() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "rename_org",
		Description: "Rename the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("rename_org",
			mcp.WithDescription("Rename the organization"),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The new name for the organization")),
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

			resp, err := org.RenameOrg(name)
			if err != nil {
				return tools.ErrorResultf("failed to rename org: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":  true,
				"message":  fmt.Sprintf("Successfully renamed organization to '%s'", name),
				"response": resp,
			}), nil
		},
	})
}

// RegisterDeleteOrg registers the delete_org tool
func RegisterDeleteOrg() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_org",
		Description: "Delete the organization (token flow)",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_org",
			mcp.WithDescription("Delete the organization (token flow)"),
			mcp.WithString("confirmation_token",
				mcp.Required(),
				mcp.Description("Confirmation token obtained from the delete-confirmation flow")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			token, ok := args["confirmation_token"].(string)
			if !ok || token == "" {
				return tools.ErrorResult("confirmation_token parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			success, err := org.DeleteOrganization(token)
			if err != nil {
				return tools.ErrorResultf("failed to delete organization: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": success,
			}), nil
		},
	})
}

// RegisterResolveARL registers the resolve_arl tool
func RegisterResolveARL() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "resolve_arl",
		Description: "Resolve an Authentication Resource Locator",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("resolve_arl",
			mcp.WithDescription("Resolve an Authentication Resource Locator"),
			mcp.WithString("arl",
				mcp.Required(),
				mcp.Description("The ARL (Authenticated Resource Locator) to resolve")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			arl, ok := args["arl"].(string)
			if !ok || arl == "" {
				return tools.ErrorResult("arl parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := org.ResolveARL(arl)
			if err != nil {
				return tools.ErrorResultf("failed to resolve ARL: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"result": resp,
			}), nil
		},
	})
}

// RegisterListAvailableExtensions registers the list_available_extensions tool
func RegisterListAvailableExtensions() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_available_extensions",
		Description: "List available extension definitions",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_available_extensions",
			mcp.WithDescription("List available extension definitions"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			extensions, err := org.ListAvailableExtensions()
			if err != nil {
				return tools.ErrorResultf("failed to list available extensions: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"extensions": extensions,
			}), nil
		},
	})
}

// RegisterReKeyExtension registers the rekey_extension tool
func RegisterReKeyExtension() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "rekey_extension",
		Description: "Rotate an extension's secret key",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("rekey_extension",
			mcp.WithDescription("Rotate an extension's secret key"),
			mcp.WithString("extension_name",
				mcp.Required(),
				mcp.Description("Name of the extension to re-key")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["extension_name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("extension_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			if err := org.ReKeyExtension(name); err != nil {
				return tools.ErrorResultf("failed to re-key extension '%s': %v", name, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully re-keyed extension '%s'", name),
			}), nil
		},
	})
}
