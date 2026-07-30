package config

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
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
	RegisterSetOrgDescription()
	RegisterGetOrgDeleteConfirmation()
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
			mcp.WithDescription("Rename the organization, optionally setting its description at the same time"),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The new name for the organization")),
			mcp.WithString("description",
				mcp.Description("Optional new description for the organization. Omit to leave the description unchanged; an empty string is ignored by the backend and does not clear it.")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("name parameter is required"), nil
			}

			description, hasDescription := args["description"]
			descriptionStr := ""
			if hasDescription && description != nil {
				descriptionStr, ok = description.(string)
				if !ok {
					return tools.ErrorResult("description parameter must be a string"), nil
				}
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp, err := renameOrg(org, name, descriptionStr)
			if err != nil {
				return tools.ErrorResultf("failed to rename org: %v", err), nil
			}

			result := map[string]interface{}{
				"success":  true,
				"message":  fmt.Sprintf("Successfully renamed organization to '%s'", name),
				"response": resp,
			}
			if descriptionStr != "" {
				result["description"] = descriptionStr
			}
			return tools.SuccessResult(result), nil
		},
	})
}

// renameOrg submits the org rename, carrying the description when one is given.
// The SDK's RenameOrg drops the description, so the route is called directly;
// it takes form/query params, not a JSON body.
func renameOrg(org *lc.Organization, name, description string) (lc.Dict, error) {
	req := lc.Dict{"name": name}
	if description != "" {
		req["description"] = description
	}
	resp := lc.Dict{}
	if err := org.GenericPOSTRequest(fmt.Sprintf("orgs/%s/name", org.GetOID()), req, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// RegisterSetOrgDescription registers the set_org_description tool
func RegisterSetOrgDescription() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_org_description",
		Description: "Set the organization's description",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_org_description",
			mcp.WithDescription("Set the organization's description. The backend only exposes the description through the rename endpoint, so this re-submits the organization's current name unchanged."),
			mcp.WithString("description",
				mcp.Required(),
				mcp.Description("New description for the organization. An empty string is accepted but the backend ignores it, leaving the existing description in place.")),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			description, ok := args["description"].(string)
			if !ok {
				return tools.ErrorResult("description parameter is required and must be a string"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// The rename endpoint rejects an empty name, so the current one has
			// to be resolved rather than guessed.
			info, err := org.GetInfo()
			if err != nil {
				return tools.ErrorResultf("failed to resolve the current organization name: %v", err), nil
			}
			if info.Name == "" {
				return tools.ErrorResult("could not resolve the current organization name, which the description update requires"), nil
			}

			resp, err := renameOrg(org, info.Name, description)
			if err != nil {
				return tools.ErrorResultf("failed to set org description: %v", err), nil
			}

			result := map[string]interface{}{
				"success":     true,
				"name":        info.Name,
				"description": description,
				"message":     fmt.Sprintf("Successfully set the description of organization '%s'", info.Name),
				"response":    resp,
			}
			if description == "" {
				result["note"] = "an empty description is ignored by the backend; the existing description is unchanged"
			}
			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterGetOrgDeleteConfirmation registers the get_org_delete_confirmation tool
func RegisterGetOrgDeleteConfirmation() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_org_delete_confirmation",
		Description: "Mint the confirmation token required by delete_org",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_org_delete_confirmation",
			mcp.WithDescription("Mint the confirmation token delete_org requires. The token expires after 60 seconds and is only valid on the gateway region that minted it, so call delete_org immediately after — a token minted outside this MCP server (e.g. via the REST API from another machine) will NOT work."),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			token, err := org.GetDeleteConfirmationToken()
			if err != nil {
				return tools.ErrorResultf("failed to get delete confirmation token: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"confirmation_token": token,
				"expires_in_seconds": 60,
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
				mcp.Description("Confirmation token from get_org_delete_confirmation, minted less than 60 seconds ago")),
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
