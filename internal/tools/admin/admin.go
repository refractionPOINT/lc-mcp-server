package admin

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register all admin/organization management tools
	RegisterGetOrgInfo()
	RegisterGetUsageStats()
	RegisterGetBillingDetails()
	RegisterGetOrgInvoiceURL()
	RegisterGetSKUDefinitions()
	RegisterCreateOrg()
	RegisterListUserOrgs()
	RegisterGetOrgErrors()
	RegisterDismissOrgError()
	RegisterListAPIKeys()
	RegisterCreateAPIKey()
	RegisterDeleteAPIKey()
	RegisterGetMITREReport()
	RegisterGetTimeWhenSensorHasData()
}

// getOrganization retrieves or creates an Organization instance from context
func getOrganization(ctx context.Context) (*lc.Organization, error) {
	cache, err := auth.GetSDKCache(ctx)
	if err != nil {
		return nil, err
	}

	return cache.GetFromContext(ctx)
}

// RegisterGetOrgInfo registers the get_org_info tool
func RegisterGetOrgInfo() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_org_info",
		Description: "Get detailed organization information and configuration",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_org_info",
			mcp.WithDescription("Get detailed organization information and configuration"),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Handle OID switching for UID mode
			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}
			}

			// Get organization
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get organization info
			info, err := org.GetInfo()
			if err != nil {
				return tools.ErrorResultf("failed to get organization info: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"org": info,
			}), nil
		},
	})
}

// RegisterGetUsageStats registers the get_usage_stats tool
func RegisterGetUsageStats() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_usage_stats",
		Description: "Get organization usage statistics",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_usage_stats",
			mcp.WithDescription("Get organization usage statistics"),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
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

			stats, err := org.GetUsageStats()
			if err != nil {
				return tools.ErrorResultf("failed to get usage stats: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"stats": stats,
			}), nil
		},
	})
}

// RegisterGetBillingDetails registers the get_billing_details tool
func RegisterGetBillingDetails() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_billing_details",
		Description: "Get billing information for the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_billing_details",
			mcp.WithDescription("Get billing information for the organization"),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
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

			details, err := org.GetBillingOrgDetails()
			if err != nil {
				return tools.ErrorResultf("failed to get billing details: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"details": details,
			}), nil
		},
	})
}

// RegisterGetOrgInvoiceURL registers the get_org_invoice_url tool
func RegisterGetOrgInvoiceURL() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_org_invoice_url",
		Description: "Get URL to download an organization invoice for a specific month",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_org_invoice_url",
			mcp.WithDescription("Get URL to download an organization invoice for a specific month"),
			mcp.WithNumber("year",
				mcp.Required(),
				mcp.Description("Invoice year (e.g., 2023)")),
			mcp.WithNumber("month",
				mcp.Required(),
				mcp.Description("Invoice month (1-12)")),
			mcp.WithString("format",
				mcp.Description("Optional format parameter for the invoice")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			year, ok := args["year"].(float64)
			if !ok {
				return tools.ErrorResult("year parameter is required and must be a number"), nil
			}

			month, ok := args["month"].(float64)
			if !ok {
				return tools.ErrorResult("month parameter is required and must be a number"), nil
			}

			format := ""
			if f, ok := args["format"].(string); ok {
				format = f
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

			invoiceURL, err := org.GetBillingInvoiceURL(int(year), int(month), format)
			if err != nil {
				return tools.ErrorResultf("failed to get invoice URL: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"url":    invoiceURL.URL,
				"year":   invoiceURL.Year,
				"month":  invoiceURL.Month,
				"format": invoiceURL.Format,
			}), nil
		},
	})
}

// RegisterGetSKUDefinitions registers the get_sku_definitions tool
func RegisterGetSKUDefinitions() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_sku_definitions",
		Description: "Get SKU pricing definitions for the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_sku_definitions",
			mcp.WithDescription("Get SKU pricing definitions for the organization"),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
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

			skus, err := org.GetSKUDefinitions()
			if err != nil {
				return tools.ErrorResultf("failed to get SKU definitions: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"definitions": skus,
			}), nil
		},
	})
}

// RegisterCreateOrg registers the create_org tool
func RegisterCreateOrg() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "create_org",
		Description: "Create a new organization (user-level operation)",
		Profile:     "platform_admin",
		RequiresOID: false,
		Schema: mcp.NewTool("create_org",
			mcp.WithDescription("Create a new organization (user-level operation, does not require OID)"),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name for the new organization")),
			mcp.WithString("location",
				mcp.Required(),
				mcp.Description("Location for the organization (e.g., 'usa', 'europe', 'canada', 'india', 'uk')")),
			mcp.WithString("template",
				mcp.Description("Optional YAML Infrastructure-as-Code template to initialize the organization")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("name parameter is required"), nil
			}

			location, ok := args["location"].(string)
			if !ok || location == "" {
				return tools.ErrorResult("location parameter is required"), nil
			}

			template := ""
			if t, ok := args["template"].(string); ok {
				template = t
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization context: %v", err), nil
			}

			// Create new organization
			newOID, err := org.CreateOrganization(name, location, template)
			if err != nil {
				return tools.ErrorResultf("failed to create organization: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"oid":      newOID,
				"name":     name,
				"location": location,
			}), nil
		},
	})
}

// RegisterListUserOrgs registers the list_user_orgs tool
func RegisterListUserOrgs() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_user_orgs",
		Description: "List all organizations accessible to the authenticated user",
		Profile:     "platform_admin",
		RequiresOID: false,
		Schema: mcp.NewTool("list_user_orgs",
			mcp.WithDescription("List all organizations accessible to the authenticated user (user-level operation)"),
			mcp.WithNumber("offset",
				mcp.Description("Starting index for pagination")),
			mcp.WithNumber("limit",
				mcp.Description("Maximum number of results to return")),
			mcp.WithString("filter",
				mcp.Description("Optional filter string")),
			mcp.WithString("sort_by",
				mcp.Description("Optional field to sort by")),
			mcp.WithString("sort_order",
				mcp.Description("Optional sort order ('asc' or 'desc')")),
			mcp.WithString("with_names",
				mcp.Description("Whether to include organization names (\"true\" or \"false\", default: \"true\")")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			var offset, limit *int
			var filter, sortBy, sortOrder *string

			if o, ok := args["offset"].(float64); ok {
				offsetInt := int(o)
				offset = &offsetInt
			}

			if l, ok := args["limit"].(float64); ok {
				limitInt := int(l)
				limit = &limitInt
			}

			if f, ok := args["filter"].(string); ok && f != "" {
				filter = &f
			}

			if sb, ok := args["sort_by"].(string); ok && sb != "" {
				sortBy = &sb
			}

			if so, ok := args["sort_order"].(string); ok && so != "" {
				sortOrder = &so
			}

			withNames := true
			if wn, ok := args["with_names"].(string); ok {
				withNames = (wn == "true")
			} else if wn, ok := args["with_names"].(bool); ok {
				withNames = wn
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization context: %v", err), nil
			}

			orgs, err := org.ListUserOrgs(offset, limit, filter, sortBy, sortOrder, withNames)
			if err != nil {
				return tools.ErrorResultf("failed to list user organizations: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"orgs": orgs,
			}), nil
		},
	})
}

// RegisterGetOrgErrors registers the get_org_errors tool
func RegisterGetOrgErrors() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_org_errors",
		Description: "Get error logs for the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_org_errors",
			mcp.WithDescription("Get error logs for the organization"),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
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

			errors, err := org.GetOrgErrors()
			if err != nil {
				return tools.ErrorResultf("failed to get org errors: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"errors": errors,
			}), nil
		},
	})
}

// RegisterDismissOrgError registers the dismiss_org_error tool
func RegisterDismissOrgError() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "dismiss_org_error",
		Description: "Dismiss a specific error for the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("dismiss_org_error",
			mcp.WithDescription("Dismiss a specific error for the organization"),
			mcp.WithString("component",
				mcp.Required(),
				mcp.Description("Component name of the error to dismiss")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			component, ok := args["component"].(string)
			if !ok || component == "" {
				return tools.ErrorResult("component parameter is required"), nil
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

			if err := org.DismissOrgError(component); err != nil {
				return tools.ErrorResultf("failed to dismiss org error: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully dismissed error for component: %s", component),
			}), nil
		},
	})
}

// RegisterListAPIKeys registers the list_api_keys tool
func RegisterListAPIKeys() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_api_keys",
		Description: "List all API keys for the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_api_keys",
			mcp.WithDescription("List all API keys for the organization (does not return actual key values)"),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
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

			keys, err := org.GetAPIKeys()
			if err != nil {
				return tools.ErrorResultf("failed to list API keys: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"keys": keys,
			}), nil
		},
	})
}

// RegisterCreateAPIKey registers the create_api_key tool
func RegisterCreateAPIKey() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "create_api_key",
		Description: "Create a new API key for the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("create_api_key",
			mcp.WithDescription("Create a new API key for the organization (key value only shown once)"),
			mcp.WithString("key_name",
				mcp.Required(),
				mcp.Description("Description/name for the API key")),
			mcp.WithArray("permissions",
				mcp.Description("Optional list of permissions for the key")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			keyName, ok := args["key_name"].(string)
			if !ok || keyName == "" {
				return tools.ErrorResult("key_name parameter is required"), nil
			}

			var permissions []string
			if perms, ok := args["permissions"].([]interface{}); ok {
				for _, p := range perms {
					if perm, ok := p.(string); ok {
						permissions = append(permissions, perm)
					}
				}
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

			key, err := org.CreateAPIKey(keyName, permissions)
			if err != nil {
				return tools.ErrorResultf("failed to create API key: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"key":      key.Key,     // Only returned on creation
				"key_hash": key.KeyHash, // Use this to retrieve full key details later
			}), nil
		},
	})
}

// RegisterDeleteAPIKey registers the delete_api_key tool
func RegisterDeleteAPIKey() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_api_key",
		Description: "Delete an API key",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_api_key",
			mcp.WithDescription("Delete an API key by its hash"),
			mcp.WithString("key_hash",
				mcp.Required(),
				mcp.Description("Hash of the API key to delete")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			keyHash, ok := args["key_hash"].(string)
			if !ok || keyHash == "" {
				return tools.ErrorResult("key_hash parameter is required"), nil
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

			if err := org.DeleteAPIKey(keyHash); err != nil {
				return tools.ErrorResultf("failed to delete API key: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted API key with hash: %s", keyHash),
			}), nil
		},
	})
}

// RegisterGetMITREReport registers the get_mitre_report tool
func RegisterGetMITREReport() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_mitre_report",
		Description: "Get MITRE ATT&CK coverage report for the organization",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("get_mitre_report",
			mcp.WithDescription("Get MITRE ATT&CK coverage report showing detection rule coverage"),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
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

			report, err := org.GetMITREReport()
			if err != nil {
				return tools.ErrorResultf("failed to get MITRE report: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"report": report,
			}), nil
		},
	})
}

// RegisterGetTimeWhenSensorHasData registers the get_time_when_sensor_has_data tool
func RegisterGetTimeWhenSensorHasData() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_time_when_sensor_has_data",
		Description: "Get timestamps when a sensor has reported data (max 30 day range)",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("get_time_when_sensor_has_data",
			mcp.WithDescription("Get timeline of when a sensor has reported data within a time range"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithNumber("start",
				mcp.Required(),
				mcp.Description("Start timestamp (Unix seconds)")),
			mcp.WithNumber("end",
				mcp.Required(),
				mcp.Description("End timestamp (Unix seconds)")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			sid, err := tools.ExtractAndValidateSID(args)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			start, ok := args["start"].(float64)
			if !ok {
				return tools.ErrorResult("start parameter is required and must be a number"), nil
			}

			end, ok := args["end"].(float64)
			if !ok {
				return tools.ErrorResult("end parameter is required and must be a number"), nil
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

			timeline, err := org.GetTimeWhenSensorHasData(sid, int64(start), int64(end))
			if err != nil {
				return tools.ErrorResultf("failed to get sensor timeline: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"sid":        timeline.SID,
				"timestamps": timeline.Timestamps,
				"start":      timeline.Start,
				"end":        timeline.End,
			}), nil
		},
	})
}
