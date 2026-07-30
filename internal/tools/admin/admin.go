package admin

import (
	"context"
	"fmt"
	"net"
	"strings"

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
	RegisterCreateOrg()
	RegisterListUserOrgs()
	RegisterGetOrgOIDByName()
	RegisterGetOrgErrors()
	RegisterDismissOrgError()
	RegisterListAPIKeys()
	RegisterCreateAPIKey()
	RegisterDeleteAPIKey()
	RegisterGetMITREReport()
	// Note: get_time_when_sensor_has_data is registered in historical/historical.go
	RegisterGetSKUDefinitions()
	RegisterUpgradeSensors()
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
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {

			// Get organization
			org, err := tools.GetOrganization(ctx)
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
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
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
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
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
			mcp.WithReadOnlyHintAnnotation(true),
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

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			invoiceURL, err := org.GetBillingInvoiceURL(int(year), int(month), format)
			if err != nil {
				return tools.ErrorResultf("failed to get invoice URL: %v", err), nil
			}

			// Add year, month, format for convenience
			result := make(map[string]interface{})
			for k, v := range invoiceURL {
				result[k] = v
			}
			result["year"] = int(year)
			result["month"] = int(month)
			if format != "" {
				result["format"] = format
			}

			return tools.SuccessResult(result), nil
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
			mcp.WithDescription("Create a new organization (user-level operation, does not require OID). NOT idempotent: on a timeout the org may still have been created — check with list_user_orgs before retrying."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name for the new organization")),
			mcp.WithString("location",
				mcp.Required(),
				mcp.Description("Datacenter for the organization: 'usa', 'europe', 'canada', 'india', 'uk', 'australia', or 'auto' for the closest region")),
			mcp.WithString("description",
				mcp.Description("Optional description for the organization")),
			mcp.WithString("template",
				mcp.Description("Optional YAML Infrastructure-as-Code template to initialize the organization")),
			mcp.WithDestructiveHintAnnotation(false),
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

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization context: %v", err), nil
			}

			// POST /v1/orgs/new directly rather than through the SDK's
			// CreateOrganization, which cannot carry "description" and discards the
			// organization code and resolved location from the response.
			form := lc.Dict{
				"name": name,
				"loc":  location,
			}
			if t, ok := args["template"].(string); ok && t != "" {
				form["template"] = t
			}
			if d, ok := args["description"].(string); ok && d != "" {
				form["description"] = d
			}

			var resp struct {
				Success bool `json:"success"`
				Data    struct {
					OID      string `json:"oid"`
					Code     string `json:"code"`
					Location string `json:"loc"`
				} `json:"data"`
			}
			if err := org.GenericPOSTRequest("orgs/new", form, &resp); err != nil {
				return tools.ErrorResultf("failed to create organization: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"oid":      resp.Data.OID,
				"code":     resp.Data.Code,
				"location": resp.Data.Location,
				"name":     name,
			}), nil
		},
	})
}

// SimpleOrgInfo contains simplified organization information for list_user_orgs response
type SimpleOrgInfo struct {
	OID         string `json:"oid"`
	Name        string `json:"name"`
	Description string `json:"description"`
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
			mcp.WithString("filter",
				mcp.Description("Optional filter string")),
			mcp.WithString("sort_by",
				mcp.Description("Optional field to sort by")),
			mcp.WithString("sort_order",
				mcp.Description("Optional sort order ('asc' or 'desc')")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			var filter, sortBy, sortOrder *string

			if f, ok := args["filter"].(string); ok && f != "" {
				filter = &f
			}

			if sb, ok := args["sort_by"].(string); ok && sb != "" {
				sortBy = &sb
			}

			if so, ok := args["sort_order"].(string); ok && so != "" {
				sortOrder = &so
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization context: %v", err), nil
			}

			// Fetch all organizations using pagination
			// Use a reasonable page size for API efficiency
			pageSize := 100
			offset := 0
			allOrgs := []lc.UserOrgInfo{}

			for {
				opts := lc.ListUserOrgsOptions{
					Offset: offset,
					Limit:  pageSize,
					Fields: []string{"oid", "name", "description"},
				}
				if filter != nil {
					opts.Filter = *filter
				}
				if sortBy != nil {
					opts.SortBy = *sortBy
				}
				if sortOrder != nil {
					opts.SortOrder = *sortOrder
				}

				orgs, _, err := org.ListUserOrgsWithOptions(opts)
				if err != nil {
					return tools.ErrorResultf("failed to list user organizations: %v", err), nil
				}

				allOrgs = append(allOrgs, orgs...)

				// If we got fewer results than the page size, we've reached the last page
				if len(orgs) < pageSize {
					break
				}

				// Move to next page
				offset += pageSize
			}

			// Transform to simplified response with only oid, name, description
			simpleOrgs := make([]SimpleOrgInfo, len(allOrgs))
			for i, org := range allOrgs {
				simpleOrgs[i] = SimpleOrgInfo{
					OID:         org.OID,
					Name:        org.Name,
					Description: org.Description,
				}
			}

			return tools.SuccessResult(map[string]interface{}{
				"orgs":  simpleOrgs,
				"count": len(simpleOrgs),
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
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
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
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			component, ok := args["component"].(string)
			if !ok || component == "" {
				return tools.ErrorResult("component parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
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
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
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
				mcp.Description("Description/name for the API key. May not contain '@'.")),
			mcp.WithArray("permissions",
				mcp.Required(),
				mcp.Description("List of permissions granted to the key (e.g., 'sensor.get', 'dr.list'). At least one is required; the API rejects keys without permissions and silently drops permissions that are deprecated or not user-assignable.")),
			mcp.WithString("allowed_ip_range",
				mcp.Description("Optional IP range in CIDR notation to restrict key usage (e.g., '192.168.1.0/24'). Must parse as CIDR.")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			keyName, ok := args["key_name"].(string)
			if !ok || keyName == "" {
				return tools.ErrorResult("key_name parameter is required"), nil
			}
			if strings.Contains(keyName, "@") {
				return tools.ErrorResult("key_name may not contain '@'"), nil
			}

			var permissions []string
			if perms, ok := args["permissions"].([]interface{}); ok {
				for _, p := range perms {
					if perm, ok := p.(string); ok && perm != "" {
						permissions = append(permissions, perm)
					}
				}
			}
			if len(permissions) == 0 {
				return tools.ErrorResult("permissions parameter is required and must contain at least one permission"), nil
			}

			allowedIPRange := ""
			if ipRange, ok := args["allowed_ip_range"].(string); ok {
				allowedIPRange = ipRange
			}
			if allowedIPRange != "" {
				if _, _, err := net.ParseCIDR(allowedIPRange); err != nil {
					return tools.ErrorResultf("allowed_ip_range must be valid CIDR notation: %v", err), nil
				}
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			key, err := org.CreateAPIKeyWithOptions(keyName, permissions, allowedIPRange)
			if err != nil {
				return tools.ErrorResultf("failed to create API key: %v", err), nil
			}

			result := map[string]interface{}{
				"key":      key.Key,     // Only returned on creation
				"key_hash": key.KeyHash, // Use this to retrieve full key details later
				"key_name": keyName,
			}
			if allowedIPRange != "" {
				result["allowed_ip_range"] = allowedIPRange
			}

			return tools.SuccessResult(result), nil
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
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			keyHash, ok := args["key_hash"].(string)
			if !ok || keyHash == "" {
				return tools.ErrorResult("key_hash parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
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
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
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

// Note: RegisterGetTimeWhenSensorHasData has been moved to historical/historical.go
// to avoid duplicate registration

// RegisterGetSKUDefinitions registers the get_sku_definitions tool
func RegisterGetSKUDefinitions() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_sku_definitions",
		Description: "Get SKU definitions and pricing information",
		Profile:     "platform_admin",
		RequiresOID: true, // The SKU route is org-scoped and authorizes org.get against the OID
		Schema: mcp.NewTool("get_sku_definitions",
			mcp.WithDescription("Get SKU definitions and pricing information for the organization"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			skus, err := org.GetBillingSkuDefinitions()
			if err != nil {
				return tools.ErrorResultf("failed to get SKU definitions: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"skus": skus,
			}), nil
		},
	})
}

// RegisterUpgradeSensors registers the upgrade_sensors tool
func RegisterUpgradeSensors() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "upgrade_sensors",
		Description: "Upgrade all sensors in an organization to a specific version or the latest, downgrade to the stable/fallback version, or set to dormant mode",
		Profile:     "fleet_management",
		RequiresOID: true,
		Schema: mcp.NewTool("upgrade_sensors",
			mcp.WithDescription("Update the sensor version for the organization. Supports upgrading to a specific version or to the latest, downgrading to the stable/fallback version, or setting sensors to dormant mode. Exactly one of version, to_latest, is_fallback or is_sleep must be provided."),
			mcp.WithString("version",
				mcp.Description("Target sensor version as a semantic version, e.g. '4.33.20'. Version labels are not accepted: the value is turned into a package filename server-side, so a non-existent version fails at download. Mutually exclusive with to_latest, is_fallback and is_sleep.")),
			mcp.WithBoolean("to_latest",
				mcp.Description("If true, upgrade to the current latest sensor version. Mutually exclusive with version, is_fallback and is_sleep.")),
			mcp.WithBoolean("is_fallback",
				mcp.Description("If true, move sensors to the stable/fallback version (a downgrade from latest). Mutually exclusive with version, to_latest and is_sleep.")),
			mcp.WithBoolean("is_sleep",
				mcp.Description("If true, move sensors to dormant mode. Mutually exclusive with version, to_latest and is_fallback.")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Get parameters
			version, _ := args["version"].(string)
			toLatest, _ := args["to_latest"].(bool)
			isFallback, _ := args["is_fallback"].(bool)
			isSleep, _ := args["is_sleep"].(bool)

			// Validate that exactly one parameter is provided
			providedCount := 0
			if version != "" {
				providedCount++
			}
			if toLatest {
				providedCount++
			}
			if isFallback {
				providedCount++
			}
			if isSleep {
				providedCount++
			}

			if providedCount == 0 {
				return tools.ErrorResult("one of 'version', 'to_latest', 'is_fallback', or 'is_sleep' must be provided"), nil
			}
			if providedCount > 1 {
				return tools.ErrorResult("only one of 'version', 'to_latest', 'is_fallback', or 'is_sleep' can be provided"), nil
			}

			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Prepare query parameters based on which option was selected
			queryParams := lc.Dict{}
			var message string

			switch {
			case version != "":
				// Upgrade to specific version
				queryParams["specific_version"] = version
				message = fmt.Sprintf("Sensor upgrade to version %s initiated successfully. Sensors will update within approximately 20 minutes.", version)
			case toLatest:
				// Sending no version parameter at all is what selects the latest
				// version from the package index server-side.
				message = "Sensor upgrade to the latest version initiated successfully. Sensors will update within approximately 20 minutes."
			case isFallback:
				// Move to the stable/fallback version
				queryParams["is_fallback"] = "true"
				message = "Sensor downgrade to the stable/fallback version initiated successfully. Sensors will update within approximately 20 minutes."
			case isSleep:
				// Move to dormant mode
				queryParams["is_sleep"] = "true"
				message = "Sensors will be moved to dormant mode within approximately 20 minutes."
			}

			// Make the API call to upgrade sensors
			// Endpoint: POST /v1/modules/{oid}
			resp := lc.Dict{}
			err = org.GenericPOSTRequest(fmt.Sprintf("modules/%s", org.GetOID()), queryParams, &resp)
			if err != nil {
				return tools.ErrorResultf("failed to update sensors: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": message,
			}), nil
		},
	})
}

// RegisterGetOrgOIDByName registers the get_org_oid_by_name tool
// This tool efficiently looks up an organization OID by name using caching
func RegisterGetOrgOIDByName() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_org_oid_by_name",
		Description: "Efficiently look up an organization OID by its name",
		Profile:     "platform_admin",
		RequiresOID: false, // User-level operation
		Schema: mcp.NewTool("get_org_oid_by_name",
			mcp.WithDescription("Efficiently look up an organization OID by its name. Uses caching for fast repeated lookups."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The organization name to look up")),
			mcp.WithBoolean("exact_match",
				mcp.Description("If true (default), match exact name; if false, case-insensitive match")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("name parameter is required"), nil
			}

			exactMatch := true
			if em, ok := args["exact_match"].(bool); ok {
				exactMatch = em
			}

			// Get auth context for cache key
			authCtx, err := auth.FromContext(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get auth context: %v", err), nil
			}
			cacheKey := authCtx.CacheKey()

			// Get global cache
			cache := GetGlobalOrgCache()

			// Check if we have a complete cache entry
			if cache.IsComplete(cacheKey) {
				oid, info, found := cache.LookupByName(cacheKey, name, exactMatch)
				if found {
					result := map[string]interface{}{
						"oid":   oid,
						"found": true,
					}
					if info != nil {
						result["name"] = info.Name
					}
					return tools.SuccessResult(result), nil
				}
				// Cache is complete but org not found
				return tools.SuccessResult(map[string]interface{}{
					"found": false,
					"error": "organization not found",
				}), nil
			}

			// Check cache for a quick hit (even if incomplete)
			if oid, info, found := cache.LookupByName(cacheKey, name, exactMatch); found {
				result := map[string]interface{}{
					"oid":   oid,
					"found": true,
				}
				if info != nil {
					result["name"] = info.Name
				}
				return tools.SuccessResult(result), nil
			}

			// Cache miss - need to query the API
			org, err := tools.GetOrganizationClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization context: %v", err), nil
			}

			// Use pagination with early termination
			pageSize := 100
			offset := 0

			for {
				offsetPtr := &offset
				limitPtr := &pageSize

				orgs, err := org.ListUserOrgs(offsetPtr, limitPtr, nil, nil, nil, true)
				if err != nil {
					return tools.ErrorResultf("failed to list user organizations: %v", err), nil
				}

				// Check if this is the last page
				isLastPage := len(orgs) < pageSize

				// Add orgs to cache
				cache.AddOrgs(cacheKey, orgs, isLastPage)

				// Search for matching org
				for _, o := range orgs {
					var match bool
					if exactMatch {
						match = o.Name == name
					} else {
						match = strings.EqualFold(o.Name, name)
					}

					if match {
						return tools.SuccessResult(map[string]interface{}{
							"oid":   o.OID,
							"name":  o.Name,
							"found": true,
						}), nil
					}
				}

				// If this was the last page, org not found
				if isLastPage {
					return tools.SuccessResult(map[string]interface{}{
						"found": false,
						"error": "organization not found",
					}), nil
				}

				// Move to next page
				offset += pageSize
			}
		},
	})
}
