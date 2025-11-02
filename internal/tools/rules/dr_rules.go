package rules

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register D&R rule management tools
	RegisterListDRGeneralRules()
	RegisterGetDRGeneralRule()
	RegisterSetDRGeneralRule()
	RegisterDeleteDRGeneralRule()
	RegisterListDRManagedRules()
	RegisterGetDRManagedRule()
	RegisterSetDRManagedRule()
	RegisterDeleteDRManagedRule()
	RegisterGetDetectionRules()
}

// getOrganization retrieves or creates an Organization instance from context
func getOrganization(ctx context.Context) (*lc.Organization, error) {
	cache, err := auth.GetSDKCache(ctx)
	if err != nil {
		return nil, err
	}
	return cache.GetFromContext(ctx)
}

// RegisterListDRGeneralRules registers the list_dr_general_rules tool
func RegisterListDRGeneralRules() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_dr_general_rules",
		Description: "List all general Detection & Response rules",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("list_dr_general_rules",
			mcp.WithDescription("List all general Detection & Response rules"),
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

			// List rules with general namespace filter
			rules, err := org.DRRules(lc.WithNamespace("general"))
			if err != nil {
				return tools.ErrorResultf("failed to list D&R rules: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"rules": rules,
				"count": len(rules),
			}), nil
		},
	})
}

// RegisterGetDRGeneralRule registers the get_dr_general_rule tool
func RegisterGetDRGeneralRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_dr_general_rule",
		Description: "Get a specific general D&R rule by name",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("get_dr_general_rule",
			mcp.WithDescription("Get a specific general Detection & Response rule by name"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name of the rule to retrieve")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
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

			// List rules and find the specific one
			rules, err := org.DRRules(lc.WithNamespace("general"))
			if err != nil {
				return tools.ErrorResultf("failed to list D&R rules: %v", err), nil
			}

			// Find the rule by name
			for _, rule := range rules {
				if name, ok := rule["name"].(string); ok && name == ruleName {
					return tools.SuccessResult(map[string]interface{}{
						"rule": rule,
					}), nil
				}
			}

			return tools.ErrorResultf("rule '%s' not found", ruleName), nil
		},
	})
}

// RegisterSetDRGeneralRule registers the set_dr_general_rule tool
func RegisterSetDRGeneralRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_dr_general_rule",
		Description: "Create or update a general D&R rule",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("set_dr_general_rule",
			mcp.WithDescription("Create or update a general Detection & Response rule"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name for the rule")),
			mcp.WithObject("rule_content",
				mcp.Required(),
				mcp.Description("Rule content (detection and response)")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
			}

			ruleContent, ok := args["rule_content"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("rule_content parameter is required and must be an object"), nil
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

			// Extract detect and respond from rule content
			detect, hasDetect := ruleContent["detect"]
			respond, hasRespond := ruleContent["respond"]

			if !hasDetect {
				return tools.ErrorResult("rule_content must contain 'detect' field"), nil
			}

			// Create rule options
			options := lc.NewDRRuleOptions{
				Namespace: "general",
				IsReplace: true, // Update if exists
				IsEnabled: true,
			}

			// Add rule
			err = org.DRRuleAdd(ruleName, detect, respond, options)
			if err != nil {
				return tools.ErrorResultf("failed to add/update D&R rule: %v", err), nil
			}

			result := map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated rule '%s'", ruleName),
			}

			// If respond wasn't provided, note it
			if !hasRespond {
				result["note"] = "Rule created without response actions"
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterDeleteDRGeneralRule registers the delete_dr_general_rule tool
func RegisterDeleteDRGeneralRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_dr_general_rule",
		Description: "Delete a general D&R rule",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_dr_general_rule",
			mcp.WithDescription("Delete a general Detection & Response rule"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name of the rule to delete")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
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

			// Delete rule with general namespace filter
			err = org.DRRuleDelete(ruleName, lc.WithNamespace("general"))
			if err != nil {
				return tools.ErrorResultf("failed to delete D&R rule: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted rule '%s'", ruleName),
			}), nil
		},
	})
}

// RegisterListDRManagedRules registers the list_dr_managed_rules tool
func RegisterListDRManagedRules() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_dr_managed_rules",
		Description: "List all managed Detection & Response rules",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("list_dr_managed_rules",
			mcp.WithDescription("List all managed Detection & Response rules"),
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

			// List rules with managed namespace filter
			rules, err := org.DRRules(lc.WithNamespace("managed"))
			if err != nil {
				return tools.ErrorResultf("failed to list managed D&R rules: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"rules": rules,
				"count": len(rules),
			}), nil
		},
	})
}

// RegisterGetDRManagedRule registers the get_dr_managed_rule tool
func RegisterGetDRManagedRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_dr_managed_rule",
		Description: "Get a specific managed D&R rule by name",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("get_dr_managed_rule",
			mcp.WithDescription("Get a specific managed Detection & Response rule by name"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name of the rule to retrieve")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
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

			// List rules and find the specific one
			rules, err := org.DRRules(lc.WithNamespace("managed"))
			if err != nil {
				return tools.ErrorResultf("failed to list managed D&R rules: %v", err), nil
			}

			// Find the rule by name
			for _, rule := range rules {
				if name, ok := rule["name"].(string); ok && name == ruleName {
					return tools.SuccessResult(map[string]interface{}{
						"rule": rule,
					}), nil
				}
			}

			return tools.ErrorResultf("managed rule '%s' not found", ruleName), nil
		},
	})
}

// RegisterSetDRManagedRule registers the set_dr_managed_rule tool
func RegisterSetDRManagedRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_dr_managed_rule",
		Description: "Create or update a managed D&R rule",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("set_dr_managed_rule",
			mcp.WithDescription("Create or update a managed Detection & Response rule"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name for the rule")),
			mcp.WithObject("rule_content",
				mcp.Required(),
				mcp.Description("Rule content (detection and response)")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
			}

			ruleContent, ok := args["rule_content"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("rule_content parameter is required and must be an object"), nil
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

			// Extract detect and respond from rule content
			detect, hasDetect := ruleContent["detect"]
			respond, hasRespond := ruleContent["respond"]

			if !hasDetect {
				return tools.ErrorResult("rule_content must contain 'detect' field"), nil
			}

			// Create rule options with managed namespace
			options := lc.NewDRRuleOptions{
				Namespace: "managed",
				IsReplace: true, // Update if exists
				IsEnabled: true,
			}

			// Add rule
			err = org.DRRuleAdd(ruleName, detect, respond, options)
			if err != nil {
				return tools.ErrorResultf("failed to add/update managed D&R rule: %v", err), nil
			}

			result := map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated managed rule '%s'", ruleName),
			}

			if !hasRespond {
				result["note"] = "Rule created without response actions"
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterDeleteDRManagedRule registers the delete_dr_managed_rule tool
func RegisterDeleteDRManagedRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_dr_managed_rule",
		Description: "Delete a managed D&R rule",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_dr_managed_rule",
			mcp.WithDescription("Delete a managed Detection & Response rule"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name of the rule to delete")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
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

			// Delete rule with managed namespace filter
			err = org.DRRuleDelete(ruleName, lc.WithNamespace("managed"))
			if err != nil {
				return tools.ErrorResultf("failed to delete managed D&R rule: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted managed rule '%s'", ruleName),
			}), nil
		},
	})
}

// RegisterGetDetectionRules registers the get_detection_rules tool
func RegisterGetDetectionRules() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_detection_rules",
		Description: "Get all Detection & Response rules (all namespaces)",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("get_detection_rules",
			mcp.WithDescription("Get all Detection & Response rules from all namespaces"),
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

			// List all rules (no namespace filter)
			rules, err := org.DRRules()
			if err != nil {
				return tools.ErrorResultf("failed to list all D&R rules: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"rules": rules,
				"count": len(rules),
			}), nil
		},
	})
}
