package rules

import (
	"context"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/hive"
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

// RegisterListDRGeneralRules registers the list_dr_general_rules tool
func RegisterListDRGeneralRules() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_dr_general_rules",
		Description: "List all general Detection & Response rules",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("list_dr_general_rules",
			mcp.WithDescription("List all general Detection & Response rules"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
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
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// List rules and find the specific one
			rules, err := org.DRRules(lc.WithNamespace("general"))
			if err != nil {
				return tools.ErrorResultf("failed to list D&R rules: %v", err), nil
			}

			// Find the rule by name (SDK returns map[string]Dict where key is rule name)
			rule, found := rules[ruleName]
			if !found {
				return tools.ErrorResultf("rule '%s' not found", ruleName), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"rule": rule,
			}), nil
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
			mcp.WithDescription("Create or update a general Detection & Response rule. Updating an existing rule preserves its metadata (enabled state, tags, comment) unless enabled/tags/comment are given, so a deliberately disabled rule stays disabled."),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name for the rule")),
			mcp.WithObject("rule_content",
				mcp.Required(),
				mcp.Description("Rule content (detection and response)")),
			mcp.WithNumber("ttl",
				mcp.Description("Time-to-live in seconds. Rule auto-deletes after this duration. Optional.")),
			hive.WithMetadataOverrideParams(),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
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

			overrides, err := hive.ParseMetadataOverrides(args)
			if err != nil {
				return tools.ErrorResultf("%v", err), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Extract detect and respond from rule content
			detect, hasDetect := ruleContent["detect"]
			respond, hasRespond := ruleContent["respond"]

			if !hasDetect {
				return tools.ErrorResult("rule_content must contain 'detect' field"), nil
			}

			// Build data structure for hive
			data := lc.Dict{
				"detect": detect,
			}
			if hasRespond {
				data["respond"] = respond
			}

			// Handle TTL parameter (Hive API expects milliseconds)
			var expiry *int64
			if ttl, ok := args["ttl"].(float64); ok && ttl > 0 {
				exp := time.Now().UnixMilli() + int64(ttl)*1000
				expiry = &exp
				overrides.Expiry = expiry
			}

			warning, err := hive.SetRecord(org, hive.RecordWrite{
				HiveName:  "dr-general",
				Key:       ruleName,
				Data:      data,
				Overrides: overrides,
			})
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

			// Note if TTL was set
			if expiry != nil {
				result["expiry"] = *expiry
			}
			if warning != "" {
				result["warning"] = warning
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
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
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
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
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
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// List rules and find the specific one
			rules, err := org.DRRules(lc.WithNamespace("managed"))
			if err != nil {
				return tools.ErrorResultf("failed to list managed D&R rules: %v", err), nil
			}

			// Find the rule by name (SDK returns map[string]Dict where key is rule name)
			rule, found := rules[ruleName]
			if !found {
				return tools.ErrorResultf("managed rule '%s' not found", ruleName), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"rule": rule,
			}), nil
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
			mcp.WithDescription("Create or update a managed Detection & Response rule. Updating an existing rule preserves its metadata (enabled state, tags, comment) unless enabled/tags/comment are given, so a deliberately disabled rule stays disabled."),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name for the rule")),
			mcp.WithObject("rule_content",
				mcp.Required(),
				mcp.Description("Rule content (detection and response)")),
			mcp.WithNumber("ttl",
				mcp.Description("Time-to-live in seconds. Rule auto-deletes after this duration. Optional.")),
			hive.WithMetadataOverrideParams(),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
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

			overrides, err := hive.ParseMetadataOverrides(args)
			if err != nil {
				return tools.ErrorResultf("%v", err), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Extract detect and respond from rule content
			detect, hasDetect := ruleContent["detect"]
			respond, hasRespond := ruleContent["respond"]

			if !hasDetect {
				return tools.ErrorResult("rule_content must contain 'detect' field"), nil
			}

			// Build data structure for hive
			data := lc.Dict{
				"detect": detect,
			}
			if hasRespond {
				data["respond"] = respond
			}

			// Handle TTL parameter (Hive API expects milliseconds)
			var expiry *int64
			if ttl, ok := args["ttl"].(float64); ok && ttl > 0 {
				exp := time.Now().UnixMilli() + int64(ttl)*1000
				expiry = &exp
				overrides.Expiry = expiry
			}

			warning, err := hive.SetRecord(org, hive.RecordWrite{
				HiveName:  "dr-managed",
				Key:       ruleName,
				Data:      data,
				Overrides: overrides,
			})
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

			// Note if TTL was set
			if expiry != nil {
				result["expiry"] = *expiry
			}
			if warning != "" {
				result["warning"] = warning
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
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
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
			mcp.WithDescription("Get all Detection & Response rules from every namespace (general, managed, service), keyed by namespace"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// The API defaults an unfiltered request to the general namespace,
			// so every namespace has to be asked for explicitly. Each namespace
			// is authorized separately (dr.list, dr.list.managed,
			// dr.list.service), so one namespace being off-limits reports itself
			// instead of failing the whole listing.
			namespaces := []string{"general", "managed", "service"}
			byNamespace := map[string]interface{}{}
			failures := map[string]interface{}{}
			total := 0
			for _, ns := range namespaces {
				rules, err := org.DRRules(lc.WithNamespace(ns))
				if err != nil {
					failures[ns] = err.Error()
					continue
				}
				byNamespace[ns] = rules
				total += len(rules)
			}
			if len(failures) == len(namespaces) {
				return tools.ErrorResultf("failed to list D&R rules in every namespace: %v", failures), nil
			}

			result := map[string]interface{}{
				"rules": byNamespace,
				"count": total,
			}
			if len(failures) > 0 {
				result["unavailable_namespaces"] = failures
			}
			return tools.SuccessResult(result), nil
		},
	})
}
