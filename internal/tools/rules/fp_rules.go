package rules

import (
	"context"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register False Positive rule management tools
	RegisterGetFPRules()
	RegisterGetFPRule()
	RegisterSetFPRule()
	RegisterDeleteFPRule()
}

// RegisterGetFPRules registers the get_fp_rules tool
func RegisterGetFPRules() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_fp_rules",
		Description: "Get all false positive rules",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("get_fp_rules",
			mcp.WithDescription("Get all false positive rules for the organization"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get all FP rules
			rules, err := org.FPRules()
			if err != nil {
				return tools.ErrorResultf("failed to get FP rules: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"rules": rules,
				"count": len(rules),
			}), nil
		},
	})
}

// RegisterGetFPRule registers the get_fp_rule tool
func RegisterGetFPRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_fp_rule",
		Description: "Get a specific false positive rule by name",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("get_fp_rule",
			mcp.WithDescription("Get a specific false positive rule by name"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name of the FP rule to retrieve")),
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

			// Get all FP rules and find the specific one
			rules, err := org.FPRules()
			if err != nil {
				return tools.ErrorResultf("failed to get FP rules: %v", err), nil
			}

			// Find the rule by name
			rule, found := rules[ruleName]
			if !found {
				return tools.ErrorResultf("FP rule '%s' not found", ruleName), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"rule": map[string]interface{}{
					"name":      rule.Name,
					"detection": rule.Detection,
					"oid":       rule.OID,
				},
			}), nil
		},
	})
}

// RegisterSetFPRule registers the set_fp_rule tool
func RegisterSetFPRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_fp_rule",
		Description: "Create or update a false positive rule",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("set_fp_rule",
			mcp.WithDescription("Create or update a false positive rule"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name for the FP rule")),
			mcp.WithObject("rule_content",
				mcp.Required(),
				mcp.Description("FP rule content (detection filter)")),
			mcp.WithNumber("ttl",
				mcp.Description("Time-to-live in seconds. Rule auto-deletes after this duration. Optional.")),
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

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Extract detection filter from rule content
			detection, hasDetection := ruleContent["detect"]
			if !hasDetection {
				// Try alternative field names
				detection, hasDetection = ruleContent["detection"]
			}
			if !hasDetection {
				return tools.ErrorResult("rule_content must contain 'detect' or 'detection' field"), nil
			}

			// FP rules store detection logic directly as data (not wrapped)
			detectionMap, ok := detection.(map[string]interface{})
			if !ok {
				return tools.ErrorResult("detection must be an object"), nil
			}

			// Handle TTL parameter (Hive API expects milliseconds)
			var expiry *int64
			if ttl, ok := args["ttl"].(float64); ok && ttl > 0 {
				exp := time.Now().UnixMilli() + int64(ttl)*1000
				expiry = &exp
			}

			// Create hive client and add rule
			hive := lc.NewHiveClient(org)
			enabled := true
			_, err = hive.Add(lc.HiveArgs{
				HiveName:     "fp",
				PartitionKey: org.GetOID(),
				Key:          ruleName,
				Data:         lc.Dict(detectionMap),
				Enabled:      &enabled,
				Expiry:       expiry,
			})
			if err != nil {
				return tools.ErrorResultf("failed to add/update FP rule: %v", err), nil
			}

			result := map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated FP rule '%s'", ruleName),
			}

			// Note if TTL was set
			if expiry != nil {
				result["expiry"] = *expiry
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterDeleteFPRule registers the delete_fp_rule tool
func RegisterDeleteFPRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_fp_rule",
		Description: "Delete a false positive rule",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_fp_rule",
			mcp.WithDescription("Delete a false positive rule"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name of the FP rule to delete")),
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

			// Delete FP rule
			err = org.FPRuleDelete(ruleName)
			if err != nil {
				return tools.ErrorResultf("failed to delete FP rule: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted FP rule '%s'", ruleName),
			}), nil
		},
	})
}
