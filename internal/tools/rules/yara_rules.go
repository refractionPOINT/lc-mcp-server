package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register YARA rule management tools
	RegisterListYaraRules()
	RegisterGetYaraRule()
	RegisterSetYaraRule()
	RegisterDeleteYaraRule()
	RegisterValidateYaraRule()
}

// RegisterListYaraRules registers the list_yara_rules tool
func RegisterListYaraRules() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_yara_rules",
		Description: "List all YARA rules in the organization",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("list_yara_rules",
			mcp.WithDescription("List all YARA rules in the organization"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// List YARA rules
			rules, err := org.YaraListRules()
			if err != nil {
				return tools.ErrorResultf("failed to list YARA rules: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"rules": rules,
				"count": len(rules),
			}), nil
		},
	})
}

// RegisterGetYaraRule registers the get_yara_rule tool
func RegisterGetYaraRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_yara_rule",
		Description: "Get a specific YARA rule by name",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("get_yara_rule",
			mcp.WithDescription("Get a specific YARA rule by name"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name of the YARA rule to retrieve")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get YARA rule source content
			ruleContent, err := org.YaraGetSource(ruleName)
			if err != nil {
				return tools.ErrorResultf("failed to get YARA rule: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"rule": map[string]interface{}{
					"name":    ruleName,
					"content": ruleContent,
				},
			}), nil
		},
	})
}

// RegisterSetYaraRule registers the set_yara_rule tool
func RegisterSetYaraRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_yara_rule",
		Description: "Create or update a YARA rule",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("set_yara_rule",
			mcp.WithDescription("Create or update a YARA rule"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name for the YARA rule")),
			mcp.WithString("rule_content",
				mcp.Required(),
				mcp.Description("YARA rule content (the actual YARA syntax)")),
			mcp.WithArray("tags",
				mcp.Description("Optional tags to apply the rule to specific sensors")),
			mcp.WithArray("platforms",
				mcp.Description("Optional platforms to restrict the rule to")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
			}

			ruleContent, ok := args["rule_content"].(string)
			if !ok || ruleContent == "" {
				return tools.ErrorResult("rule_content parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Optional: validate YARA rule syntax before adding
			if err := validateYaraRuleSyntax(ruleContent); err != nil {
				return tools.ErrorResultf("invalid YARA rule syntax: %v", err), nil
			}

			// Add YARA rule source
			yaraSource := lc.YaraSource{
				Content: ruleContent,
			}
			err = org.YaraSourceAdd(ruleName, yaraSource)
			if err != nil {
				return tools.ErrorResultf("failed to add/update YARA rule: %v", err), nil
			}

			result := map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated YARA rule '%s'", ruleName),
			}

			// Note about tags and platforms if provided
			if tags, ok := args["tags"].([]interface{}); ok && len(tags) > 0 {
				result["note_tags"] = "Tags parameter provided but not yet supported by SDK"
			}
			if platforms, ok := args["platforms"].([]interface{}); ok && len(platforms) > 0 {
				result["note_platforms"] = "Platforms parameter provided but not yet supported by SDK"
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterDeleteYaraRule registers the delete_yara_rule tool
func RegisterDeleteYaraRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_yara_rule",
		Description: "Delete a YARA rule",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_yara_rule",
			mcp.WithDescription("Delete a YARA rule"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name of the YARA rule to delete")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Delete YARA rule source
			err = org.YaraSourceDelete(ruleName)
			if err != nil {
				return tools.ErrorResultf("failed to delete YARA rule: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted YARA rule '%s'", ruleName),
			}), nil
		},
	})
}

// RegisterValidateYaraRule registers the validate_yara_rule tool
func RegisterValidateYaraRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "validate_yara_rule",
		Description: "Validate YARA rule syntax",
		Profile:     "detection_engineering",
		RequiresOID: false, // Client-side validation, no OID needed
		Schema: mcp.NewTool("validate_yara_rule",
			mcp.WithDescription("Validate YARA rule syntax (client-side validation)"),
			mcp.WithString("rule_content",
				mcp.Required(),
				mcp.Description("YARA rule content to validate")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleContent, ok := args["rule_content"].(string)
			if !ok || ruleContent == "" {
				return tools.ErrorResult("rule_content parameter is required"), nil
			}

			// Validate YARA rule syntax
			if err := validateYaraRuleSyntax(ruleContent); err != nil {
				return tools.SuccessResult(map[string]interface{}{
					"valid":   false,
					"message": fmt.Sprintf("Invalid YARA rule: %v", err),
				}), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"valid":   true,
				"message": "YARA rule syntax is valid",
			}), nil
		},
	})
}

// validateYaraRuleSyntax performs basic client-side YARA syntax validation
func validateYaraRuleSyntax(ruleContent string) error {
	// Basic validation checks
	if len(strings.TrimSpace(ruleContent)) == 0 {
		return fmt.Errorf("rule content cannot be empty")
	}

	// Check for required YARA keywords
	hasRule := strings.Contains(ruleContent, "rule ")
	if !hasRule {
		return fmt.Errorf("rule content must contain 'rule' keyword")
	}

	// Check for basic structure
	hasOpenBrace := strings.Contains(ruleContent, "{")
	hasCloseBrace := strings.Contains(ruleContent, "}")
	if !hasOpenBrace || !hasCloseBrace {
		return fmt.Errorf("rule content must have opening and closing braces")
	}

	// Count braces for balance
	openCount := strings.Count(ruleContent, "{")
	closeCount := strings.Count(ruleContent, "}")
	if openCount != closeCount {
		return fmt.Errorf("unbalanced braces in rule content")
	}

	// Check for condition keyword (required in YARA)
	hasCondition := strings.Contains(ruleContent, "condition:")
	if !hasCondition {
		return fmt.Errorf("rule must contain 'condition:' section")
	}

	// Note: For full validation, would need to use YARA library
	// This is basic syntax checking only

	return nil
}
