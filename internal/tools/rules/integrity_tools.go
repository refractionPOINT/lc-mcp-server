package rules

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register File/Registry Integrity Monitoring (FIM) rule tools.
	RegisterListIntegrityRules()
	RegisterSetIntegrityRule()
	RegisterDeleteIntegrityRule()
}

// RegisterListIntegrityRules registers the list_integrity_rules tool.
func RegisterListIntegrityRules() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_integrity_rules",
		Description: "List all file/registry integrity (FIM) rules",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("list_integrity_rules",
			mcp.WithDescription("List all file/registry integrity (FIM) rules"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			rules, err := org.IntegrityRules()
			if err != nil {
				return tools.ErrorResultf("failed to list integrity rules: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"rules": rules,
				"count": len(rules),
			}), nil
		},
	})
}

// RegisterSetIntegrityRule registers the set_integrity_rule tool.
func RegisterSetIntegrityRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_integrity_rule",
		Description: "Create or update a file/registry integrity (FIM) rule",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("set_integrity_rule",
			mcp.WithDescription("Create or update a file/registry integrity (FIM) rule"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name for the integrity rule")),
			mcp.WithArray("patterns",
				mcp.Required(),
				mcp.Description("File/registry path patterns to monitor")),
			mcp.WithArray("tags",
				mcp.Description("Optional sensor tags filter (rule applies only to sensors with these tags)")),
			mcp.WithArray("platforms",
				mcp.Description("Optional platform filter (e.g. windows, linux, macos)")),
			mcp.WithDestructiveHintAnnotation(true),
			mcp.WithIdempotentHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
			}

			patterns, err := toStringSlice(args["patterns"])
			if err != nil {
				return tools.ErrorResultf("patterns parameter is invalid: %v", err), nil
			}
			if len(patterns) == 0 {
				return tools.ErrorResult("patterns parameter is required and must be a non-empty array"), nil
			}

			tags, err := toStringSlice(args["tags"])
			if err != nil {
				return tools.ErrorResultf("tags parameter is invalid: %v", err), nil
			}
			platforms, err := toStringSlice(args["platforms"])
			if err != nil {
				return tools.ErrorResultf("platforms parameter is invalid: %v", err), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			rule := lc.IntegrityRule{
				Patterns: patterns,
				Filters: lc.IntegrityRuleFilter{
					Tags:      tags,
					Platforms: platforms,
				},
			}

			if err := org.IntegrityRuleAdd(ruleName, rule); err != nil {
				return tools.ErrorResultf("failed to set integrity rule '%s': %v", ruleName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated integrity rule '%s'", ruleName),
			}), nil
		},
	})
}

// RegisterDeleteIntegrityRule registers the delete_integrity_rule tool.
func RegisterDeleteIntegrityRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_integrity_rule",
		Description: "Delete a file/registry integrity (FIM) rule",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_integrity_rule",
			mcp.WithDescription("Delete a file/registry integrity (FIM) rule"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name of the integrity rule to delete")),
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

			if err := org.IntegrityRuleDelete(ruleName); err != nil {
				return tools.ErrorResultf("failed to delete integrity rule '%s': %v", ruleName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted integrity rule '%s'", ruleName),
			}), nil
		},
	})
}
