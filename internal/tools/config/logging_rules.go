package config

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterListLoggingRules()
	RegisterSetLoggingRule()
	RegisterDeleteLoggingRule()
}

// RegisterListLoggingRules registers the list_logging_rules tool
func RegisterListLoggingRules() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_logging_rules",
		Description: "List artifact/logging-collection rules",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_logging_rules",
			mcp.WithDescription("List artifact/logging-collection rules"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			rules, err := org.LoggingRules()
			if err != nil {
				return tools.ErrorResultf("failed to list logging rules: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"rules": rules,
				"count": len(rules),
			}), nil
		},
	})
}

// RegisterSetLoggingRule registers the set_logging_rule tool
func RegisterSetLoggingRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_logging_rule",
		Description: "Create/update a logging rule",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_logging_rule",
			mcp.WithDescription("Create/update a logging rule"),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name of the logging rule")),
			mcp.WithArray("patterns",
				mcp.Required(),
				mcp.Description("List of file path patterns to collect (glob wildcards supported)")),
			mcp.WithArray("tags",
				mcp.Description("Optional sensor tag filter")),
			mcp.WithArray("platforms",
				mcp.Description("Optional platform filter")),
			mcp.WithNumber("days_retention",
				mcp.Description("Log retention period in days")),
			mcp.WithBoolean("delete_after",
				mcp.Description("Delete the source file after collection")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("name parameter is required"), nil
			}

			patternsRaw, ok := args["patterns"].([]interface{})
			if !ok {
				return tools.ErrorResult("patterns parameter is required and must be an array"), nil
			}
			patterns := toStringSlice(patternsRaw)

			rule := lc.LoggingRule{
				Patterns: patterns,
			}
			if tagsRaw, ok := args["tags"].([]interface{}); ok {
				rule.Tags = toStringSlice(tagsRaw)
			}
			if platformsRaw, ok := args["platforms"].([]interface{}); ok {
				rule.Platforms = toStringSlice(platformsRaw)
			}
			if v, ok := args["days_retention"].(float64); ok {
				rule.RetentionDays = int(v)
			}
			if v, ok := args["delete_after"].(bool); ok {
				rule.DeleteAfter = v
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			if err := org.LoggingRuleAdd(name, rule); err != nil {
				return tools.ErrorResultf("failed to set logging rule '%s': %v", name, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated logging rule '%s'", name),
			}), nil
		},
	})
}

// RegisterDeleteLoggingRule registers the delete_logging_rule tool
func RegisterDeleteLoggingRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_logging_rule",
		Description: "Delete a logging rule",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_logging_rule",
			mcp.WithDescription("Delete a logging rule"),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name of the logging rule to delete")),
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

			if err := org.LoggingRuleDelete(name); err != nil {
				return tools.ErrorResultf("failed to delete logging rule '%s': %v", name, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted logging rule '%s'", name),
			}), nil
		},
	})
}

// toStringSlice converts a []interface{} of strings into a []string, skipping
// any non-string elements.
func toStringSlice(raw []interface{}) []string {
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
