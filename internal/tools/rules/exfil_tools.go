package rules

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register exfil (event/watch) rule tools.
	RegisterListExfilRules()
	RegisterSetExfilEventRule()
	RegisterSetExfilWatchRule()
	RegisterDeleteExfilRule()
}

// RegisterListExfilRules registers the list_exfil_rules tool.
func RegisterListExfilRules() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_exfil_rules",
		Description: "List all exfil event and watch rules",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("list_exfil_rules",
			mcp.WithDescription("List all exfil event and watch rules"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			rules, err := org.ExfilRules()
			if err != nil {
				return tools.ErrorResultf("failed to list exfil rules: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"rules":       rules,
				"event_count": len(rules.Events),
				"watch_count": len(rules.Watches),
			}), nil
		},
	})
}

// RegisterSetExfilEventRule registers the set_exfil_event_rule tool.
func RegisterSetExfilEventRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_exfil_event_rule",
		Description: "Create or update an exfil event rule (which events to forward)",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("set_exfil_event_rule",
			mcp.WithDescription("Create or update an exfil event rule (selects which event types are forwarded)"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name for the exfil event rule")),
			mcp.WithArray("events",
				mcp.Required(),
				mcp.Description("List of event type names to forward")),
			mcp.WithArray("tags",
				mcp.Description("Optional sensor tags filter")),
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

			events, err := toStringSlice(args["events"])
			if err != nil {
				return tools.ErrorResultf("events parameter is invalid: %v", err), nil
			}
			if len(events) == 0 {
				return tools.ErrorResult("events parameter is required and must be a non-empty array"), nil
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

			event := lc.ExfilRuleEvent{
				Events: events,
				Filters: lc.ExfilEventFilters{
					Tags:      tags,
					Platforms: platforms,
				},
			}

			if err := org.ExfilRuleEventAdd(ruleName, event); err != nil {
				return tools.ErrorResultf("failed to set exfil event rule '%s': %v", ruleName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated exfil event rule '%s'", ruleName),
			}), nil
		},
	})
}

// RegisterSetExfilWatchRule registers the set_exfil_watch_rule tool.
func RegisterSetExfilWatchRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_exfil_watch_rule",
		Description: "Create or update an exfil watch rule (match a value within an event)",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("set_exfil_watch_rule",
			mcp.WithDescription("Create or update an exfil watch rule (forwards an event when a value matches at a path)"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name for the exfil watch rule")),
			mcp.WithString("event",
				mcp.Required(),
				mcp.Description("Event type to watch")),
			mcp.WithString("operator",
				mcp.Required(),
				mcp.Description("Match operator (e.g. is, contains, matches, starts with, ends with)")),
			mcp.WithString("value",
				mcp.Required(),
				mcp.Description("Value to match")),
			mcp.WithArray("path",
				mcp.Description("Path within the event to inspect (array of path components)")),
			mcp.WithArray("tags",
				mcp.Description("Optional sensor tags filter")),
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
			event, ok := args["event"].(string)
			if !ok || event == "" {
				return tools.ErrorResult("event parameter is required"), nil
			}
			operator, ok := args["operator"].(string)
			if !ok || operator == "" {
				return tools.ErrorResult("operator parameter is required"), nil
			}
			value, ok := args["value"].(string)
			if !ok || value == "" {
				return tools.ErrorResult("value parameter is required"), nil
			}

			path, err := toStringSlice(args["path"])
			if err != nil {
				return tools.ErrorResultf("path parameter is invalid: %v", err), nil
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

			watch := lc.ExfilRuleWatch{
				Event:    event,
				Value:    value,
				Path:     path,
				Operator: operator,
				Filters: lc.ExfilEventFilters{
					Tags:      tags,
					Platforms: platforms,
				},
			}

			if err := org.ExfilRuleWatchAdd(ruleName, watch); err != nil {
				return tools.ErrorResultf("failed to set exfil watch rule '%s': %v", ruleName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated exfil watch rule '%s'", ruleName),
			}), nil
		},
	})
}

// RegisterDeleteExfilRule registers the delete_exfil_rule tool.
func RegisterDeleteExfilRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_exfil_rule",
		Description: "Delete an exfil rule (event or watch)",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_exfil_rule",
			mcp.WithDescription("Delete an exfil rule. Use rule_type to select event or watch (default: event)"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name of the exfil rule to delete")),
			mcp.WithString("rule_type",
				mcp.Description("Type of rule to delete: 'event' or 'watch' (default: event)")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
			}

			ruleType := "event"
			if rt, ok := args["rule_type"].(string); ok && rt != "" {
				ruleType = rt
			}
			if ruleType != "event" && ruleType != "watch" {
				return tools.ErrorResult("rule_type must be 'event' or 'watch'"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			if ruleType == "watch" {
				err = org.ExfilRuleWatchDelete(ruleName)
			} else {
				err = org.ExfilRuleEventDelete(ruleName)
			}
			if err != nil {
				return tools.ErrorResultf("failed to delete exfil %s rule '%s': %v", ruleType, ruleName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted exfil %s rule '%s'", ruleType, ruleName),
			}), nil
		},
	})
}
