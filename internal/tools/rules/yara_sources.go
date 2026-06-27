package rules

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register YARA source and deployed rule-set tools.
	RegisterListYaraSources()
	RegisterSetYaraRuleset()
	RegisterDeleteYaraRuleset()
}

// RegisterListYaraSources registers the list_yara_sources tool.
func RegisterListYaraSources() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_yara_sources",
		Description: "List all YARA sources",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("list_yara_sources",
			mcp.WithDescription("List all YARA sources"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			sources, err := org.YaraListSources()
			if err != nil {
				return tools.ErrorResultf("failed to list YARA sources: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"sources": sources,
				"count":   len(sources),
			}), nil
		},
	})
}

// RegisterSetYaraRuleset registers the set_yara_ruleset tool. A YARA rule-set
// is a deployed mapping of YARA sources to a set of sensors (via tag/platform
// filters), managed through YaraRuleAdd.
func RegisterSetYaraRuleset() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_yara_ruleset",
		Description: "Create or update a deployed YARA rule-set",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("set_yara_ruleset",
			mcp.WithDescription("Create or update a deployed YARA rule-set (maps YARA sources to sensors)"),
			mcp.WithString("ruleset_name",
				mcp.Required(),
				mcp.Description("Name for the YARA rule-set")),
			mcp.WithArray("sources",
				mcp.Required(),
				mcp.Description("List of YARA source names to include in this rule-set")),
			mcp.WithArray("tags",
				mcp.Description("Optional sensor tags filter (rule-set applies only to sensors with these tags)")),
			mcp.WithArray("platforms",
				mcp.Description("Optional platform filter (e.g. windows, linux, macos)")),
			mcp.WithDestructiveHintAnnotation(true),
			mcp.WithIdempotentHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			rulesetName, ok := args["ruleset_name"].(string)
			if !ok || rulesetName == "" {
				return tools.ErrorResult("ruleset_name parameter is required"), nil
			}

			sources, err := toStringSlice(args["sources"])
			if err != nil {
				return tools.ErrorResultf("sources parameter is invalid: %v", err), nil
			}
			if len(sources) == 0 {
				return tools.ErrorResult("sources parameter is required and must be a non-empty array"), nil
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

			rule := lc.YaraRule{
				Sources: sources,
				Filters: lc.YaraRuleFilter{
					Tags:      tags,
					Platforms: platforms,
				},
			}

			if err := org.YaraRuleAdd(rulesetName, rule); err != nil {
				return tools.ErrorResultf("failed to set YARA rule-set '%s': %v", rulesetName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated YARA rule-set '%s'", rulesetName),
			}), nil
		},
	})
}

// RegisterDeleteYaraRuleset registers the delete_yara_ruleset tool.
func RegisterDeleteYaraRuleset() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_yara_ruleset",
		Description: "Delete a deployed YARA rule-set",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_yara_ruleset",
			mcp.WithDescription("Delete a deployed YARA rule-set"),
			mcp.WithString("ruleset_name",
				mcp.Required(),
				mcp.Description("Name of the YARA rule-set to delete")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			rulesetName, ok := args["ruleset_name"].(string)
			if !ok || rulesetName == "" {
				return tools.ErrorResult("ruleset_name parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			if err := org.YaraRuleDelete(rulesetName); err != nil {
				return tools.ErrorResultf("failed to delete YARA rule-set '%s': %v", rulesetName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted YARA rule-set '%s'", rulesetName),
			}), nil
		},
	})
}
