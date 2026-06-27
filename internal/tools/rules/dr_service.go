package rules

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

const drServiceNamespace = "service"

func init() {
	// Register dr-service namespace rule tools.
	RegisterListDRServiceRules()
	RegisterSetDRServiceRule()
	RegisterDeleteDRServiceRule()
}

// RegisterListDRServiceRules registers the list_dr_service_rules tool.
func RegisterListDRServiceRules() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_dr_service_rules",
		Description: "List all D&R rules in the service namespace",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("list_dr_service_rules",
			mcp.WithDescription("List all Detection & Response rules in the service namespace"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			rules, err := org.DRRules(lc.WithNamespace(drServiceNamespace))
			if err != nil {
				return tools.ErrorResultf("failed to list service D&R rules: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"rules": rules,
				"count": len(rules),
			}), nil
		},
	})
}

// RegisterSetDRServiceRule registers the set_dr_service_rule tool.
func RegisterSetDRServiceRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_dr_service_rule",
		Description: "Create or update a D&R rule in the service namespace",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("set_dr_service_rule",
			mcp.WithDescription("Create or update a Detection & Response rule in the service namespace"),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name for the rule")),
			mcp.WithObject("rule_content",
				mcp.Required(),
				mcp.Description("Rule content with 'detect' (and optional 'respond')")),
			mcp.WithDestructiveHintAnnotation(true),
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

			detect, hasDetect := ruleContent["detect"]
			if !hasDetect {
				return tools.ErrorResult("rule_content must contain a 'detect' field"), nil
			}
			respond := ruleContent["respond"]

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			err = org.DRRuleAdd(ruleName, detect, respond, lc.NewDRRuleOptions{
				IsReplace: true,
				Namespace: drServiceNamespace,
				IsEnabled: true,
			})
			if err != nil {
				return tools.ErrorResultf("failed to set service D&R rule '%s': %v", ruleName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated service D&R rule '%s'", ruleName),
			}), nil
		},
	})
}

// RegisterDeleteDRServiceRule registers the delete_dr_service_rule tool.
func RegisterDeleteDRServiceRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_dr_service_rule",
		Description: "Delete a D&R rule from the service namespace",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_dr_service_rule",
			mcp.WithDescription("Delete a Detection & Response rule from the service namespace"),
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

			if err := org.DRRuleDelete(ruleName, lc.WithNamespace(drServiceNamespace)); err != nil {
				return tools.ErrorResultf("failed to delete service D&R rule '%s': %v", ruleName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted service D&R rule '%s'", ruleName),
			}), nil
		},
	})
}
