package hive

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register generic hive operation tools
	RegisterListRules()
	RegisterGetRule()
	RegisterSetRule()
	RegisterDeleteRule()
}

// RegisterListRules registers the list_rules tool
func RegisterListRules() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_rules",
		Description: "List all rules from a specific hive",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_rules",
			mcp.WithDescription("List all rules from a specific hive (e.g., 'dr-general', 'dr-managed', 'fp')"),
			mcp.WithString("hive_name",
				mcp.Required(),
				mcp.Description("Name of the hive (e.g., 'dr-general', 'dr-managed', 'fp')")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			hiveName, ok := args["hive_name"].(string)
			if !ok || hiveName == "" {
				return tools.ErrorResult("hive_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client
			hive := lc.NewHiveClient(org)

			// List all rules from the specified hive
			rules, err := hive.List(lc.HiveArgs{
				HiveName:     hiveName,
				PartitionKey: org.GetOID(),
			})
			if err != nil {
				return tools.ErrorResultf("failed to list rules from hive '%s': %v", hiveName, err), nil
			}

			// Convert to response format
			result := make(map[string]interface{})
			for name, data := range rules {
				result[name] = map[string]interface{}{
					"data":     data.Data,
					"enabled":  data.UsrMtd.Enabled,
					"tags":     data.UsrMtd.Tags,
					"comment":  data.UsrMtd.Comment,
					"metadata": data.SysMtd,
				}
			}

			return tools.SuccessResult(map[string]interface{}{
				"rules": result,
				"count": len(result),
			}), nil
		},
	})
}

// RegisterGetRule registers the get_rule tool
func RegisterGetRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_rule",
		Description: "Get a specific rule from a hive",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_rule",
			mcp.WithDescription("Get a specific rule from a hive"),
			mcp.WithString("hive_name",
				mcp.Required(),
				mcp.Description("Name of the hive (e.g., 'dr-general', 'dr-managed', 'fp')")),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name of the rule to retrieve")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			hiveName, ok := args["hive_name"].(string)
			if !ok || hiveName == "" {
				return tools.ErrorResult("hive_name parameter is required"), nil
			}

			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client
			hive := lc.NewHiveClient(org)

			// Get rule
			rule, err := hive.Get(lc.HiveArgs{
				HiveName:     hiveName,
				PartitionKey: org.GetOID(),
				Key:          ruleName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get rule '%s' from hive '%s': %v", ruleName, hiveName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"rule": map[string]interface{}{
					"name":    ruleName,
					"data":    rule.Data,
					"enabled": rule.UsrMtd.Enabled,
					"tags":    rule.UsrMtd.Tags,
					"comment": rule.UsrMtd.Comment,
					"metadata": map[string]interface{}{
						"created_at":  rule.SysMtd.CreatedAt,
						"created_by":  rule.SysMtd.CreatedBy,
						"last_mod":    rule.SysMtd.LastMod,
						"last_author": rule.SysMtd.LastAuthor,
						"guid":        rule.SysMtd.GUID,
					},
				},
			}), nil
		},
	})
}

// RegisterSetRule registers the set_rule tool
func RegisterSetRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_rule",
		Description: "Create or update a rule in a hive",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_rule",
			mcp.WithDescription("Create or update a rule in a hive"),
			mcp.WithString("hive_name",
				mcp.Required(),
				mcp.Description("Name of the hive (e.g., 'dr-general', 'dr-managed', 'fp')")),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name for the rule")),
			mcp.WithObject("rule_content",
				mcp.Required(),
				mcp.Description("Rule content (detection and response for D&R rules)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			hiveName, ok := args["hive_name"].(string)
			if !ok || hiveName == "" {
				return tools.ErrorResult("hive_name parameter is required"), nil
			}

			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
			}

			ruleContent, ok := args["rule_content"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("rule_content parameter is required and must be an object"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client
			hive := lc.NewHiveClient(org)

			// Set rule
			enabled := true
			_, err = hive.Add(lc.HiveArgs{
				HiveName:     hiveName,
				PartitionKey: org.GetOID(),
				Key:          ruleName,
				Data:         lc.Dict(ruleContent),
				Enabled:      &enabled,
			})
			if err != nil {
				return tools.ErrorResultf("failed to set rule '%s' in hive '%s': %v", ruleName, hiveName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated rule '%s' in hive '%s'", ruleName, hiveName),
			}), nil
		},
	})
}

// RegisterDeleteRule registers the delete_rule tool
func RegisterDeleteRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_rule",
		Description: "Delete a rule from a hive",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_rule",
			mcp.WithDescription("Delete a rule from a hive"),
			mcp.WithString("hive_name",
				mcp.Required(),
				mcp.Description("Name of the hive (e.g., 'dr-general', 'dr-managed', 'fp')")),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name of the rule to delete")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			hiveName, ok := args["hive_name"].(string)
			if !ok || hiveName == "" {
				return tools.ErrorResult("hive_name parameter is required"), nil
			}

			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Create hive client
			hive := lc.NewHiveClient(org)

			// Delete rule
			_, err = hive.Remove(lc.HiveArgs{
				HiveName:     hiveName,
				PartitionKey: org.GetOID(),
				Key:          ruleName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to delete rule '%s' from hive '%s': %v", ruleName, hiveName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted rule '%s' from hive '%s'", ruleName, hiveName),
			}), nil
		},
	})
}
