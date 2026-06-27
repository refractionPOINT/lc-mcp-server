package rules

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register D&R and FP rule enable/disable state tools.
	RegisterEnableDRRule()
	RegisterDisableDRRule()
	RegisterEnableFPRule()
	RegisterDisableFPRule()
}

// drNamespaceToHive maps a D&R namespace ("general" or "managed") to its hive name.
func drNamespaceToHive(args map[string]interface{}) (string, error) {
	ns := "general"
	if v, ok := args["namespace"].(string); ok && v != "" {
		ns = v
	}
	switch ns {
	case "general":
		return "dr-general", nil
	case "managed":
		return "dr-managed", nil
	default:
		return "", fmt.Errorf("unsupported namespace '%s' (expected 'general' or 'managed')", ns)
	}
}

// setHiveRecordEnabled flips only the Enabled flag of a hive record, preserving
// the existing tags, comment and expiry. It reads the current mtd first and only
// changes Enabled.
func setHiveRecordEnabled(org *lc.Organization, hiveName, key string, enabled bool) error {
	hive := lc.NewHiveClient(org)
	args := lc.HiveArgs{
		HiveName:     hiveName,
		PartitionKey: org.GetOID(),
		Key:          key,
	}

	existing, err := hive.GetMTD(args)
	if err != nil {
		return err
	}

	// Preserve existing metadata, only flip Enabled.
	enabledVal := enabled
	expiry := existing.UsrMtd.Expiry
	comment := existing.UsrMtd.Comment
	updateArgs := lc.HiveArgs{
		HiveName:     hiveName,
		PartitionKey: org.GetOID(),
		Key:          key,
		Enabled:      &enabledVal,
		Tags:         existing.UsrMtd.Tags,
		Comment:      &comment,
	}
	if expiry != 0 {
		updateArgs.Expiry = &expiry
	}

	_, err = hive.Update(updateArgs)
	return err
}

func registerDRStateTool(name, summary string, enabled bool) {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        name,
		Description: summary,
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool(name,
			mcp.WithDescription(summary),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name of the D&R rule")),
			mcp.WithString("namespace",
				mcp.Description("D&R namespace: 'general' (default) or 'managed'")),
			mcp.WithDestructiveHintAnnotation(true),
			mcp.WithIdempotentHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
			}

			hiveName, err := drNamespaceToHive(args)
			if err != nil {
				return tools.ErrorResultf("%v", err), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			if err := setHiveRecordEnabled(org, hiveName, ruleName, enabled); err != nil {
				return tools.ErrorResultf("failed to update D&R rule '%s': %v", ruleName, err), nil
			}

			state := "disabled"
			if enabled {
				state = "enabled"
			}
			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully %s D&R rule '%s'", state, ruleName),
			}), nil
		},
	})
}

func registerFPStateTool(name, summary string, enabled bool) {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        name,
		Description: summary,
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool(name,
			mcp.WithDescription(summary),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name of the false-positive rule")),
			mcp.WithDestructiveHintAnnotation(true),
			mcp.WithIdempotentHintAnnotation(true),
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

			if err := setHiveRecordEnabled(org, "fp", ruleName, enabled); err != nil {
				return tools.ErrorResultf("failed to update FP rule '%s': %v", ruleName, err), nil
			}

			state := "disabled"
			if enabled {
				state = "enabled"
			}
			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully %s FP rule '%s'", state, ruleName),
			}), nil
		},
	})
}

// RegisterEnableDRRule registers the enable_dr_rule tool.
func RegisterEnableDRRule() {
	registerDRStateTool("enable_dr_rule", "Enable a D&R rule (preserves its configuration)", true)
}

// RegisterDisableDRRule registers the disable_dr_rule tool.
func RegisterDisableDRRule() {
	registerDRStateTool("disable_dr_rule", "Disable a D&R rule (preserves its configuration)", false)
}

// RegisterEnableFPRule registers the enable_fp_rule tool.
func RegisterEnableFPRule() {
	registerFPStateTool("enable_fp_rule", "Enable a false-positive rule (preserves its configuration)", true)
}

// RegisterDisableFPRule registers the disable_fp_rule tool.
func RegisterDisableFPRule() {
	registerFPStateTool("disable_fp_rule", "Disable a false-positive rule (preserves its configuration)", false)
}
