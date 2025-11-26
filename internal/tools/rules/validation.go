package rules

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register validation tools
	RegisterValidateDRRuleComponents()
}

// RegisterValidateDRRuleComponents registers the validate_dr_rule_components tool
// This tool validates D&R rules using the Replay service for proper server-side validation.
func RegisterValidateDRRuleComponents() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "validate_dr_rule_components",
		Description: "Validate D&R rule syntax using the Replay service",
		Profile:     "detection_engineering",
		RequiresOID: true, // Server-side validation requires organization
		Schema: mcp.NewTool("validate_dr_rule_components",
			mcp.WithDescription("Validate D&R rule syntax using the Replay service. Provide either rule_name OR detect/respond components."),
			mcp.WithString("rule_name",
				mcp.Description("Name of an existing rule to validate (optional if detect is provided)")),
			mcp.WithString("namespace",
				mcp.Description("Rule namespace: 'general', 'managed', or 'service' (default: 'general')")),
			mcp.WithObject("detect",
				mcp.Description("Detection component (YAML/JSON structure). Required if rule_name not provided")),
			mcp.WithObject("respond",
				mcp.Description("Response component (array of actions). Optional")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Get organization
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Extract rule source
			ruleName, _ := args["rule_name"].(string)
			namespace := GetNamespaceWithDefault(args)
			detect, hasDetect := args["detect"]
			respond := args["respond"]

			// Validate that we have either rule_name or detect
			if ruleName == "" && !hasDetect {
				return tools.ErrorResult("either 'rule_name' or 'detect' must be provided"), nil
			}

			// If rule_name is provided, fetch and validate the existing rule
			if ruleName != "" {
				// Fetch all rules in the namespace and find the one we want
				rules, err := org.DRRules(lc.WithNamespace(namespace))
				if err != nil {
					return tools.ErrorResultf("failed to fetch rules: %v", err), nil
				}

				rule, ok := rules[ruleName]
				if !ok {
					return tools.ErrorResultf("rule '%s' not found in namespace '%s'", ruleName, namespace), nil
				}

				// Extract detect and respond from the rule and build for validation
				fullRule, err := BuildRuleFromComponents(rule["detect"], rule["respond"], "validation-test")
				if err != nil {
					return tools.ErrorResultf("invalid rule structure: %v", err), nil
				}

				// Validate using Replay service
				resp, err := org.ValidateDRRule(fullRule)
				if err != nil {
					return tools.ErrorResultf("validation request failed: %v", err), nil
				}

				if resp.Error != "" {
					return tools.SuccessResult(map[string]interface{}{
						"valid":     false,
						"error":     resp.Error,
						"rule_name": ruleName,
						"namespace": namespace,
					}), nil
				}

				return tools.SuccessResult(map[string]interface{}{
					"valid":     true,
					"message":   fmt.Sprintf("Rule '%s' syntax is valid", ruleName),
					"rule_name": ruleName,
					"namespace": namespace,
				}), nil
			}

			// Build rule from detect/respond components using shared helper
			rule, err := BuildRuleFromComponents(detect, respond, "validation-test")
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			// Validate using Replay service
			resp, err := org.ValidateDRRule(rule)
			if err != nil {
				return tools.ErrorResultf("validation request failed: %v", err), nil
			}

			if resp.Error != "" {
				return tools.SuccessResult(map[string]interface{}{
					"valid": false,
					"error": resp.Error,
				}), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"valid":   true,
				"message": "D&R rule syntax is valid",
			}), nil
		},
	})
}
