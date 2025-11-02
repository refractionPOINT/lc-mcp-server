package rules

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register validation tools
	RegisterValidateDRRuleComponents()
}

// RegisterValidateDRRuleComponents registers the validate_dr_rule_components tool
func RegisterValidateDRRuleComponents() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "validate_dr_rule_components",
		Description: "Validate D&R rule detection and response components",
		Profile:     "detection_engineering",
		RequiresOID: false, // Client-side validation
		Schema: mcp.NewTool("validate_dr_rule_components",
			mcp.WithDescription("Validate D&R rule by providing detect and respond components separately"),
			mcp.WithObject("detect",
				mcp.Required(),
				mcp.Description("The detection component (YAML/JSON structure)")),
			mcp.WithObject("respond",
				mcp.Description("Optional respond component (YAML/JSON structure)")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (optional, for context)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			detect, ok := args["detect"]
			if !ok {
				return tools.ErrorResult("detect parameter is required"), nil
			}

			// Get respond if provided
			respond, hasRespond := args["respond"]

			// If OID is provided, we could validate against the organization
			// For now, do basic structural validation
			if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
				var err error
				ctx, err = auth.WithOID(ctx, oidParam)
				if err != nil {
					return tools.ErrorResultf("failed to switch OID: %v", err), nil
				}

				// Could potentially use org.DRRuleAdd with dry-run flag if SDK supports it
				// For now, just do client-side validation
			}

			// Validate detect component
			if err := validateDetectComponent(detect); err != nil {
				return tools.SuccessResult(map[string]interface{}{
					"valid": false,
					"error": fmt.Sprintf("Invalid detect component: %v", err),
				}), nil
			}

			// Validate respond component if provided
			if hasRespond && respond != nil {
				if err := validateRespondComponent(respond); err != nil {
					return tools.SuccessResult(map[string]interface{}{
						"valid": false,
						"error": fmt.Sprintf("Invalid respond component: %v", err),
					}), nil
				}
			}

			return tools.SuccessResult(map[string]interface{}{
				"valid":   true,
				"message": "D&R rule components are valid",
			}), nil
		},
	})
}

// validateDetectComponent validates the detection component structure
func validateDetectComponent(detect interface{}) error {
	detectMap, ok := detect.(map[string]interface{})
	if !ok {
		return fmt.Errorf("detect must be an object/map")
	}

	// Check for required 'op' field
	op, hasOp := detectMap["op"]
	if !hasOp {
		return fmt.Errorf("detect must have 'op' field")
	}

	opStr, ok := op.(string)
	if !ok {
		return fmt.Errorf("'op' field must be a string")
	}

	// Validate op type
	validOps := map[string]bool{
		"and":           true,
		"or":            true,
		"exists":        true,
		"is":            true,
		"contains":      true,
		"starts with":   true,
		"ends with":     true,
		"matches":       true,
		"is greater than": true,
		"is less than":    true,
		"length is":       true,
		"lookup":          true,
	}

	if !validOps[opStr] {
		// It might be a valid op we don't know about, so just warn
		// Don't fail validation
	}

	// For 'and' and 'or', need 'rules' array
	if opStr == "and" || opStr == "or" {
		rules, hasRules := detectMap["rules"]
		if !hasRules {
			return fmt.Errorf("'%s' operation requires 'rules' array", opStr)
		}
		rulesArray, ok := rules.([]interface{})
		if !ok {
			return fmt.Errorf("'rules' must be an array")
		}
		if len(rulesArray) == 0 {
			return fmt.Errorf("'rules' array cannot be empty for '%s' operation", opStr)
		}
	}

	// For other ops, typically need 'path' field
	if opStr != "and" && opStr != "or" {
		_, hasPath := detectMap["path"]
		_, hasEvent := detectMap["event"]
		if !hasPath && !hasEvent {
			// Some ops might not need path, so just check it exists
		}
	}

	return nil
}

// validateRespondComponent validates the response component structure
func validateRespondComponent(respond interface{}) error {
	// Respond can be an array of actions
	respondArray, ok := respond.([]interface{})
	if !ok {
		// Try as single object
		respondMap, ok := respond.(map[string]interface{})
		if !ok {
			return fmt.Errorf("respond must be an array or object")
		}
		// Convert to array for uniform validation
		respondArray = []interface{}{respondMap}
	}

	if len(respondArray) == 0 {
		// Empty respond is okay - just a detection without response
		return nil
	}

	// Validate each response action
	for i, action := range respondArray {
		actionMap, ok := action.(map[string]interface{})
		if !ok {
			return fmt.Errorf("respond action %d must be an object", i)
		}

		// Check for required 'action' field
		actionType, hasAction := actionMap["action"]
		if !hasAction {
			return fmt.Errorf("respond action %d must have 'action' field", i)
		}

		actionStr, ok := actionType.(string)
		if !ok {
			return fmt.Errorf("'action' field in respond action %d must be a string", i)
		}

		// Validate common action types
		validActions := map[string]bool{
			"report":           true,
			"task":             true,
			"add tag":          true,
			"remove tag":       true,
			"isolate network":  true,
			"rejoin network":   true,
			"service request":  true,
		}

		if !validActions[actionStr] {
			// It might be a valid action we don't know about
			// Don't fail validation
		}

		// 'report' action typically needs 'name' field
		if actionStr == "report" {
			_, hasName := actionMap["name"]
			if !hasName {
				return fmt.Errorf("'report' action requires 'name' field")
			}
		}

		// 'task' action needs 'command' field
		if actionStr == "task" {
			_, hasCommand := actionMap["command"]
			if !hasCommand {
				return fmt.Errorf("'task' action requires 'command' field")
			}
		}
	}

	return nil
}
