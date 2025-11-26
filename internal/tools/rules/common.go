package rules

import (
	"fmt"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// BuildRuleFromComponents constructs a D&R rule from detect and respond components.
// It handles type validation and normalization of the detect/respond structures.
//
// Parameters:
//   - detect: The detection component (must be a map[string]interface{})
//   - respond: The response component (can be nil, array, or single object)
//   - defaultActionName: Name to use for the default report action if respond is nil
//
// Returns the constructed rule or an error if validation fails.
func BuildRuleFromComponents(detect, respond interface{}, defaultActionName string) (lc.Dict, error) {
	rule := lc.Dict{}

	// Handle detect component - must be a map
	switch d := detect.(type) {
	case map[string]interface{}:
		rule["detect"] = d
	default:
		return nil, fmt.Errorf("detect must be an object/map")
	}

	// Handle respond component
	if respond != nil {
		switch r := respond.(type) {
		case []interface{}:
			rule["respond"] = r
		case map[string]interface{}:
			// Single respond object, wrap in array
			rule["respond"] = []interface{}{r}
		default:
			return nil, fmt.Errorf("respond must be an array or object")
		}
	} else {
		// Default respond action
		rule["respond"] = []interface{}{
			map[string]interface{}{
				"action": "report",
				"name":   defaultActionName,
			},
		}
	}

	return rule, nil
}

// GetNamespaceWithDefault returns the namespace from args, defaulting to "general" if not provided.
func GetNamespaceWithDefault(args map[string]interface{}) string {
	if ns, ok := args["namespace"].(string); ok && ns != "" {
		return ns
	}
	return "general"
}
