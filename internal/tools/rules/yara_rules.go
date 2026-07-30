package rules

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register YARA rule management tools
	RegisterListYaraRules()
	RegisterGetYaraRule()
	RegisterSetYaraRule()
	RegisterDeleteYaraRule()
	RegisterValidateYaraRule()
}

// RegisterListYaraRules registers the list_yara_rules tool
func RegisterListYaraRules() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_yara_rules",
		Description: "List YARA sources and deployed rule-sets",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("list_yara_rules",
			mcp.WithDescription("List both kinds of YARA object in the organization: 'sources' (individual YARA rule sources — these names are what get_yara_rule, set_yara_rule and delete_yara_rule take) and 'rule_sets' (deployments mapping sources to sensors — these names are what set_yara_ruleset and delete_yara_ruleset take). Source content is omitted here; fetch it with get_yara_rule (a source whose 'source' is empty holds literal rules rather than a remote URL)."),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// The two halves are independent listings, so one of them failing
			// (they have separate failure modes: the source listing resolves the
			// content of every literal source) still returns the other.
			sources, sourcesErr := org.YaraListSources()
			ruleSets, ruleSetsErr := org.YaraListRules()
			if sourcesErr != nil && ruleSetsErr != nil {
				return tools.ErrorResultf("failed to list YARA sources (%v) and rule-sets (%v)", sourcesErr, ruleSetsErr), nil
			}

			// Keep the listing an index: the source bodies are what
			// get_yara_rule is for, and they are large.
			sourceIndex := make(map[string]interface{}, len(sources))
			for name, source := range sources {
				sourceIndex[name] = map[string]interface{}{
					"by":      source.Author,
					"source":  source.Source,
					"updated": source.LastUpdated,
				}
			}

			result := map[string]interface{}{
				"sources":        sourceIndex,
				"source_count":   len(sourceIndex),
				"rule_sets":      ruleSets,
				"rule_set_count": len(ruleSets),
			}
			if sourcesErr != nil {
				result["sources_error"] = sourcesErr.Error()
			}
			if ruleSetsErr != nil {
				result["rule_sets_error"] = ruleSetsErr.Error()
			}
			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterGetYaraRule registers the get_yara_rule tool
func RegisterGetYaraRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_yara_rule",
		Description: "Get a specific YARA source by name",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("get_yara_rule",
			mcp.WithDescription("Get the content of a specific YARA source by name. Deals in sources, not deployed rule-sets; list them with list_yara_rules or list_yara_sources."),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name of the YARA source to retrieve")),
			mcp.WithReadOnlyHintAnnotation(true),
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

			// Get YARA rule source content
			ruleContent, err := org.YaraGetSource(ruleName)
			if err != nil {
				return tools.ErrorResultf("failed to get YARA rule: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"rule": map[string]interface{}{
					"name":    ruleName,
					"content": ruleContent,
				},
			}), nil
		},
	})
}

// RegisterSetYaraRule registers the set_yara_rule tool
func RegisterSetYaraRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_yara_rule",
		Description: "Create or update a YARA source",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("set_yara_rule",
			mcp.WithDescription("Create or update a YARA source. This creates a source, not a deployment: attach it to sensors with set_yara_ruleset."),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name for the YARA source")),
			mcp.WithString("rule_content",
				mcp.Required(),
				mcp.Description("YARA source content (the actual YARA syntax)")),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleName, ok := args["rule_name"].(string)
			if !ok || ruleName == "" {
				return tools.ErrorResult("rule_name parameter is required"), nil
			}

			ruleContent, ok := args["rule_content"].(string)
			if !ok || ruleContent == "" {
				return tools.ErrorResult("rule_content parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Add YARA rule source. The client-side heuristics are advisory
			// only -- the server does the real parse -- so they never block.
			yaraSource := lc.YaraSource{
				Content: ruleContent,
			}
			err = org.YaraSourceAdd(ruleName, yaraSource)
			if err != nil {
				return tools.ErrorResultf("failed to add/update YARA source: %v", err), nil
			}

			result := map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated YARA source '%s'", ruleName),
			}
			if advisories := yaraSyntaxAdvisories(ruleContent); len(advisories) > 0 {
				result["advisories"] = advisories
			}
			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterDeleteYaraRule registers the delete_yara_rule tool
func RegisterDeleteYaraRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_yara_rule",
		Description: "Delete a YARA source",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_yara_rule",
			mcp.WithDescription("Delete a YARA source. Deals in sources, not deployed rule-sets (see delete_yara_ruleset)."),
			mcp.WithString("rule_name",
				mcp.Required(),
				mcp.Description("Name of the YARA source to delete")),
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

			// Delete YARA rule source
			err = org.YaraSourceDelete(ruleName)
			if err != nil {
				return tools.ErrorResultf("failed to delete YARA rule: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted YARA rule '%s'", ruleName),
			}), nil
		},
	})
}

// RegisterValidateYaraRule registers the validate_yara_rule tool
func RegisterValidateYaraRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "validate_yara_rule",
		Description: "Validate YARA rule syntax",
		Profile:     "detection_engineering",
		RequiresOID: false, // Client-side validation, no OID needed
		Schema: mcp.NewTool("validate_yara_rule",
			mcp.WithDescription("Check YARA rule content with client-side heuristics. This is not a YARA parse: the authoritative validation happens server-side when the source is saved with set_yara_rule."),
			mcp.WithString("rule_content",
				mcp.Required(),
				mcp.Description("YARA rule content to validate")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ruleContent, ok := args["rule_content"].(string)
			if !ok || ruleContent == "" {
				return tools.ErrorResult("rule_content parameter is required"), nil
			}

			advisories := yaraSyntaxAdvisories(ruleContent)
			result := map[string]interface{}{
				"looks_like_yara": len(advisories) == 0,
				"advisories":      advisories,
				"note":            "heuristic check only; the authoritative YARA parse happens server-side when the source is saved",
			}
			if len(advisories) == 0 {
				result["message"] = "YARA rule content passes the client-side heuristics"
			} else {
				result["message"] = "YARA rule content did not pass every client-side heuristic; these are hints, not errors"
			}
			return tools.SuccessResult(result), nil
		},
	})
}

// yaraConditionRe matches a condition section header. YARA allows whitespace
// before the colon, so a plain "condition:" substring test misses legal rules.
var yaraConditionRe = regexp.MustCompile(`(?m)^\s*condition\s*:`)

// yaraSyntaxAdvisories reports what does not look like YARA about a source.
//
// These are heuristics, not a parse: the authoritative validation happens
// server-side when the source is saved (legion_config_hive def_yara parses it
// with gyp), and legal rules can trip them -- a brace inside a string literal
// unbalances the brace count, for instance. They must therefore never block a
// write, only inform the caller.
func yaraSyntaxAdvisories(ruleContent string) []string {
	advisories := []string{}

	if !strings.Contains(ruleContent, "rule ") {
		advisories = append(advisories, "no 'rule' keyword found")
	}

	openCount := strings.Count(ruleContent, "{")
	closeCount := strings.Count(ruleContent, "}")
	switch {
	case openCount == 0 || closeCount == 0:
		advisories = append(advisories, "no rule body braces found")
	case openCount != closeCount:
		advisories = append(advisories, "braces look unbalanced (expected if a string literal contains a brace)")
	}

	if !yaraConditionRe.MatchString(ruleContent) {
		advisories = append(advisories, "no 'condition:' section found")
	}

	return advisories
}
