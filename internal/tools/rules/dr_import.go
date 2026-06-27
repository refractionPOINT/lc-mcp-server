package rules

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterImportDRRules()
}

// importNamespaceToHive maps an import namespace ("general"/"managed") to its hive name.
func importNamespaceToHive(args map[string]interface{}) (string, string, error) {
	ns := "general"
	if v, ok := args["namespace"].(string); ok && v != "" {
		ns = v
	}
	switch ns {
	case "general":
		return "dr-general", ns, nil
	case "managed":
		return "dr-managed", ns, nil
	default:
		return "", "", fmt.Errorf("unsupported namespace '%s' (expected 'general' or 'managed')", ns)
	}
}

// RegisterImportDRRules registers the import_dr_rules tool.
func RegisterImportDRRules() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "import_dr_rules",
		Description: "Bulk import (upsert) D&R rules into a namespace",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("import_dr_rules",
			mcp.WithDescription("Bulk import (upsert) D&R rules into a namespace. Each rule is an object with 'detect' (and optional 'respond'). Use dry_run to preview without writing."),
			mcp.WithObject("rules",
				mcp.Required(),
				mcp.Description("Map of rule_name -> {detect, respond} objects to upsert")),
			mcp.WithString("namespace",
				mcp.Description("D&R namespace: 'general' (default) or 'managed'")),
			mcp.WithBoolean("dry_run",
				mcp.Description("If true, validate and report what would change without writing")),
			mcp.WithDestructiveHintAnnotation(true),
			mcp.WithIdempotentHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			rulesArg, ok := args["rules"].(map[string]interface{})
			if !ok || len(rulesArg) == 0 {
				return tools.ErrorResult("rules parameter is required and must be a non-empty object"), nil
			}

			hiveName, namespace, err := importNamespaceToHive(args)
			if err != nil {
				return tools.ErrorResultf("%v", err), nil
			}

			dryRun := false
			if v, ok := args["dry_run"].(bool); ok {
				dryRun = v
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Normalize and validate each rule's content.
			type preparedRule struct {
				name string
				data lc.Dict
			}
			prepared := make([]preparedRule, 0, len(rulesArg))
			validationErrors := map[string]string{}

			for name, raw := range rulesArg {
				content, ok := raw.(map[string]interface{})
				if !ok {
					validationErrors[name] = "rule must be an object with a 'detect' field"
					continue
				}
				detect, hasDetect := content["detect"]
				if !hasDetect {
					validationErrors[name] = "rule must contain a 'detect' field"
					continue
				}
				data := lc.Dict{"detect": detect}
				if respond, hasRespond := content["respond"]; hasRespond {
					data["respond"] = respond
				}
				prepared = append(prepared, preparedRule{name: name, data: data})
			}

			if len(validationErrors) > 0 {
				return tools.ErrorResultf("validation failed for %d rule(s): %v", len(validationErrors), validationErrors), nil
			}

			if dryRun {
				wouldChange := make([]string, 0, len(prepared))
				perRuleValidation := map[string]interface{}{}
				for _, p := range prepared {
					wouldChange = append(wouldChange, p.name)
					// Best-effort server-side validation of each rule.
					if res, vErr := org.ValidateDRRule(p.data); vErr != nil {
						perRuleValidation[p.name] = fmt.Sprintf("validation request error: %v", vErr)
					} else if res != nil && res.Error != "" {
						perRuleValidation[p.name] = res.Error
					} else {
						perRuleValidation[p.name] = "ok"
					}
				}
				return tools.SuccessResult(map[string]interface{}{
					"dry_run":      true,
					"namespace":    namespace,
					"would_upsert": wouldChange,
					"count":        len(wouldChange),
					"validation":   perRuleValidation,
				}), nil
			}

			// Build and execute the batch upsert.
			hive := lc.NewHiveClient(org)
			batch := hive.NewBatchOperations()
			enabled := true
			hiveID := lc.HiveID{
				Name:      hiveName,
				Partition: lc.PartitionID(org.GetOID()),
			}
			for _, p := range prepared {
				record := lc.RecordID{
					Hive: hiveID,
					Name: lc.RecordName(p.name),
				}
				batch.SetRecord(record, lc.ConfigRecordMutation{
					Data:   p.data,
					UsrMtd: &lc.UsrMtd{Enabled: enabled},
				})
			}

			responses, err := batch.Execute()
			if err != nil {
				return tools.ErrorResultf("failed to import D&R rules: %v", err), nil
			}

			// Surface any per-operation errors.
			opErrors := []string{}
			for i, r := range responses {
				if r.Error != "" {
					name := ""
					if i < len(prepared) {
						name = prepared[i].name
					}
					opErrors = append(opErrors, fmt.Sprintf("%s: %s", name, r.Error))
				}
			}
			if len(opErrors) > 0 {
				return tools.ErrorResultf("imported with %d error(s): %v", len(opErrors), opErrors), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":   true,
				"namespace": namespace,
				"imported":  len(prepared),
				"message":   fmt.Sprintf("Successfully imported %d D&R rule(s) into %s", len(prepared), hiveName),
			}), nil
		},
	})
}
