package cloudsec

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// V2 persists historical controls rather than treating missing detector proof as a pass.
func registerComplianceV2() {
	for _, spec := range []struct {
		name, suffix, description string
		strings                   []string
		numbers                   map[string]int
	}{
		{"cloudsec_list_compliance_runs", "compliance/runs", "List immutable compliance runs. Supply run_id to return that historical run AND its complete control snapshot (controls); framework/assignment choose a listing otherwise.", []string{"run_id", "framework", "assignment"}, map[string]int{"limit": 200}},
		{"cloudsec_list_compliance_attestations", "compliance/attestations", "Read immutable control attestation revisions for a framework/assignment. Review scope, expiry, approval and revocation before treating evidence as valid.", []string{"framework", "assignment"}, nil},
		{"cloudsec_list_compliance_events", "compliance/events", "Read material control-state changes for compliance drift.", []string{"assignment"}, map[string]int{"days": 36500, "limit": 1000}},
		{"cloudsec_export_compliance_run", "compliance/export", "Render an immutable compliance run as JSON, CSV or PDF. The response is the gateway's artifact object; returned content/URLs are never fetched by this tool with org credentials.", []string{"run_id", "format", "brand"}, nil},
		{"cloudsec_list_compliance_schedules", "compliance/schedules", "Read recurring compliance assessment/delivery schedules.", nil, nil},
		{"cloudsec_get_azure_scope_hierarchy", "azure/scope-hierarchy", "Read Azure tenant/management-group/subscription/resource-group containment evidence. These containment links are not traversable access grants.", nil, nil},
	} {
		params := []mcp.ToolOption{}
		for _, key := range spec.strings {
			opts := []mcp.PropertyOption{mcp.Description(complianceFieldHelp(key))}
			if key == "run_id" && spec.name == "cloudsec_export_compliance_run" {
				opts = append(opts, mcp.Required())
			}
			params = append(params, mcp.WithString(key, opts...))
		}
		for _, key := range []string{"days", "limit"} {
			if max, ok := spec.numbers[key]; ok {
				params = append(params, mcp.WithNumber(key, mcp.Description(fmt.Sprintf("Positive whole number, maximum %d", max))))
			}
		}
		register(toolDef{name: spec.name, description: spec.description, readOnly: true, params: params, handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			required := []string{}
			if spec.name == "cloudsec_export_compliance_run" {
				required = []string{"run_id"}
			}
			q, e := boundedCodeFields(args, required, spec.strings...)
			if e != nil {
				return tools.ErrorResult(e.Error()), nil
			}
			for k, max := range spec.numbers {
				if _, present := args[k]; present {
					n, e := strictPositiveInt(args, k, max)
					if e != nil {
						return tools.ErrorResult(e.Error()), nil
					}
					q[k] = n
				}
			}
			if f, ok := q["format"]; ok && !contains([]string{"json", "csv", "pdf"}, f.(string)) {
				return tools.ErrorResult("format must be json, csv or pdf"), nil
			}
			return readProductGET(ctx, spec.suffix, lc.Dict(q))
		}})
	}
	register(toolDef{name: "cloudsec_create_compliance_run", description: "Evaluate compliance with positive detector execution proof and persist an immutable historical run. Missing or stale detector proof is unknown, not pass. Requires cloudsec.set; assignment's framework supersedes framework.", params: []mcp.ToolOption{mcp.WithString("framework"), mcp.WithString("assignment"), mcp.WithString("run_id", mcp.Description("Optional run id for the historical snapshot"))}, handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
		b, e := boundedCodeFields(args, nil, "framework", "assignment", "run_id")
		if e != nil {
			return tools.ErrorResult(e.Error()), nil
		}
		return callPOST(ctx, "compliance/v2", b, defaultTimeout)
	}})
	register(toolDef{name: "cloudsec_create_compliance_attestation", description: "Write an attributed immutable control attestation revision (cloudsec.set). Server binds tenant/actor/framework/scope. Read the assessment and prior revisions first. Revocation is a later revision with revoked_at, never an overwrite. Evidence must use credential-free https://, output:// or ticket:// references; no inline secrets.", params: []mcp.ToolOption{mcp.WithObject("attestation", mcp.Required(), mcp.Description("Revision object: id, revision, assignment, framework_id, control_key, outcome (pass/fail/not_applicable), rationale, effective_at, expires_at; optional approved_at, evidence_refs, supersedes_id, revoked_at, expected_scope_hash and expected_framework_version. RFC3339 timestamps. Tenant, framework version, scope and actor are server-owned."))}, handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
		return postProductObject(ctx, args, "attestation", "compliance/attestations")
	}})
	register(toolDef{name: "cloudsec_set_compliance_schedule", description: "Create or revise an organization-scoped weekly/monthly compliance assessment/delivery schedule (cloudsec.set). This replaces schedule configuration: read current schedules before writing. Delivery references are output:// or secret://, never inline credentials or a webhook URL.", destructive: true, params: []mcp.ToolOption{mcp.WithObject("schedule", mcp.Required(), mcp.Description("Object: id, revision, assignment, framework_id, owner, cadence (weekly/monthly), delivery (output/email/webhook), destination_ref (output:// or secret://), formats (json/csv/pdf array), enabled, next_run_at (RFC3339). Server stamps tenant and actor."))}, handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
		return postProductObject(ctx, args, "schedule", "compliance/schedules")
	}})
}

func complianceFieldHelp(key string) string {
	switch key {
	case "format":
		return "json (default), csv or pdf"
	case "brand":
		return "Optional report branding selector"
	case "run_id":
		return "Immutable compliance run id"
	case "framework":
		return "Framework id (default cis-gcp; assignment overrides it)"
	case "assignment":
		return "Named scoped assignment; omit for whole-estate assessment"
	}
	return key
}
func postProductObject(ctx context.Context, args map[string]interface{}, key, suffix string) (*mcp.CallToolResult, error) {
	object, ok := args[key].(map[string]interface{})
	if !ok || len(object) == 0 {
		return tools.ErrorResultf("%s must be a nonempty JSON object", key), nil
	}
	for _, name := range []string{"oid", "by", "assessor", "approver", "created_by", "updated_by", "revoked_by"} {
		if _, present := object[name]; present {
			return tools.ErrorResultf("%s is server-owned; omit it from %s", name, key), nil
		}
	}
	b, e := json.Marshal(object)
	if e != nil || len(b) > 1<<20 {
		return tools.ErrorResultf("%s must be JSON at most 1 MiB", key), nil
	}
	return callPOST(ctx, suffix, object, defaultTimeout)
}
