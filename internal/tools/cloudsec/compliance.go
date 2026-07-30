package cloudsec

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// registerCompliance registers the compliance assessment reads.
func registerCompliance() {
	register(toolDef{
		name: "cloudsec_get_compliance_report",
		description: "Get the per-control pass/fail compliance assessment for a framework against the org's open findings, with evidence and a summary score. " +
			"Defaults to cis-gcp server-side. Pass 'assignment' to evaluate a named scoped assignment instead (its framework over its in-scope estate); 'framework' is then ignored.",
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithString("framework",
				mcp.Description("Framework id to assess (e.g. cis-gcp); defaults to cis-gcp. See cloudsec_list_compliance_frameworks. Ignored when 'assignment' is set")),
			mcp.WithString("assignment",
				mcp.Description("Name of a scoped compliance assignment to evaluate instead of the whole estate. See cloudsec_list_compliance_assignments")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addScalars(q, args, "framework", "assignment")
			return readGET(ctx, "compliance", q)
		},
	})

	register(toolDef{
		name:        "cloudsec_list_compliance_frameworks",
		description: "List the selectable compliance frameworks (id, name, version, control count) for cloudsec_get_compliance_report.",
		readOnly:    true,
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return readGET(ctx, "compliance/frameworks", lc.Dict{})
		},
	})

	register(toolDef{
		name: "cloudsec_list_compliance_assignments",
		description: "List the org's scoped compliance assignments (name, framework, scope, and a scoped summary score each). " +
			"Empty when the org has defined none, in which case only the whole-estate default applies.",
		readOnly: true,
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return readGET(ctx, "compliance/assignments", lc.Dict{})
		},
	})
}
