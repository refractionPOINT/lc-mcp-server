package cloudsec

import (
	"context"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// registerPosture registers the org-level posture summary and trend reads.
func registerPosture() {
	register(toolDef{
		name: "cloudsec_get_overview",
		description: "Get the organization's composed cloud-security risk overview in one round-trip: " +
			"posture score, severity distribution, top attack paths, account coverage, the score trend and recent finding changes. " +
			"Start here before drilling into cloudsec_list_findings.",
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithNumber("trend_days",
				mcp.Description("Days of score trend to include (default 30)")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addInt(q, args, "trend_days", 0)
			return readGET(ctx, "overview", q)
		},
	})

	register(toolDef{
		name:        "cloudsec_get_risk_trend",
		description: "Get the organization's cloud-security risk-score history over time (the overview sparkline), oldest first.",
		readOnly:    true,
		params: []mcp.ToolOption{
			mcp.WithNumber("trend_days",
				mcp.Description("Days of score trend to include (default 30)")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addInt(q, args, "trend_days", 0)
			return readGET(ctx, "risk-trend", q)
		},
	})

	register(toolDef{
		name:        "cloudsec_list_changes",
		description: "List recent cloud-finding lifecycle changes (created/closed), newest first.",
		readOnly:    true,
		params: []mcp.ToolOption{
			mcp.WithNumber("limit",
				mcp.Description("Maximum number of change events (default 50, clamped to 1000)")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addInt(q, args, "limit", maxPageLimit)
			return readGET(ctx, "changes", q)
		},
	})

	register(toolDef{
		name: "cloudsec_get_scan_status",
		description: "Get the cloud-collection sweep status for one provider: whether a sweep is running, when it last started/completed, " +
			"the last diff stats, and any error (including a free-tier gate reason). " + hiveNote,
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithString("provider",
				mcp.Description("Provider to read status for (gcp | aws | azure | okta | …); defaults to gcp server-side. Case-insensitive: the value is lowercased before it is sent, because the backend lookup is case-sensitive on lowercase provider ids")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			// The backend scan-state read is a case-sensitive lookup on lowercase
			// provider ids, so "AWS" would silently read as never-scanned.
			if p := strings.ToLower(strings.TrimSpace(argString(args, "provider"))); p != "" {
				q["provider"] = p
			}
			return readGET(ctx, "scan-status", q)
		},
	})

	register(toolDef{
		name: "cloudsec_get_topology",
		description: "Get the pre-aggregated estate topology: per-scope node counts and inter-scope relationship rollups, " +
			"a response whose size is independent of resource count. " +
			"available:false means the projector has not materialized this org yet — fall back to cloudsec_list_inventory.",
		readOnly: true,
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return readGET(ctx, "topology", lc.Dict{})
		},
	})

	register(toolDef{
		name: "cloudsec_list_chokepoints",
		description: "List the estate-wide chokepoints: shared attack-path hops ranked by how many distinct paths each one breaks, " +
			"plus the total attack-path count — so a fix can be framed as 'closes N of M paths'. " +
			"Empty when the estate has no shared hops or has not been analyzed yet.",
		readOnly: true,
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return readGET(ctx, "chokepoints", lc.Dict{})
		},
	})
}
