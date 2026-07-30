package cloudsec

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// registerCAASM registers the CAASM (third-party asset attack surface) reads and the
// per-provider coverage manifests.
func registerCAASM() {
	register(toolDef{
		name: "cloudsec_list_caasm_assets",
		description: "List the merged third-party asset inventory: every device/identity the org's connected tools (EDR / IdP / MDM / scanners) report, " +
			"entity-resolved to one row per real asset with per-source provenance kept in props (sources, merge key, hostname/serial/MACs/email, last_seen). " +
			"Keyset-paginated. The ThirdPartyAsset type is stamped server-side, so this route cannot be widened to other resource types.",
		readOnly: true,
		params: append([]mcp.ToolOption{
			mcp.WithString("q",
				mcp.Description("Substring filter over the asset urn/name/hostname/serial/os/email")),
			mcp.WithArray("kind", mcp.WithStringItems(),
				mcp.Description("Asset-kind filter (device | user | …). Repeatable")),
			mcp.WithArray("source", mcp.WithStringItems(),
				mcp.Description("Observing-tool filter (sentinelone | ms_graph | limacharlie | …). Repeatable")),
			mcp.WithArray("posture_encryption", mcp.WithStringItems(),
				mcp.Description("Disk-encryption posture filter. Repeatable. Pass an EMPTY STRING element to select assets no source reported this fact for — unreported is not compliant")),
			mcp.WithArray("posture_screen_lock", mcp.WithStringItems(),
				mcp.Description("Screen-lock posture filter. Repeatable; an empty-string element selects unreported")),
			mcp.WithArray("posture_compromised", mcp.WithStringItems(),
				mcp.Description("Compromised-state posture filter. Repeatable; an empty-string element selects unreported")),
			mcp.WithArray("posture_managed", mcp.WithStringItems(),
				mcp.Description("Managed-state posture filter. Repeatable; an empty-string element selects unreported")),
			mcp.WithString("sort",
				mcp.Description("Page order: 'urn' (default — stable, safe for a full walk) or 'last_seen' for most-recently-observed first")),
		}, pagingParams("assets")...),
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addScalars(q, args, "q", "sort", "cursor")
			addStrings(q, args, "kind", "source",
				"posture_encryption", "posture_screen_lock", "posture_compromised", "posture_managed")
			addInt(q, args, "limit", maxPageLimit)
			return readGET(ctx, "caasm/assets", q)
		},
	})

	register(toolDef{
		name: "cloudsec_list_caasm_coverage",
		description: "List the org's coverage-gap findings: assets observed by at least one connected tool but missing a tool the expected-coverage policy requires " +
			"(e.g. seen by the IdP, no EDR). Same row shape as cloudsec_list_findings with the coverage_gap class stamped server-side. " +
			"Declare the expectations with cloudsec_set_caasm_policy.",
		readOnly: true,
		params: append([]mcp.ToolOption{
			mcp.WithArray("status", mcp.WithStringItems(),
				mcp.Description("Status filter: 'open' | 'resolved' | 'accepted'. Repeatable")),
			mcp.WithArray("severity", mcp.WithStringItems(),
				mcp.Description("Severity filter. Repeatable")),
			mcp.WithString("q", mcp.Description("Substring filter")),
			mcp.WithString("sort", mcp.Description("Sort field: 'lc_risk' (default) | 'severity' | 'first_seen'")),
			mcp.WithString("order", mcp.Description("Sort direction: 'desc' (default) | 'asc'")),
		}, pagingParams("findings")...),
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addStrings(q, args, "severity", "status")
			addScalars(q, args, "q", "sort", "order", "cursor")
			addInt(q, args, "limit", maxPageLimit)
			return readGET(ctx, "caasm/coverage", q)
		},
	})

	register(toolDef{
		name: "cloudsec_get_caasm_policy",
		description: "Get the org's stored CAASM expected-coverage policy. The policy is one system-of-record row, so the response is the standard resource-list shape: " +
			"'resources' holds zero rows (no policy declared — coverage evaluation is then a no-op by design) or one row whose 'props' object is the policy ({expect:[...]}).",
		readOnly: true,
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return readGET(ctx, "caasm/policy", lc.Dict{})
		},
	})

	register(toolDef{
		name: "cloudsec_get_provider_manifests",
		description: "Get the per-provider coverage manifests: for each provider the collectors (resource kinds + edge kinds) with their status, the posture checks that can fire, " +
			"the activity/CIEM support level, the validation grade, the known gaps, and this org's own scan coverage/freshness. " +
			"Pass 'type' for a single provider (returned under 'manifest' instead of 'manifests'), including a provider the org has never swept. " + hiveNote,
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithString("type",
				mcp.Description("Provider type to fetch the manifest for (e.g. gcp | aws | azure | okta); omit to list every provider the org has a manifest or a sweep for")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addScalars(q, args, "type")
			return readGET(ctx, "providers/manifest", q)
		},
	})
}
