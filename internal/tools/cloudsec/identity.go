package cloudsec

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// registerIdentity registers the CIEM / identity-access reads.
func registerIdentity() {
	register(toolDef{
		name: "cloudsec_get_public_access",
		description: "Get the CIEM findings where a public or external principal holds an allow grant on a sensitive resource (workloads and data stores), " +
			"plus a per-principal rollup. This is a risk-ranked top-N; use cloudsec_list_identities for the filterable, paginated population.",
		readOnly: true,
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return readGET(ctx, "ciem/public-access", lc.Dict{})
		},
	})

	register(toolDef{
		name: "cloudsec_get_identity",
		description: "Get the effective-access rollup for one identity urn: grant / privileged / sensitive-reach counts, posture facets and risk score. " +
			"Works for ANY identity, not just the risk-ranked top-N. Returns identity:null when the urn is not a known identity.",
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithString("urn",
				mcp.Required(),
				mcp.Description("The canonical lcrn of the identity to fetch")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			urn := argString(args, "urn")
			if urn == "" {
				return tools.ErrorResult("urn parameter is required"), nil
			}
			return readGET(ctx, "ciem/identity", lc.Dict{"urn": urn})
		},
	})

	register(toolDef{
		name: "cloudsec_get_identity_facets",
		description: "Get the cross-cutting identity facet counts for the CIEM worklist (kind, MFA state, risk band, plus the admin/external/public/disabled/dormant/escalation/sensitive-access rollups and the total). " +
			"The selectors CROSS-FILTER the rail: each dimension is counted under the other active selectors but not its own, so a value's count is exactly how many rows selecting it would list. " +
			"With no selectors this is the whole-population rollup. Pass the same selectors to cloudsec_list_identities to get the matching rows.",
		readOnly: true,
		params:   append(identitySelectorParams(), identityPlacementParams()...),
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addIdentitySelector(q, args)
			addIdentityPlacement(q, args)
			return readGET(ctx, "ciem/facets", q)
		},
	})

	register(toolDef{
		name: "cloudsec_list_identities",
		description: "List one keyset-paginated page of the identity population with the same per-principal effective-access rollup rows cloudsec_get_public_access carries, " +
			"but server-filtered and pageable instead of a top-N. Ranked by risk score descending by default. " +
			"Takes the same selectors as cloudsec_get_identity_facets, so the rail's counts and this list always describe the same population. " +
			"A walk that spans a projector recompute can move a row across the cursor, so use it for browsing rather than exact exports.",
		readOnly: true,
		params: append(append(identitySelectorParams(), identityPlacementParams()...),
			pagingParams("principals")...),
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addIdentitySelector(q, args)
			addIdentityPlacement(q, args)
			addScalars(q, args, "cursor")
			addInt(q, args, "limit", maxPageLimit)
			return readGET(ctx, "ciem/identities", q)
		},
	})
}
