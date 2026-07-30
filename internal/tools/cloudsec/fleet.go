package cloudsec

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// registerFleet registers the free-tier standing read and the multi-org fleet board.
func registerFleet() {
	register(toolDef{
		name: "cloudsec_get_free_tier_status",
		description: "Report whether the organization is on the cloud-security free tier and the limits that apply — " +
			"read it before adding a provider, so a refused write is explained in advance. " +
			"The trial countdown is deliberately not reported here; the collector publishes a gated reason through cloudsec_get_scan_status instead. " + hiveNote,
		readOnly: true,
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return readGET(ctx, "free-tier", lc.Dict{})
		},
	})

	register(toolDef{
		name: "cloudsec_get_fleet_overview",
		description: "Get the multi-org cloud-security posture board in one call: one posture row per authorized org (score, severity distribution, trend direction, coverage/freshness, usage counters) " +
			"plus, on the first page, the cross-tenant rollups (widely-recurring rules, fleet risk distribution, orgs with failing providers). " +
			"The org set is whatever the CALLING TOKEN can see, narrowed by 'oids' and/or an org 'group', intersected with the orgs holding cloudsec.get that are subscribed to the extension; " +
			"an org failing either filter is excluded rather than erroring (see 'skipped'). " +
			"IMPORTANT: with an organization-scoped API key the token sees exactly one org, so the board degrades to a single row — a user-scoped credential is needed for a real fleet view. " +
			"Rate-limited to 120 calls/hour.",
		readOnly: true,
		// The route carries no {oid}: the gateway resolves the org set from the
		// caller's own token.
		noOID: true,
		params: []mcp.ToolOption{
			mcp.WithArray("oids", mcp.WithStringItems(),
				mcp.Description(fmt.Sprintf("Explicit org ids to include; each must be a valid UUID or the call fails. Omit (with no 'group') to span every org the token can see. At most %d orgs resolve per call", maxFleetOids))),
			mcp.WithString("group",
				mcp.Description("An org-group id whose member orgs to include; the caller must be a member or owner of the group")),
			mcp.WithString("cursor",
				mcp.Description("Opaque keyset token returned as 'next_cursor' by a previous page; omit for the first page")),
			mcp.WithNumber("limit",
				mcp.Description(fmt.Sprintf("Maximum orgs per page (default 25, hard cap %d)", maxFleetLimit))),
			mcp.WithNumber("trend_days",
				mcp.Description("Days of score trend per org (default 30)")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// This is a user-level read, so it goes through the raw client rather than
			// GetOrganization: in UID mode there may be no OID in context at all, and
			// the route does not want one.
			client, err := tools.GetClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get client: %v", err), nil
			}
			org, err := lc.NewOrganization(client)
			if err != nil {
				return tools.ErrorResultf("failed to build request client: %v", err), nil
			}
			q := lc.Dict{}
			addStrings(q, args, "oids")
			addScalars(q, args, "group", "cursor")
			addInt(q, args, "limit", maxFleetLimit)
			addInt(q, args, "trend_days", 0)
			// No {oid} in this path: the gateway is the sole authorizer and stamps
			// the org list itself.
			return readGETOrg(org, "cloudsec/fleet/overview", q)
		},
	})
}
