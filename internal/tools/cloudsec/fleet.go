package cloudsec

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// filterFleetByAIAgentPermission drops fleet rows for orgs whose ai_agent.operate
// permission the caller lacks, mutating resp in place.
//
// This tool is the one org-data-bearing read with no {oid} in its path, so the
// dispatcher — which keys its ai_agent.operate check off the effective OID —
// never covers it. An org that revoked ai_agent.operate did so to keep agents
// out of exactly this data, so the check is applied per row here instead.
//
// One WhoAmI backs every row: PermissionCache caches it against the caller's
// credential, so N orgs cost one round trip. If the check cannot run (enforcement
// off, no cache wired, WhoAmI failure) the payload is left untouched — this is a
// policy filter, not the tenant boundary, which the gateway owns.
func filterFleetByAIAgentPermission(ctx context.Context, org *lc.Organization, resp map[string]interface{}) {
	if !auth.IsPermissionEnforcementEnabled(ctx) {
		return
	}
	permCache := auth.GetPermissionCache(ctx)
	if permCache == nil {
		return
	}

	rows, ok := resp["orgs"].([]interface{})
	if !ok || len(rows) == 0 {
		return
	}

	kept := make([]interface{}, 0, len(rows))
	denied := 0
	for _, row := range rows {
		oid := ""
		if m, ok := row.(map[string]interface{}); ok {
			oid, _ = m["oid"].(string)
		}
		if oid == "" {
			// Cannot attribute the row to an org: keep it rather than silently
			// dropping data on a shape we do not recognize.
			kept = append(kept, row)
			continue
		}
		allowed, err := permCache.CheckPermission(ctx, org, oid, "ai_agent.operate")
		if err != nil {
			// Fail open on an infrastructure error, as above.
			kept = append(kept, row)
			continue
		}
		if !allowed {
			denied++
			continue
		}
		kept = append(kept, row)
	}

	if denied == 0 {
		return
	}

	resp["orgs"] = kept
	// The rollups are computed gateway-side across the unfiltered set, so once a
	// row is withheld they describe a population that includes it. Drop them
	// rather than reporting aggregates over data this caller may not see.
	delete(resp, "rollups")
	skipped, ok := resp["skipped"].(map[string]interface{})
	if !ok {
		skipped = map[string]interface{}{}
		resp["skipped"] = skipped
	}
	skipped["ai_agent_operate_denied"] = denied
	resp["rollups_withheld"] = true
}

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
			// No {oid} in this path: the gateway authorizes the org set from the
			// caller's token and stamps the list itself.
			resp, err := getJSON(ctx, org, "cloudsec/fleet/overview", q)
			if err != nil {
				return tools.ErrorResult(describeErr(err)), nil
			}
			// The route carries no {oid}, so the dispatcher's ai_agent.operate
			// check never runs for this tool — but every row is one org's posture
			// data, and an org that revoked ai_agent.operate revoked exactly this.
			// Drop those rows rather than erroring, matching how the gateway
			// silently excludes orgs that fail its own filters.
			filterFleetByAIAgentPermission(ctx, org, resp)
			return tools.SuccessResult(resp), nil
		},
	})
}
