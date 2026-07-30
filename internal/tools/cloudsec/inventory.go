package cloudsec

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// inventorySelectorParams describes the generic inventory selectors. provider,
// account and region are single-valued: the gateway only accepts the repeatable
// form under type=Identity, and an array sent to the generic walk reads as unset.
func inventorySelectorParams() []mcp.ToolOption {
	return []mcp.ToolOption{
		mcp.WithString("type",
			mcp.Description("Filter to one resource_type (e.g. compute_instance | Identity | ThirdPartyAsset)")),
		mcp.WithString("provider",
			mcp.Description("Producing-sweep filter (gcp | okta | google_workspace | …). Single-valued; with type=Identity use the repeatable 'source' selector to match several")),
		mcp.WithString("account",
			mcp.Description("Account/project filter. Single-valued, except with type=Identity where a list of values is also accepted")),
		mcp.WithString("region",
			mcp.Description("Region filter. Single-valued, except with type=Identity where a list of values is also accepted")),
		mcp.WithString("q",
			mcp.Description("Case-insensitive substring filter over the resource's identifying fields")),
		mcp.WithBoolean("account_unscoped",
			mcp.Description("Set true to drop the account scoping so the walk spans the whole estate")),
	}
}

// registerInventory registers the inventory, data-security, resource and graph reads.
func registerInventory() {
	register(toolDef{
		name: "cloudsec_list_inventory",
		description: "List the organization's cloud resource inventory — every collected resource with its type, account, region and properties. " +
			"Keyset-paginated via 'cursor'/'limit'. With type=Identity the rows are the MERGED identity inventory (one row per real identity, unified across the sweeps that observed it) " +
			"and the identity cross-filter selectors below additionally apply; they are ignored for every other type.",
		readOnly: true,
		params: append(append(inventorySelectorParams(),
			mcp.WithString("sort",
				mcp.Description("Page order: 'urn' (default — stable, safe for a full walk) or 'risk' with type=Identity / 'last_seen' with type=ThirdPartyAsset. A ranked walk can move a row across the cursor when the projector recomputes")),
		), append(identitySelectorParams(), pagingParams("resources")...)...),
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addInventorySelector(q, args)
			addScalars(q, args, "sort", "cursor")
			addInt(q, args, "limit", maxPageLimit)
			addIdentitySelector(q, args)
			return readGET(ctx, "inventory", q)
		},
	})

	register(toolDef{
		name: "cloudsec_get_inventory_facets",
		description: "Get the inventory resource counts grouped by resource type, account, provider and region, computed under the same selectors as cloudsec_list_inventory. " +
			"The identity cross-filter is deliberately NOT accepted here (this rollup counts system-of-record rows and cannot honor it) — " +
			"use cloudsec_get_identity_facets for the identity equivalent.",
		readOnly: true,
		params:   inventorySelectorParams(),
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addInventorySelector(q, args)
			return readGET(ctx, "inventory/facets", q)
		},
	})

	register(toolDef{
		name: "cloudsec_get_data_security_facets",
		description: "Get the data-security (DSPM) rollup over every data store: total / sensitive / public / public-sensitive counts plus the store-kind, sensitivity and exposure facets. " +
			"Computed server-side under the same selectors as cloudsec_list_data_stores, so the counts always describe the rows that list returns.",
		readOnly: true,
		params:   dataStoreSelectorParams(false),
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addDataStoreSelector(q, args, false)
			return readGET(ctx, "data-security/facets", q)
		},
	})

	register(toolDef{
		name:        "cloudsec_list_data_stores",
		description: "List the data-store rows behind the DSPM facet counts, keyset-paginated and served from the materialized graph store under the same selectors as cloudsec_get_data_security_facets.",
		readOnly:    true,
		params:      dataStoreSelectorParams(true),
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addDataStoreSelector(q, args, true)
			return readGET(ctx, "data-security/stores", q)
		},
	})

	register(toolDef{
		name: "cloudsec_get_resource",
		description: "Get the single canonical record for any urn the system-of-record or security graph knows: " +
			"{urn, resource_type, name, account, region, is_public, is_sensitive, props, first_seen}. " +
			"Covers derived graph nodes (vulnerabilities, identities) that have no inventory row. Returns resource:null when the urn is unknown.",
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithString("urn",
				mcp.Required(),
				mcp.Description("The canonical lcrn of the resource to fetch")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			urn := argString(args, "urn")
			if urn == "" {
				return tools.ErrorResult("urn parameter is required"), nil
			}
			return readGET(ctx, "resource", lc.Dict{"urn": urn})
		},
	})

	register(toolDef{
		name: "cloudsec_get_graph_neighbors",
		description: "Expand one resource's 1-hop neighborhood in the security graph: every node directly connected to the urn (in either direction) plus the connecting edges, " +
			"in the same {graph:{nodes, edges}} shape a graph query returns. Server-bounded and ranked (sensitive, then public, then data/identity); " +
			"'truncated' is true when the resource has more neighbors than the cap.",
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithString("urn",
				mcp.Required(),
				mcp.Description("The canonical lcrn of the resource to expand from")),
			mcp.WithNumber("limit",
				mcp.Description("Maximum neighbors to return (default 200, hard cap 500)")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			urn := argString(args, "urn")
			if urn == "" {
				return tools.ErrorResult("urn parameter is required"), nil
			}
			q := lc.Dict{"urn": urn}
			addInt(q, args, "limit", maxNeighborLimit)
			return readGET(ctx, "graph/neighbors", q)
		},
	})

	register(toolDef{
		name: "cloudsec_list_queries",
		description: "List the built-in cloud-security query pack: the canonical security questions runnable by name with cloudsec_run_query. " +
			"Org-defined saved queries live in the \"cloudsec_query\" hive — reach them with the generic hive tools (list_rules / get_rule / set_rule with hive_name).",
		readOnly: true,
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return readGET(ctx, "queries", lc.Dict{})
		},
	})
}
