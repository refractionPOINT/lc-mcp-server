// Package cloudsec exposes the LimaCharlie Cloud Security (CNAPP) API surface as MCP
// tools: the posture overview, the findings worklist and its triage writes, CIEM /
// identity access, the cloud inventory and Data Security (DSPM) rollups, compliance
// assessments, CAASM third-party asset coverage, the security-graph query DSL, the
// sensor <-> cloud-asset resolver, and the CSV exports.
//
// Every route lives under /v1/cloudsec/ on the API gateway
// (lc_api-go/service/endpoint_cloudsec*.go). Reads require the cloudsec.get
// permission, writes cloudsec.set, and the whole surface is gated on the
// organization's subscription to the ext-cloud-security extension.
package cloudsec

import (
	"context"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// profileName is the profile every cloudsec tool belongs to. The read-only subset is
// additionally listed in cloud_security_readonly by the profile definitions.
const profileName = "cloud_security"

func init() {
	registerPosture()
	registerFindings()
	registerIdentity()
	registerInventory()
	registerCompliance()
	registerCAASM()
	registerPolicyAids()
	registerResolve()
	registerExport()
	registerWrites()
	registerFleet()
}

// toolDef describes one cloudsec tool. Registering through a single helper keeps the
// extension-gate note, the annotations and the profile identical across ~45 tools.
type toolDef struct {
	name        string
	description string
	// readOnly marks a tool that changes nothing. It is true for the POST-shaped
	// previews too (run_query / policy suggest / the two simulates), which the
	// gateway documents as read-only (endpoint_cloudsec.go:908-914, 1085-1091).
	readOnly bool
	// destructive is only read when readOnly is false.
	destructive bool
	// noOID marks the one tool whose route has no {oid} (the fleet board).
	noOID   bool
	params  []mcp.ToolOption
	handler tools.ToolHandler
}

func register(d toolDef) {
	desc := d.description + " " + extGateNote
	opts := make([]mcp.ToolOption, 0, len(d.params)+2)
	opts = append(opts, mcp.WithDescription(desc))
	opts = append(opts, d.params...)
	if d.readOnly {
		// NewTool defaults DestructiveHint to true, so a read has to say otherwise
		// explicitly or it ships a contradictory pair of annotations.
		opts = append(opts,
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false))
	} else {
		opts = append(opts,
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(d.destructive))
	}

	tools.RegisterTool(&tools.ToolRegistration{
		Name:        d.name,
		Description: desc,
		Profile:     profileName,
		RequiresOID: !d.noOID,
		Schema:      mcp.NewTool(d.name, opts...),
		Handler:     d.handler,
	})
}

// ------------------------------------------------------------------
// call helpers
// ------------------------------------------------------------------

// readGET runs a GET cloudsec read for the context's organization and returns the
// gateway's payload unwrapped: request.respond writes the backend RPC's Data dict
// directly, so {"findings": [...], "next_cursor": ...} arrives as-is.
func readGET(ctx context.Context, suffix string, query lc.Dict) (*mcp.CallToolResult, error) {
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResultf("failed to get organization: %v", err), nil
	}
	return readGETOrg(org, orgPath(org, suffix), query)
}

// readGETOrg is readGET for a caller that already resolved the organization and/or
// needs a path that is not oid-scoped (the fleet board).
func readGETOrg(org *lc.Organization, path string, query lc.Dict) (*mcp.CallToolResult, error) {
	resp := map[string]interface{}{}
	if err := org.GenericGETRequest(path, query, &resp); err != nil {
		return tools.ErrorResultf("cloudsec request to %s failed: %s", path, describeErr(err)), nil
	}
	return tools.SuccessResult(resp), nil
}

// getJSON is readGETOrg for a caller that needs to post-process the payload
// before returning it.
func getJSON(ctx context.Context, org *lc.Organization, path string, query lc.Dict) (map[string]interface{}, error) {
	resp := map[string]interface{}{}
	if err := org.GenericGETRequest(path, query, &resp); err != nil {
		return nil, fmt.Errorf("cloudsec request to %s failed: %w", path, err)
	}
	return resp, nil
}

// callPOST runs a JSON-body cloudsec call for the context's organization.
func callPOST(ctx context.Context, suffix string, body map[string]interface{}, timeout time.Duration) (*mcp.CallToolResult, error) {
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResultf("failed to get organization: %v", err), nil
	}
	path := orgPath(org, suffix)
	resp, err := postJSON(ctx, org, path, body, timeout)
	if err != nil {
		return tools.ErrorResultf("cloudsec request to %s failed: %s", path, describeErr(err)), nil
	}
	return tools.SuccessResult(resp), nil
}

// ------------------------------------------------------------------
// shared schema fragments
// ------------------------------------------------------------------

// pagingParams are the keyset-pagination params. The gateway clamps limit to 1000.
func pagingParams(noun string) []mcp.ToolOption {
	return []mcp.ToolOption{
		mcp.WithString("cursor",
			mcp.Description("Opaque keyset token returned as 'next_cursor' by a previous page; omit for the first page")),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of "+noun+" for this page (clamped to 1000); omit for the backend default")),
	}
}

// findingSelectorParams describes the findings worklist filter set shared by the
// findings list, its facets, the cause rollup and the CSV export.
func findingSelectorParams(paging bool) []mcp.ToolOption {
	params := []mcp.ToolOption{
		mcp.WithArray("severity", mcp.WithStringItems(),
			mcp.Description("Severity filter: CRITICAL | HIGH | MEDIUM | LOW | INFO. Repeatable (OR within the key, AND across keys); at most 100 values are honored")),
		mcp.WithArray("finding_class", mcp.WithStringItems(),
			mcp.Description("Finding-class filter; call cloudsec_list_finding_classes for the live vocabulary. Repeatable")),
		mcp.WithArray("status", mcp.WithStringItems(),
			mcp.Description("Status filter, closed set: 'open' | 'resolved' | 'accepted'. 'accepted' is a live risk somebody signed off on carrying, NOT a fix. Repeatable")),
		mcp.WithArray("account", mcp.WithStringItems(),
			mcp.Description("Cloud account/project filter. Repeatable")),
		mcp.WithArray("owner", mcp.WithStringItems(),
			mcp.Description("Owner filter. Repeatable. An EMPTY STRING element selects the unassigned bucket, so [\"\"] means 'findings with no owner'")),
		mcp.WithBoolean("reachable",
			mcp.Description("Restrict to findings on internet-reachable (or not reachable) resources. Omit entirely for no constraint — absent is not false")),
		mcp.WithBoolean("kev",
			mcp.Description("Restrict to findings carrying a CISA KEV vulnerability (or not). Omit for no constraint")),
		mcp.WithString("source",
			mcp.Description("AppSec code-lane PRODUCER filter — which scanner found the finding. "+
				"'hosted' = the scan LimaCharlie ran; 'ingest' = a document the customer's own pipeline pushed (SARIF, CycloneDX, or a local scan); "+
				"'other' = a producer that is neither, today the source control's own detectors; "+
				"'none' = no code provenance at all, which on a cloud estate is nearly every finding. "+
				"'both' (and omitting it) applies no filter. A SCALAR, not a list — 'both' is what a multi-value selection would mean. "+
				"Applied inside the server's paged query, so cloudsec_get_finding_facets counts under it describe the same set this lists. "+
				"The 'source' facet's values sum to its total only on an UNFILTERED read — like every dimension it is counted with its own filter excluded while the total applies it — so compute a share without a source filter set. "+
				"The facet key is ABSENT (never zeroed) if the server has that dimension turned off. "+
				"An unrecognised value is REJECTED with an error naming it, not silently ignored. "+
				"NOTE this is unrelated to the 'source' on the identity tools, which names a producing cloud sweep")),
		mcp.WithString("q",
			mcp.Description("Free-text filter over the findings")),
		mcp.WithString("sort",
			mcp.Description("Sort field: 'lc_risk' (default) | 'severity' | 'first_seen'")),
		mcp.WithString("order",
			mcp.Description("Sort direction: 'desc' (default) | 'asc'")),
	}
	if paging {
		params = append(params, pagingParams("findings")...)
	}
	return params
}

// identitySelectorParams describes the merged-identity cross-filter. The same set
// reaches the identity list, the facet rail and the type=Identity inventory lane, so
// a facet count always describes the population the list would return.
func identitySelectorParams() []mcp.ToolOption {
	return []mcp.ToolOption{
		mcp.WithArray("source", mcp.WithStringItems(),
			mcp.Description("Producing-sweep filter (okta | gcp | google_workspace | …). Alias of 'provider'; use this form to select several. Repeatable")),
		mcp.WithArray("kind", mcp.WithStringItems(),
			mcp.Description("Identity kind filter (user | service_account | group | ai_agent | …). Repeatable")),
		mcp.WithArray("criticality", mcp.WithStringItems(),
			mcp.Description("Crown-jewel tier filter. Repeatable")),
		mcp.WithArray("risk_band", mcp.WithStringItems(),
			mcp.Description("Risk-band filter (critical | high | medium | low) — the band token, not a numeric range. Repeatable")),
		mcp.WithString("mfa",
			mcp.Description("MFA state: 'on' | 'off' | 'unknown'. 'unknown' means the MFA question does not apply or no identity provider reported it — it is NOT 'off'")),
		mcp.WithBoolean("admin",
			mcp.Description("Restrict to identities holding (or not holding) an admin role. Omit for no constraint")),
		mcp.WithBoolean("external",
			mcp.Description("Restrict to identities outside the org's own domains. Omit for no constraint")),
		mcp.WithBoolean("public",
			mcp.Description("Restrict to public principals (allUsers / allAuthenticatedUsers and equivalents). Omit for no constraint")),
		mcp.WithBoolean("disabled",
			mcp.Description("Restrict to disabled (or enabled) identities. Omit for no constraint")),
		mcp.WithBoolean("crown_jewel",
			mcp.Description("Restrict to identities the org's cloudsec_policy declares sensitive. Omit for no constraint")),
		mcp.WithBoolean("can_escalate",
			mcp.Description("Restrict to identities that can escalate their own privileges. Omit for no constraint")),
		mcp.WithBoolean("dormant_90d",
			mcp.Description("Restrict to identities with no observed activity in 90 days. Omit for no constraint")),
		mcp.WithBoolean("with_sensitive",
			mcp.Description("Restrict to principals holding at least one non-deny grant on a sensitive resource. Omit for no constraint")),
	}
}

// identityPlacementParams are the repeatable placement dimensions the identity-only
// routes accept (the inventory route keeps them single-valued).
func identityPlacementParams() []mcp.ToolOption {
	return []mcp.ToolOption{
		mcp.WithArray("provider", mcp.WithStringItems(),
			mcp.Description("Producing-sweep filter; alias of 'source'. Repeatable")),
		mcp.WithArray("account", mcp.WithStringItems(),
			mcp.Description("Account/project filter. Repeatable")),
		mcp.WithArray("region", mcp.WithStringItems(),
			mcp.Description("Region filter. Repeatable")),
		mcp.WithString("q",
			mcp.Description("Case-insensitive substring filter over the identity's urn/email/kind")),
	}
}

// dataStoreSelectorParams describes the Data Security (DSPM) selector set shared by
// the facet rollup and the store list.
func dataStoreSelectorParams(paging bool) []mcp.ToolOption {
	params := []mcp.ToolOption{
		mcp.WithArray("provider", mcp.WithStringItems(), mcp.Description("Cloud provider filter. Repeatable")),
		mcp.WithArray("account", mcp.WithStringItems(), mcp.Description("Account/project filter. Repeatable")),
		mcp.WithArray("region", mcp.WithStringItems(), mcp.Description("Region filter. Repeatable")),
		mcp.WithArray("store_kind", mcp.WithStringItems(),
			mcp.Description("Data-store kind filter (the DSPM dimension name on the wire). Repeatable")),
		mcp.WithArray("tier", mcp.WithStringItems(), mcp.Description("Criticality tier filter. Repeatable")),
		mcp.WithArray("data_class", mcp.WithStringItems(), mcp.Description("Content/data-class filter. Repeatable")),
		mcp.WithString("q", mcp.Description("Substring filter over the store's identifying fields")),
		mcp.WithBoolean("sensitivity",
			mcp.Description("Restrict to sensitive (or non-sensitive) stores. Omit for no constraint")),
		mcp.WithBoolean("exposure",
			mcp.Description("Restrict to publicly exposed (or not exposed) stores. Omit for no constraint")),
	}
	if paging {
		params = append(params, pagingParams("stores")...)
	}
	return params
}
