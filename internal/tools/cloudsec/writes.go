package cloudsec

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// resolutionKinds is the closed set the finding-status write accepts. "open" is a
// reopen that keeps the owner and ticket linkage; it is accepted only by the
// single-finding route.
var resolutionKinds = map[string]bool{
	"mitigated":      true,
	"accepted":       true,
	"false_positive": true,
	"open":           true,
}

// registerWrites registers the cloudsec.set writes. The gateway server-stamps the
// oid and the acting user (as "by") from the JWT, so no tool sends either.
func registerWrites() {
	registerFindingWrites()
	registerChokepointWrites()
	registerCAASMWrites()

	register(toolDef{
		name: "cloudsec_test_provider",
		description: "Preflight a cloud-security provider configuration: connect to the provider with the given credentials and probe every permission surface collection needs. " +
			"Credentials are ephemeral — supply them inline or as a \"hive://secret/<name>\" reference; nothing is stored by this call. " +
			"report.ok is the verdict over the REQUIRED checks; each check carries id/name/required/ok/detail, and a failed optional check means a gracefully degraded surface rather than a failure. " +
			"Probing runs against the live provider and can take up to a minute. " + hiveNote,
		// A probe persists nothing, but it is gated on cloudsec.set because testing
		// a credential is as sensitive as saving one.
		destructive: false,
		params: []mcp.ToolOption{
			mcp.WithObject("provider",
				mcp.Required(),
				mcp.Description("The provider to test, in the cloudsec_provider record shape, with 'credentials' inline (ephemeral) or a \"hive://secret/<name>\" reference")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			provider, ok := argMap(args, "provider")
			if !ok {
				return tools.ErrorResult("provider parameter is required and must be an object (the cloudsec_provider record shape)"), nil
			}
			return callPOST(ctx, "providers/test", map[string]interface{}{"provider": provider}, providerTestTimeout)
		},
	})
}

func registerFindingWrites() {
	register(toolDef{
		name: "cloudsec_set_finding_status",
		description: "Disposition one cloud-security finding: record an operator resolution with an optional reason. " +
			"kind='accepted' is a live risk somebody signed off on carrying, NOT a fix; kind='open' reopens the finding and keeps its owner and ticket linkage.",
		destructive: true,
		params: []mcp.ToolOption{
			mcp.WithString("finding_id",
				mcp.Required(),
				mcp.Description("The finding id (fnd_...) to disposition")),
			mcp.WithString("kind",
				mcp.Required(),
				mcp.Description("The resolution: 'mitigated' | 'accepted' | 'false_positive' | 'open' (reopen)")),
			mcp.WithString("reason",
				mcp.Description("Free-text reason recorded with the resolution")),
			mcp.WithNumber("expires_at",
				mcp.Description("Expiry of an acceptance as a unix timestamp in SECONDS (not milliseconds). Only meaningful with kind='accepted'; omit for a permanent acceptance")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			findingID := argString(args, "finding_id")
			if findingID == "" {
				return tools.ErrorResult("finding_id parameter is required"), nil
			}
			resolution, errResult := resolutionBody(args, true)
			if errResult != nil {
				return errResult, nil
			}
			path := fmt.Sprintf("findings/%s/status", url.PathEscape(findingID))
			return callPOST(ctx, path, map[string]interface{}{"resolution": resolution}, defaultTimeout)
		},
	})

	register(toolDef{
		name: "cloudsec_bulk_set_finding_status",
		description: fmt.Sprintf("Apply one resolution to many cloud-security findings at once, up to %d ids per call (a larger batch is rejected, so split it). "+
			"kind='open' is NOT accepted here — reopen findings one at a time with cloudsec_set_finding_status. Returns the number of findings updated.", maxBulkFindings),
		destructive: true,
		params: []mcp.ToolOption{
			mcp.WithArray("finding_ids", mcp.WithStringItems(),
				mcp.Required(),
				mcp.Description(fmt.Sprintf("The finding ids to disposition (at most %d)", maxBulkFindings))),
			mcp.WithString("kind",
				mcp.Required(),
				mcp.Description("The resolution: 'mitigated' | 'accepted' | 'false_positive'")),
			mcp.WithString("reason",
				mcp.Description("Free-text reason recorded with the resolution")),
			mcp.WithNumber("expires_at",
				mcp.Description("Expiry of an acceptance as a unix timestamp in SECONDS (not milliseconds). Only meaningful with kind='accepted'")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			ids, ok := argStrings(args, "finding_ids")
			if !ok || len(ids) == 0 {
				return tools.ErrorResult("finding_ids parameter is required and must be a non-empty array"), nil
			}
			if len(ids) > maxBulkFindings {
				return tools.ErrorResultf("finding_ids has %d entries, above the per-call cap of %d; split into batches", len(ids), maxBulkFindings), nil
			}
			resolution, errResult := resolutionBody(args, false)
			if errResult != nil {
				return errResult, nil
			}
			body := map[string]interface{}{
				"finding_ids": ids,
				"resolution":  resolution,
			}
			return callPOST(ctx, "findings/bulk/status", body, defaultTimeout)
		},
	})

	register(toolDef{
		name: "cloudsec_set_finding_owner",
		description: "Assign the owner of a cloud-security finding, or clear it by passing an empty string. " +
			"Unassigned findings are selectable in cloudsec_list_findings with owner=[\"\"].",
		destructive: false,
		params: []mcp.ToolOption{
			mcp.WithString("finding_id",
				mcp.Required(),
				mcp.Description("The finding id (fnd_...) to assign")),
			mcp.WithString("owner",
				mcp.Required(),
				mcp.Description("The owner to record; an empty string clears the assignment")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return setFindingField(ctx, args, "owner")
		},
	})

	register(toolDef{
		name:        "cloudsec_set_finding_ticket",
		description: "Link a ticket id or url to a cloud-security finding, or clear it by passing an empty string.",
		destructive: false,
		params: []mcp.ToolOption{
			mcp.WithString("finding_id",
				mcp.Required(),
				mcp.Description("The finding id (fnd_...) to link")),
			mcp.WithString("ticket",
				mcp.Required(),
				mcp.Description("The ticket id or url to record; an empty string clears the link")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return setFindingField(ctx, args, "ticket")
		},
	})
}

func registerChokepointWrites() {
	register(toolDef{
		name: "cloudsec_dismiss_chokepoint",
		description: "Dismiss an estate-wide chokepoint by its resource urn so it no longer surfaces on the risk overview. " +
			"A chokepoint is an aggregate (one resource on many attack paths), so dispositioning a single finding cannot clear it — and dismissing it hides an estate-wide risk. " +
			"Reversible with cloudsec_restore_chokepoint.",
		destructive: true,
		params: []mcp.ToolOption{
			mcp.WithString("urn",
				mcp.Required(),
				mcp.Description("The chokepoint's resource urn")),
			mcp.WithString("reason",
				mcp.Description("Free-text reason recorded with the dismissal")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			urn := argString(args, "urn")
			if urn == "" {
				return tools.ErrorResult("urn parameter is required"), nil
			}
			body := map[string]interface{}{"urn": urn}
			if reason, supplied := argStringOK(args, "reason"); supplied {
				body["reason"] = reason
			}
			return callPOST(ctx, "chokepoints/dismiss", body, defaultTimeout)
		},
	})

	register(toolDef{
		name:        "cloudsec_restore_chokepoint",
		description: "Restore (un-dismiss) a previously dismissed estate-wide chokepoint so it surfaces on the risk overview again.",
		destructive: false,
		params: []mcp.ToolOption{
			mcp.WithString("urn",
				mcp.Required(),
				mcp.Description("The chokepoint's resource urn")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			urn := argString(args, "urn")
			if urn == "" {
				return tools.ErrorResult("urn parameter is required"), nil
			}
			return callPOST(ctx, "chokepoints/restore", map[string]interface{}{"urn": urn}, defaultTimeout)
		},
	})
}

func registerCAASMWrites() {
	register(toolDef{
		name: "cloudsec_set_caasm_policy",
		description: "Set the org's CAASM expected-coverage policy: the declarative expectations the coverage engine evaluates over the merged asset inventory, " +
			"e.g. {\"expect\":[{\"label\":\"edr-on-devices\",\"capability\":\"edr\",\"kinds\":[\"device\"]}]}. " +
			"This is an UPSERT that replaces the whole policy — read the current one with cloudsec_get_caasm_policy first. An invalid policy is rejected server-side.",
		destructive: true,
		params: []mcp.ToolOption{
			mcp.WithObject("policy",
				mcp.Required(),
				mcp.Description("The whole coverage policy, shaped {\"expect\": [{label, capability, kinds}]}")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			policy, ok := argMap(args, "policy")
			if !ok {
				return tools.ErrorResult("policy parameter is required and must be an object shaped {\"expect\": [...]}"), nil
			}
			return callPOST(ctx, "caasm/policy", map[string]interface{}{"policy": policy}, defaultTimeout)
		},
	})

	register(toolDef{
		name: "cloudsec_ingest_caasm_records",
		description: "Ingest a batch of raw third-party asset records into the merged CAASM asset inventory. " +
			"'source' must be a source the backend knows (sentinelone, crowdstrike, defender, okta, entraid, ms_graph, wiz and others as the registry grows — it is validated server-side). " +
			"'records' holds the raw vendor-shaped JSON objects that source's tool ships; a single object may be sent as 'record' instead. " +
			"Records are normalized, entity-resolved against the existing inventory and written as ThirdPartyAsset rows; re-ingesting identical records is a no-op. " +
			"Chunk large imports: the request body is capped at 1 MiB and the server-side reconcile runs up to a minute.",
		// An ingest is an idempotent merge, not a destructive replacement, but it is
		// still a write.
		destructive: false,
		params: []mcp.ToolOption{
			mcp.WithString("source",
				mcp.Required(),
				mcp.Description("The CAASM source shipping these records (validated server-side against the known-source registry)")),
			mcp.WithArray("records", mcp.Items(map[string]any{"type": "object"}),
				mcp.Description("The raw vendor-shaped records to ingest. Wins over 'record' when both are given")),
			mcp.WithObject("record",
				mcp.Description("A single raw record, as a friendlier form of a one-element 'records' batch")),
			mcp.WithObject("policy",
				mcp.Description("Optional coverage policy to evaluate against this batch without storing it")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			source := argString(args, "source")
			if source == "" {
				return tools.ErrorResult("source parameter is required"), nil
			}
			body := map[string]interface{}{"source": source}
			records, hasRecords := argList(args, "records")
			if hasRecords {
				body["records"] = records
			}
			if record, ok := argMap(args, "record"); ok && !hasRecords {
				body["records"] = []interface{}{record}
			}
			if _, ok := body["records"]; !ok {
				return tools.ErrorResult("provide 'records' (an array of raw records) or 'record' (a single raw record)"), nil
			}
			if policy, ok := argMap(args, "policy"); ok {
				body["policy"] = policy
			}
			return callPOST(ctx, "caasm/ingest", body, ingestTimeout)
		},
	})
}

// setFindingField powers the owner/ticket writes, which share a shape: a required
// string whose EMPTY value clears the field, so presence is what is checked.
func setFindingField(ctx context.Context, args map[string]interface{}, field string) (*mcp.CallToolResult, error) {
	findingID := argString(args, "finding_id")
	if findingID == "" {
		return tools.ErrorResult("finding_id parameter is required"), nil
	}
	value, supplied := argStringOK(args, field)
	if !supplied {
		return tools.ErrorResultf("%s parameter is required (pass an empty string to clear it)", field), nil
	}
	path := fmt.Sprintf("findings/%s/%s", url.PathEscape(findingID), field)
	return callPOST(ctx, path, map[string]interface{}{field: value}, defaultTimeout)
}

// resolutionBody assembles the {kind, reason?, expires_at?} resolution object.
// allowReopen is false for the bulk route, which the gateway does not let reopen a
// batch — the remedy is the single-finding tool.
func resolutionBody(args map[string]interface{}, allowReopen bool) (map[string]interface{}, *mcp.CallToolResult) {
	kind := strings.TrimSpace(argString(args, "kind"))
	if kind == "" {
		return nil, tools.ErrorResult("kind parameter is required ('mitigated', 'accepted' or 'false_positive'" + reopenHint(allowReopen) + ")")
	}
	if !resolutionKinds[kind] {
		return nil, tools.ErrorResultf("unknown kind %q: expected 'mitigated', 'accepted' or 'false_positive'%s", kind, reopenHint(allowReopen))
	}
	if kind == "open" && !allowReopen {
		return nil, tools.ErrorResult("kind='open' is not accepted for a bulk disposition; reopen findings one at a time with cloudsec_set_finding_status")
	}

	resolution := map[string]interface{}{"kind": kind}
	if reason, supplied := argStringOK(args, "reason"); supplied {
		resolution["reason"] = reason
	}
	if n, ok := argInt(args, "expires_at"); ok {
		// A Date.now()-style value would silently record an acceptance expiring in
		// the year 58000 rather than failing, so it is refused here.
		if n > maxSecondsTimestamp {
			return nil, tools.ErrorResultf("expires_at is %d, which is out of range for a timestamp in SECONDS (it looks like milliseconds); divide by 1000", n)
		}
		resolution["expires_at"] = n
	}
	return resolution, nil
}

// maxSecondsTimestamp is the same 1e11 threshold the platform's own timestamp
// validation uses to tell a seconds value from a milliseconds one.
const maxSecondsTimestamp = 100_000_000_000

func reopenHint(allowReopen bool) string {
	if allowReopen {
		return " or 'open'"
	}
	return ""
}
