package cloudsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

const (
	// defaultCSVBytes bounds how much CSV text is handed back by default. The
	// gateway caps an export at 100k rows, which is far more than belongs in a
	// model's context; the response is cut at a row boundary with a trailing
	// comment row when it does not fit, mirroring the gateway's own truncation
	// convention.
	defaultCSVBytes = 1 << 20 // 1 MiB
	maxCSVBytes     = 8 << 20 // 8 MiB
)

// registerExport registers the single CSV export tool covering the four exportable
// datasets, which share one mechanism and differ only in dataset + selectors.
func registerExport() {
	params := []mcp.ToolOption{
		mcp.WithString("dataset",
			mcp.Required(),
			mcp.Description("Which dataset to export: 'findings' | 'inventory' | 'compliance' | 'query'. The selectors for that dataset are the same ones its list tool takes")),
		mcp.WithNumber("max_bytes",
			mcp.Description(fmt.Sprintf("Maximum CSV bytes to return (default %d, max %d). A longer export is cut at a row boundary with a trailing '#' comment row", defaultCSVBytes, maxCSVBytes))),
	}
	// findings selectors (no paging: the export always walks the full filtered set)
	params = append(params, findingSelectorParams(false)...)
	// inventory selectors, minus 'account': the findings dataset declares it as a
	// repeatable array above, and one name cannot be two JSON types in one schema.
	// The inventory branch reads it with argScalar, which accepts either form.
	params = append(params,
		mcp.WithString("type",
			mcp.Description("dataset=inventory: filter to one resource_type (e.g. compute_instance | Identity | ThirdPartyAsset)")),
		mcp.WithString("provider",
			mcp.Description("dataset=inventory: producing-sweep filter (gcp | okta | …). Single-valued; use the repeatable 'source' selector with type=Identity")),
		mcp.WithString("region",
			mcp.Description("dataset=inventory: region filter. Single-valued")),
		mcp.WithBoolean("account_unscoped",
			mcp.Description("dataset=inventory: set true to drop the account scoping so the walk spans the whole estate")),
	)
	params = append(params, identitySelectorParams()...)
	// compliance selectors
	params = append(params,
		mcp.WithString("framework",
			mcp.Description("dataset=compliance: framework id to assess (defaults to cis-gcp); ignored when 'assignment' is set")),
		mcp.WithString("assignment",
			mcp.Description("dataset=compliance: name of a scoped assignment to evaluate instead of the whole estate")),
	)
	// query selectors
	params = append(params,
		mcp.WithString("named",
			mcp.Description("dataset=query: a query-pack name; see cloudsec_list_queries")),
		mcp.WithString("text",
			mcp.Description("dataset=query: a text query")),
		mcp.WithObject("query",
			mcp.Description("dataset=query: a raw query DSL object")),
		mcp.WithString("project",
			mcp.Description("dataset=query: set to 'graph' to also project a subgraph; the only accepted value")),
	)
	// Overrides, declared last so they win over the dataset-specific descriptions
	// above for the names more than one dataset shares.
	params = append(params,
		mcp.WithArray("account", mcp.WithStringItems(),
			mcp.Description("Account/project filter. Repeatable for dataset=findings; single-valued for dataset=inventory, where only the first value is used")),
		mcp.WithString("q",
			mcp.Description("Free-text filter: over the findings for dataset=findings, over the resource's identifying fields for dataset=inventory")),
		mcp.WithString("sort",
			mcp.Description("Page order. dataset=findings: 'lc_risk' (default) | 'severity' | 'first_seen'. dataset=inventory: 'urn' (default) | 'risk' with type=Identity | 'last_seen' with type=ThirdPartyAsset")),
		mcp.WithArray("repo", mcp.WithStringItems(),
			mcp.Description("dataset=findings ONLY: source-repository filter, keyed '<owner>/<name>' as the 'repo' facet of cloudsec_get_finding_facets returns it. "+
				"LOWER-CASED here before it is sent, since the stored key is the repository urn's case-folded owner/name and the backend matches it exactly. "+
				"Supplying it on any other dataset is REJECTED rather than ignored — those rows have no repository, so dropping it would export the whole estate. "+
				"Repeatable; at most 100 values are honored")),
	)

	register(toolDef{
		name: "cloudsec_export_csv",
		description: "Export a cloud-security dataset as CSV text. The server walks the FULL filtered set (any cursor/limit is ignored), capped at 100k rows with a trailing '#' comment row on truncation. " +
			"Datasets and their selectors: 'findings' (the cloudsec_list_findings filters), 'inventory' (the cloudsec_list_inventory filters, including 'sort'), " +
			"'compliance' ('framework' or 'assignment'), 'query' (exactly one of 'named' / 'text' / 'query'). " +
			"Returns the CSV document itself, not JSON — use the list tools when you want structured rows.",
		readOnly: true,
		params:   params,
		handler:  handleExportCSV,
	})
}

func handleExportCSV(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	dataset := strings.ToLower(strings.TrimSpace(argString(args, "dataset")))
	if dataset == "" {
		return tools.ErrorResult("dataset parameter is required ('findings', 'inventory', 'compliance' or 'query')"), nil
	}

	limitBytes := defaultCSVBytes
	if n, ok := argInt(args, "max_bytes"); ok && n > 0 {
		if n > maxCSVBytes {
			n = maxCSVBytes
		}
		limitBytes = n
	}

	// `repo` reaches this tool's schema through the findings selector, so it is
	// declarable on any dataset — but only the findings walk has the column. Refused
	// rather than dropped for the reason findingRepoValues refuses: an ignored `repo`
	// does not export a narrower set, it exports the whole estate under a filter the
	// caller believes it applied. The other shared findings selectors predate this and
	// are still dropped; this is the one whose whole point is that it must not be.
	if _, scoped := args["repo"]; scoped && dataset != "findings" {
		return tools.ErrorResultf(
			"the 'repo' filter applies only to dataset=findings — a %s row has no repository, "+
				"so exporting one under a repository filter would return the whole estate. "+
				"Drop 'repo', or export dataset=findings.", dataset), nil
	}

	var (
		suffix string
		method = http.MethodGet
		query  = lc.Dict{}
		body   []byte
	)

	switch dataset {
	case "findings":
		suffix = "findings"
		if errResult := addFindingSelector(query, args, false); errResult != nil {
			return errResult, nil
		}
	case "inventory":
		suffix = "inventory"
		addInventorySelector(query, args)
		addScalars(query, args, "sort")
		addIdentitySelector(query, args)
	case "compliance":
		suffix = "compliance"
		addScalars(query, args, "framework", "assignment")
	case "query":
		suffix = "query"
		method = http.MethodPost
		qBody, errResult := queryBody(args)
		if errResult != nil {
			return errResult, nil
		}
		encoded, err := json.Marshal(qBody)
		if err != nil {
			return tools.ErrorResultf("could not encode query body: %v", err), nil
		}
		body = encoded
	default:
		return tools.ErrorResultf("unknown dataset %q: expected 'findings', 'inventory', 'compliance' or 'query'", dataset), nil
	}

	// Resolved AFTER the selectors, so every local refusal above — an unknown dataset,
	// an ambiguous query body, a malformed `repo` — is reported as the thing that is
	// actually wrong rather than as whatever the credential lookup happens to say. It is
	// needed from here on and not before.
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResultf("failed to get organization: %v", err), nil
	}

	values := queryValues(query)
	// format rides the query string on every dataset, including the POST one
	// (endpoint_cloudsec.go:892-895).
	values.Set("format", "csv")

	path := orgPath(org, suffix)
	// Read one byte past the budget: enough to know the export was longer without
	// pulling a multi-megabyte document into memory to then throw most of it away.
	raw, err := rawRequest(ctx, org, method, path, values, body, csvTimeout, int64(limitBytes))
	if err != nil {
		return tools.ErrorResultf("cloudsec CSV export of %s failed: %s", dataset, describeErr(err)), nil
	}

	return mcp.NewToolResultText(truncateCSV(string(raw), limitBytes)), nil
}

// truncateCSV cuts a CSV document at the last complete row that fits in limit bytes
// and appends a comment row saying so, so a caller never sees a half row and never
// mistakes a cut export for a complete one. The gateway uses the same '#' comment
// convention for its own 100k-row cap.
//
// The document is only ever read one byte past the budget, so the note cannot report
// the export's real total size — it says how much was kept, not what was dropped.
func truncateCSV(csv string, limit int) string {
	if limit <= 0 || len(csv) <= limit {
		return csv
	}
	cut := strings.LastIndexByte(csv[:limit], '\n')
	sep := ""
	if cut < 0 {
		// A single row longer than the whole budget: keep the budget's worth
		// rather than returning nothing, and break the line so the note is a
		// comment row instead of gluing onto the partial row.
		cut = limit
		sep = "\n"
	} else {
		cut++ // keep the newline
	}
	return csv[:cut] + sep + fmt.Sprintf("# truncated by lc-mcp-server after %d bytes; the export was longer — narrow the filters or raise max_bytes\n", cut)
}

// queryValues encodes a cloudsec query dict as URL values, matching how the SDK's
// own getStringKV encodes the same dict for the JSON reads: a []string becomes
// REPEATED keys and scalars are stringified with %v (so a bool travels as
// true/false, which the gateway's strconv.ParseBool accepts).
//
// Empty string elements are preserved: owner="" selects the unassigned findings
// bucket and an empty posture_* value selects assets no source reported that fact
// for, so dropping them would silently widen the export.
func queryValues(d lc.Dict) url.Values {
	values := url.Values{}
	for k, v := range d {
		switch typed := v.(type) {
		case []string:
			for _, e := range typed {
				values.Add(k, e)
			}
		case []interface{}:
			for _, e := range typed {
				values.Add(k, fmt.Sprintf("%v", e))
			}
		default:
			values.Set(k, fmt.Sprintf("%v", typed))
		}
	}
	return values
}
