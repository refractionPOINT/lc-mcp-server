package cloudsec

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// registerFindings registers the findings worklist reads.
func registerFindings() {
	register(toolDef{
		name: "cloudsec_list_findings",
		description: "List the merged, risk-ranked cloud-security findings (CSPM misconfigurations + graph toxic-combination attack paths + CIEM access), " +
			"ordered by lc_risk by default. Keyset-paginated: pass the response's 'next_cursor' back as 'cursor' for the following page.",
		readOnly: true,
		params:   findingSelectorParams(true),
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addFindingSelector(q, args, true)
			return readGET(ctx, "findings", q)
		},
	})

	register(toolDef{
		name: "cloudsec_get_finding_facets",
		description: "Get the cross-filtered facet counts and total for the findings worklist under the same selectors as cloudsec_list_findings: " +
			"each dimension is counted against the OTHER active filters, so a value's count is exactly how many rows selecting it would list. " +
			"The 'owner' facet keys the unassigned bucket under the empty string and is capped at the top 50 owners; 'owner_truncated' reports whether any were dropped.",
		readOnly: true,
		params: append(findingSelectorParams(false),
			mcp.WithArray("owner_pin", mcp.WithStringItems(),
				mcp.Description("Owners to keep visible inside the capped 'owner' facet (e.g. the calling user, so their own row stays reachable on a large estate). NOT a filter: it selects no rows and changes no count. Repeatable")),
		),
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addFindingSelector(q, args, false)
			addStrings(q, args, "owner_pin")
			return readGET(ctx, "findings/facets", q)
		},
	})

	register(toolDef{
		name: "cloudsec_get_finding",
		description: "Get a single cloud-security finding by id with full detail (vulnerability/CVE, evidence, remediation, status), " +
			"independent of the worklist pagination.",
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithString("finding_id",
				mcp.Required(),
				mcp.Description("The finding id (fnd_...) to fetch")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			findingID := argString(args, "finding_id")
			if findingID == "" {
				return tools.ErrorResult("finding_id parameter is required"), nil
			}
			return readGET(ctx, "findings/"+url.PathEscape(findingID), lc.Dict{})
		},
	})

	register(toolDef{
		name: "cloudsec_list_finding_classes",
		description: "List the canonical finding_class vocabulary — the valid values for the finding_class filter and for suppression-policy matchers. " +
			"Served from the backend enum, so use it instead of guessing class names.",
		readOnly: true,
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return readGET(ctx, "findings/classes", lc.Dict{})
		},
	})

	register(toolDef{
		name: "cloudsec_list_attack_paths",
		description: "List the headline toxic-combination attack paths (internet-exposed workload with a KEV vulnerability that can reach a sensitive resource). " +
			"This route is neither paginated nor sortable and pins the finding class server-side, so it takes only the four selectors below.",
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithArray("severity", mcp.WithStringItems(),
				mcp.Description("Severity filter on the source finding (CRITICAL | HIGH | MEDIUM | LOW). Repeatable")),
			mcp.WithArray("status", mcp.WithStringItems(),
				mcp.Description("Status filter: 'open' | 'resolved' | 'accepted'. Repeatable")),
			mcp.WithArray("account", mcp.WithStringItems(),
				mcp.Description("Account/project filter. Repeatable")),
			mcp.WithString("q",
				mcp.Description("Free-text filter over the source findings")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addStrings(q, args, "severity", "status", "account")
			addScalars(q, args, "q")
			return readGET(ctx, "attack-paths", q)
		},
	})

	register(toolDef{
		name: "cloudsec_list_finding_causes",
		description: "Group findings by their CAUSE — the mutable object (e.g. a firewall rule) whose single edit resolves all of them — " +
			"under the same selectors as cloudsec_list_findings. The highest-leverage remediation view: 'one edit fixes N findings'. " +
			"Omit 'cause' for the top causes by count plus 'distinct' (the total number of causes matching the filter); pass 'cause' for one cause's exact count.",
		readOnly: true,
		params: append(findingSelectorParams(false),
			mcp.WithString("cause",
				mcp.Description(fmt.Sprintf("A single cause key (a resource urn, or a 'cause:<kind>:<name>' fallback) to count exactly. Truncated at %d bytes, which is longer than any stored key", maxCauseKeyLen))),
			mcp.WithNumber("limit",
				mcp.Description(fmt.Sprintf("Maximum number of causes to return (default 20, max %d)", maxCauseLimit))),
		),
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addFindingSelector(q, args, false)
			addInt(q, args, "limit", maxCauseLimit)
			if cause := argString(args, "cause"); cause != "" {
				if len(cause) > maxCauseKeyLen {
					// The gateway clamps by bytes; drop any rune the cut split so the
					// query param stays valid UTF-8.
					cause = strings.ToValidUTF8(cause[:maxCauseKeyLen], "")
				}
				q["cause"] = cause
			}
			return readGET(ctx, "findings/causes", q)
		},
	})
}
