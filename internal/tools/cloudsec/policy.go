package cloudsec

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// registerPolicyAids registers the policy-authoring aids and the graph query runner.
// All five are read-only — nothing is persisted — even though four of them are POSTs
// (the gateway documents them as read-only previews and gates them on cloudsec.get).
func registerPolicyAids() {
	register(toolDef{
		name: "cloudsec_get_policy_vocabulary",
		description: "Get the classification-policy vocabulary that drives crown-jewel / coverage / exclusion rules: " +
			"the per-surface capability table (which matcher dimensions each policy surface honors), the closed vocabularies " +
			"(resource types per section, providers, criticality tiers, content classes, suggested classes), and the org's in-use histograms " +
			"(accounts, regions, label keys, network tags, resource types) for autocomplete. Read this before writing a cloudsec_policy record. " + hiveNote,
		readOnly: true,
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return readGET(ctx, "policy/vocabulary", lc.Dict{})
		},
	})

	register(toolDef{
		name: "cloudsec_suggest_policy_values",
		description: "Suggest values for a cloudsec_policy matcher dimension from the org's own inventory, for the high-cardinality dimensions the bundled vocabulary histograms cannot carry. " +
			"dimension 'name' walks the estate's policy-matchable resources (bounded, truncation-flagged) for names containing the typed text; dimension 'account' filters the account facet. " +
			"Returns ranked {value,count} suggestions. Read-only: nothing is saved. " + hiveNote,
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithString("dimension",
				mcp.Required(),
				mcp.Description("The matcher dimension to suggest values for: 'name' or 'account'")),
			mcp.WithString("q",
				mcp.Required(),
				mcp.Description(fmt.Sprintf("The typed text fragment to match (at most %d bytes; longer is rejected by the gateway)", maxSuggestQueryB))),
			mcp.WithString("target",
				mcp.Description("Narrow the walked resource family to the rule set being edited: 'data_store' | 'compute' | 'identity' | 'any'")),
			mcp.WithNumber("limit",
				mcp.Description(fmt.Sprintf("Maximum suggestions to return (clamped to %d)", maxSuggestLimit))),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			dimension := argString(args, "dimension")
			if dimension == "" {
				return tools.ErrorResult("dimension parameter is required ('name' or 'account')"), nil
			}
			q, supplied := argStringOK(args, "q")
			if !supplied || q == "" {
				return tools.ErrorResult("q parameter is required and must not be empty"), nil
			}
			if len(q) > maxSuggestQueryB {
				return tools.ErrorResultf("q is %d bytes, above the %d-byte limit for a suggestion fragment", len(q), maxSuggestQueryB), nil
			}
			body := map[string]interface{}{"dimension": dimension, "q": q}
			if target := argString(args, "target"); target != "" {
				body["target"] = target
			}
			if n, ok := argInt(args, "limit"); ok && n > 0 {
				if n > maxSuggestLimit {
					n = maxSuggestLimit
				}
				body["limit"] = n
			}
			return callPOST(ctx, "policy/suggest", body, defaultTimeout)
		},
	})

	register(toolDef{
		name: "cloudsec_simulate_resource_match",
		description: "Preview what a set of cloudsec_policy resource matcher rules would hit, against the org's stored inventory, before saving them. " +
			"Rules compose as OR and use the Data Classification / Coverage / Exclusions vocabulary " +
			"(account_contains, account_glob, name_contains, name_glob, label, label_key_present, tag). " +
			"Returns evaluated/matched/indeterminate counts, a bounded sample, and truncated=true when the walk hit its size/time bound. " +
			"'indeterminate' counts resources whose stored row cannot evaluate a label constraint because their type does not persist labels. " +
			"Read-only: nothing is saved — persist the rules in the \"cloudsec_policy\" hive with set_rule.",
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithArray("rules", mcp.Items(map[string]any{"type": "object"}),
				mcp.Required(),
				mcp.Description("The matcher rules to simulate: an array of rule objects (see cloudsec_get_policy_vocabulary for the dimensions each surface honors)")),
			mcp.WithString("target",
				mcp.Description("The policy surface the rules belong to: 'data_store' | 'compute' | 'identity' | 'any'")),
			mcp.WithArray("resource_types", mcp.WithStringItems(),
				mcp.Description("Restrict the walk to these resource types")),
			mcp.WithNumber("sample_limit",
				mcp.Description(fmt.Sprintf("Maximum sample rows to return (clamped to %d)", maxSampleLimit))),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			rules, ok := argList(args, "rules")
			if !ok {
				return tools.ErrorResult("rules parameter is required and must be an array of rule objects"), nil
			}
			body := map[string]interface{}{"rules": rules}
			if target := argString(args, "target"); target != "" {
				body["target"] = target
			}
			if types, ok := argStrings(args, "resource_types"); ok && len(types) > 0 {
				body["resource_types"] = types
			}
			addSampleLimit(body, args)
			return callPOST(ctx, "simulate/resources", body, defaultTimeout)
		},
	})

	register(toolDef{
		name: "cloudsec_simulate_finding_match",
		description: "Preview which OPEN findings a suppression-policy matcher would disposition, using the exact semantics the suppression engine applies " +
			"(finding_class, rule, account globs, urn_prefix, max_severity). " +
			"Returns evaluated/matched counts, a bounded sample, and truncated=true when the walk hit its size/time bound. " +
			"An empty match object {} is valid and means 'everything up to the default severity ceiling'. " +
			"Read-only: nothing is dispositioned — persist the matcher in the \"cloudsec_policy\" hive with set_rule.",
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithObject("match",
				mcp.Required(),
				mcp.Description("The suppression matcher to simulate. {} is valid and matches everything up to the default severity ceiling")),
			mcp.WithNumber("sample_limit",
				mcp.Description(fmt.Sprintf("Maximum sample rows to return (clamped to %d)", maxSampleLimit))),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			match, ok := argMap(args, "match")
			if !ok {
				return tools.ErrorResult("match parameter is required and must be an object (pass {} to match everything up to the default severity ceiling)"), nil
			}
			body := map[string]interface{}{"match": match}
			addSampleLimit(body, args)
			return callPOST(ctx, "simulate/findings", body, defaultTimeout)
		},
	})

	register(toolDef{
		name: "cloudsec_run_query",
		description: "Run a query against the org's security graph and get alias->urn rows back. Provide EXACTLY ONE of 'named' (a query-pack name from cloudsec_list_queries), " +
			"'text' (a text query) or 'query' (a DSL object). Set project='graph' to also return a drawable induced subgraph over the matched urns. " +
			"Org-defined saved queries live in the \"cloudsec_query\" hive — reach them with the generic hive tools (list_rules / get_rule / set_rule with hive_name).",
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithString("named",
				mcp.Description("A query-pack name; see cloudsec_list_queries")),
			mcp.WithString("text",
				mcp.Description("A text query, e.g. MATCH (d:DataStore {is_sensitive: true})<-[:has_permission_on]-(i:Identity {is_external: true}) RETURN i, d")),
			mcp.WithObject("query",
				mcp.Description("A raw query DSL object (may also be supplied as a JSON string that decodes to an object)")),
			mcp.WithString("project",
				mcp.Description("Set to 'graph' to also return an induced subgraph over the matched urns; the only accepted value")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			body, errResult := queryBody(args)
			if errResult != nil {
				return errResult, nil
			}
			return callPOST(ctx, "query", body, defaultTimeout)
		},
	})
}

// addSampleLimit forwards the simulate preview's sample size, clamped to the
// gateway's own cap.
func addSampleLimit(body map[string]interface{}, args map[string]interface{}) {
	n, ok := argInt(args, "sample_limit")
	if !ok || n <= 0 {
		return
	}
	if n > maxSampleLimit {
		n = maxSampleLimit
	}
	body["sample_limit"] = n
}

// queryBody assembles the graph-query POST body, enforcing client-side what the CLI
// enforces: exactly one of named/text/query, none of them empty. Round-tripping an
// empty 'text' would spend a call to learn what is knowable here.
func queryBody(args map[string]interface{}) (map[string]interface{}, *mcp.CallToolResult) {
	body := map[string]interface{}{}
	var given []string

	if v, supplied := argStringOK(args, "named"); supplied {
		given = append(given, "named")
		if strings.TrimSpace(v) == "" {
			return nil, tools.ErrorResult("named must not be empty")
		}
		body["named"] = v
	}
	if v, supplied := argStringOK(args, "text"); supplied {
		given = append(given, "text")
		if strings.TrimSpace(v) == "" {
			return nil, tools.ErrorResult("text must not be empty")
		}
		body["text"] = v
	}
	if raw, present := args["query"]; present {
		given = append(given, "query")
		q, err := asObject(raw)
		if err != nil {
			return nil, tools.ErrorResultf("query must be an object (or a JSON string that decodes to one): %v", err)
		}
		body["query"] = q
	}

	if len(given) != 1 {
		return nil, tools.ErrorResultf("provide exactly one of 'named', 'text' or 'query' (got %d: %s)", len(given), strings.Join(given, ", "))
	}

	if project, supplied := argStringOK(args, "project"); supplied && project != "" {
		if project != "graph" {
			return nil, tools.ErrorResultf("project must be 'graph' (got %q)", project)
		}
		body["project"] = project
	}
	return body, nil
}
