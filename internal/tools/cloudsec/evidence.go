package cloudsec

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// Code Security evidence reads: a finding's evidence chain, the coverage report and code
// impact. All three are cloudsec.get reads that take no action.

// commitRe is a full hexadecimal commit. findingIDRe (code.go) is the finding id shape.
var commitRe = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// assertiveOutcomes are the outcomes that state a fact about the finding. The server only
// sends them on a proven stage; this reader removes one anywhere else, so an agent can never
// read "verified" or "not_observed" off a stage whose evidence is incomplete.
var assertiveOutcomes = map[string][]string{
	"running":   {"rolling"},
	"exposed":   {"exposed"},
	"observed":  {"executing", "loaded", "not_observed"},
	"responded": {"monitoring", "verified", "persists", "regressed"},
	"verified":  {"verified"},
}

func isAssertiveOutcome(stage, outcome string) bool {
	for _, o := range assertiveOutcomes[stage] {
		if o == outcome {
			return true
		}
	}
	return false
}

// normalizeChain passes the server's chain through, removing only an assertive outcome on
// a stage that is not proven. Reasons and actions are never mapped: an unrecognised token
// stays exactly as the server sent it.
func normalizeChain(resp map[string]interface{}) map[string]interface{} {
	chain, ok := resp["chain"].(map[string]interface{})
	if !ok {
		return resp
	}
	stages, _ := chain["stages"].([]interface{})
	for _, raw := range stages {
		s, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := s["stage"].(string)
		status, _ := s["status"].(string)
		outcome, _ := s["outcome"].(string)
		if status != "proven" && isAssertiveOutcome(name, outcome) {
			delete(s, "outcome")
		}
	}
	return resp
}

// coveragePercent mirrors the server's rule: a percentage exists only for a measured,
// complete, untruncated line with a positive denominator and no stated reason.
func coveragePercent(line map[string]interface{}) (float64, bool) {
	num, nok := line["numerator"].(float64)
	den, dok := line["denominator"].(float64)
	if !nok || !dok || den <= 0 || num < 0 || num > den {
		return 0, false
	}
	if complete, _ := line["complete"].(bool); !complete {
		return 0, false
	}
	if truncated, _ := line["truncated"].(bool); truncated {
		return 0, false
	}
	if reason, _ := line["reason"].(string); reason != "" {
		return 0, false
	}
	return num * 100 / den, true
}

// annotateCoverage adds `percent` to the lines that may show one and `percent_shown`
// to every line, so an agent quotes the server's rule instead of dividing on its own.
func annotateCoverage(resp map[string]interface{}) map[string]interface{} {
	report, ok := resp["coverage"].(map[string]interface{})
	if !ok {
		return resp
	}
	lines, _ := report["lines"].([]interface{})
	for _, raw := range lines {
		line, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		p, shown := coveragePercent(line)
		line["percent_shown"] = shown
		if shown {
			line["percent"] = p
		} else {
			delete(line, "percent")
		}
	}
	return resp
}

func registerEvidence() {
	register(toolDef{
		name: "cloudsec_get_finding_evidence_chain",
		description: "Read a finding's evidence chain in eight stages: declared, committed, built, running, exposed, observed, responded, verified. " +
			"Each stage is proven, partial, unknown or not_applicable, with an evidence level, times, a reason and, when not proven, a concrete next 'action'. " +
			"'proven' means the evidence is complete, NOT that the news is good; read 'outcome'. An unknown or partial stage is never a statement that something is safe, not exposed or fixed. " +
			"A reason this server does not recognise arrives verbatim with reason_recognised=false and action review_reason: quote it, never replace it. " +
			"'gaps' is the server's count of partial or unknown stages; quote it rather than counting yourself. " +
			"runtime=true adds existing runtime evidence to the observed stage (read-only; cloudsec_check_finding_runtime starts a measurement). " +
			"A null chain carries reason feature_disabled or finding_not_found.",
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithString("finding_id", mcp.Required(), mcp.Description("The finding id: fnd_ followed by 32 lowercase hex")),
			mcp.WithBoolean("runtime", mcp.Description("Include existing runtime evidence on the observed stage")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			id := argString(args, "finding_id")
			if !findingIDRe.MatchString(id) {
				return tools.ErrorResult("finding_id must be fnd_ followed by 32 lowercase hex"), nil
			}
			query := lc.Dict{}
			if v, ok := argBool(args, "runtime"); ok && v {
				query["runtime"] = "true"
			}
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}
			resp, err := getJSON(ctx, org, orgPath(org, "findings/"+id+"/evidence-chain"), query)
			if err != nil {
				return tools.ErrorResultf("%s", describeErr(err)), nil
			}
			return tools.SuccessResult(normalizeChain(resp)), nil
		},
	})
	register(toolDef{
		name: "cloudsec_get_code_coverage",
		description: "Read Code Security coverage with explicit denominators: workloads with an immutable digest, workloads fully resolved, digests with a source commit, proven chains, declarations attributed, pull-request context success, remediation outcomes, verification latency and runtime telemetry. " +
			"Every metric is listed. An unmeasured metric has null numerator and denominator, never 0 of 0. " +
			"Each line carries percent_shown; quote a percentage ONLY when it is true (the line is complete, fresh, untruncated and has a positive denominator). Otherwise report the counts with the line's reason and action. Never compute a percentage yourself. " +
			"A null coverage carries reason feature_disabled.",
		readOnly: true,
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}
			resp, err := getJSON(ctx, org, orgPath(org, "code/coverage"), nil)
			if err != nil {
				return tools.ErrorResultf("%s", describeErr(err)), nil
			}
			return tools.SuccessResult(annotateCoverage(resp)), nil
		},
	})
	register(toolDef{
		name: "cloudsec_get_code_impact",
		description: "Read which live cloud resources a repository's infrastructure-as-code declarations touch, and what is at stake on each (exposure, sensitive data, privileged identity, the running artifact, open findings). " +
			"Select EITHER repo_urn (optionally with a full commit) OR one IaC code finding_id. Anything not fully established is 'partial' with a closed reason, never 'no impact'; 'not_established' does not mean safe. " +
			"A null impact carries reason feature_disabled or subject_not_found.",
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithString("repo_urn", mcp.Description("Canonical repository URN in this organization")),
			mcp.WithString("commit", mcp.Description("Full hexadecimal commit (with repo_urn)")),
			mcp.WithString("finding_id", mcp.Description("One IaC code finding id instead of a repository")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			repo, commit, finding := argString(args, "repo_urn"), argString(args, "commit"), argString(args, "finding_id")
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}
			query := url.Values{}
			switch {
			case finding != "" && repo == "" && commit == "":
				if !findingIDRe.MatchString(finding) {
					return tools.ErrorResult("finding_id must be fnd_ followed by 32 lowercase hex"), nil
				}
				query.Set("finding_id", finding)
			case repo != "" && finding == "":
				if len(repo) > 2048 || !strings.HasPrefix(repo, "lcrn:1:"+org.GetOID()+":") {
					return tools.ErrorResult("repo_urn must be a repository of this organization"), nil
				}
				if commit != "" && !commitRe.MatchString(commit) {
					return tools.ErrorResult("commit must be a full hexadecimal commit"), nil
				}
				query.Set("repo_urn", repo)
				if commit != "" {
					query.Set("commit", commit)
				}
			default:
				return tools.ErrorResult("select either repo_urn (optionally with commit) or finding_id"), nil
			}
			return rawJSON(ctx, org, http.MethodGet, "code/impact", query)
		},
	})
}
