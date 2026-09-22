package cloudsec

import (
	"context"
	"net/url"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// Runtime package evidence (CS-15) — the PUBLIC five-rung ladder.
//
// The question: for one open package finding on one cloud workload, did that code
// actually run? Plan 24 decision D6 fixes the answer to five rungs and no more.
// go-cloudsec findings/runtime.go and runtimeevidence/verdict.go
// (PR refractionPOINT/go-cloudsec#413) are the authority; these constants mirror them
// so the MCP surface cannot drift into a sixth rung or a different spelling.
//
// The reason this file carries so much description text is that the tool's consumer is
// a model, and the failure mode that matters is a model reading an absence of telemetry
// as a clean bill of health and closing a live finding. The rungs and their
// preconditions therefore live IN the description, not only in the docs.
const (
	// runtimeUnknown: no usable evidence — missing, stale, expired, foreign,
	// unattributable or conflicting. Its wire spelling is the EMPTY STRING, so an
	// absent status and status:"" mean the same thing.
	runtimeUnknown = ""
	// runtimePresent: an agent runs on the resource but the telemetry cannot carry a
	// claim about this package.
	runtimePresent = "present"
	// runtimeNotObserved: a COMPLETE telemetry window saw the package never run. The
	// only negative rung, and the only one with a completeness precondition.
	runtimeNotObserved = "not_observed"
	// runtimeLoaded: the package is mapped into a running process.
	runtimeLoaded = "loaded"
	// runtimeExecuting: the package IS the running executable.
	runtimeExecuting = "executing"

	// legacyRuntimeNotObserved is the pre-CS-15 spelling. Plan 24 §14: "Decode legacy
	// dormant as not_observed but never emit it." Nothing here produces it, and
	// decodeRuntimeStatus is the only thing that recognizes it.
	//
	// UNRELATED USES OF THE WORD: the CIEM identity-dormancy facet (dormant_90d,
	// dormant_admin), the AI-sessions session status, and sensor sleep mode. Different
	// vocabularies entirely.
	legacyRuntimeNotObserved = "dormant"
)

// runtimeStatuses is the ladder in ascending evidence order, unknown first — the exact
// membership and order of findings.RuntimeStatuses().
var runtimeStatuses = []string{
	runtimeUnknown, runtimePresent, runtimeNotObserved, runtimeLoaded, runtimeExecuting,
}

// runtimeRank is the aggregation order. NOT a severity, and it never feeds lc_risk.
// The negative rung deliberately ranks BELOW present so that one package with an
// incomplete window vetoes a resource-level negative — see runtimeHeadline.
var runtimeRank = map[string]int{
	runtimeNotObserved: 1,
	runtimePresent:     2,
	runtimeLoaded:      3,
	runtimeExecuting:   4,
}

// decodeRuntimeStatus folds any stored or wire spelling onto the public ladder,
// mirroring findings.DecodeRuntimeStatus. The legacy `dormant` token becomes
// not_observed; an empty or absent token stays unknown; an unrecognized token becomes
// unknown rather than being read as a verdict. The second return is false when the
// input was not a known token at all, so a caller can count malformed input instead of
// silently treating it as unknown. Nothing here can return the legacy token.
func decodeRuntimeStatus(v interface{}) (string, bool) {
	raw, ok := v.(string)
	if !ok {
		return runtimeUnknown, v == nil
	}
	switch token := strings.ToLower(strings.TrimSpace(raw)); token {
	case runtimeUnknown:
		return runtimeUnknown, true
	case legacyRuntimeNotObserved, runtimeNotObserved:
		return runtimeNotObserved, true
	case runtimePresent:
		return runtimePresent, true
	case runtimeLoaded:
		return runtimeLoaded, true
	case runtimeExecuting:
		return runtimeExecuting, true
	default:
		return runtimeUnknown, false
	}
}

// isRuntimeNegative reports whether a status asserts the package was not observed
// running. Callers ask through this rather than testing "not loaded and not
// executing": those are different statements and only this one has been earned.
func isRuntimeNegative(status string) bool { return status == runtimeNotObserved }

func isRuntimePositive(status string) bool {
	return status == runtimeLoaded || status == runtimeExecuting
}

// runtimeHeadline folds the per-package rows of a runtime-check result into the single
// verdict to report, mirroring runtimeevidence.Aggregate / CheckResult.Headline.
//
// It exists because the naive fold is wrong in a specific way. A maximum over the
// rungs would return the negative whenever nothing positive was seen; the real ranking
// puts the negative BELOW present precisely so that one package whose window is
// incomplete — or a sensor set the caller could not fully enumerate — vetoes a
// whole-resource negative. A model handed the raw rows will take that maximum.
//
// Deliberately stamps no `source` on a locally-folded unknown: the Go original does,
// because there it IS the producer, whereas claiming the producer token for a
// reduction performed here would invent provenance.
func runtimeHeadline(result map[string]interface{}) map[string]interface{} {
	sensorsComplete := truthy(result["sensors_complete"])
	rows, _ := result["packages"].([]interface{})

	verdicts := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		entry, _ := row.(map[string]interface{})
		raw, _ := entry["verdict"].(map[string]interface{})
		verdict := map[string]interface{}{}
		for k, v := range raw {
			verdict[k] = v
		}
		status, _ := decodeRuntimeStatus(raw["status"])
		verdict["status"] = status
		verdicts = append(verdicts, verdict)
	}

	if len(verdicts) == 0 {
		if sensorsComplete {
			return runtimeUnknownVerdict("no_evidence")
		}
		return runtimeUnknownVerdict("sensors_partial")
	}

	// Seeded with the FIRST row rather than a synthetic unknown, so an all-unknown
	// input keeps a real reason instead of collapsing to no_evidence. Ties keep the
	// earlier element, which makes the fold deterministic.
	best := verdicts[0]
	negatives := 0
	for i, verdict := range verdicts {
		status, _ := verdict["status"].(string)
		if isRuntimeNegative(status) {
			negatives++
		}
		bestStatus, _ := best["status"].(string)
		if i > 0 && runtimeRank[status] > runtimeRank[bestStatus] {
			best = verdict
		}
	}

	bestStatus, _ := best["status"].(string)
	// A sighting on any package is the resource's answer: incomplete evidence can hide
	// a sighting, never invent one, so a positive needs no precondition.
	if isRuntimePositive(bestStatus) {
		return best
	}
	// No sighting. The negative survives only if it is unanimous over a known-complete
	// sensor set.
	if negatives > 0 && negatives == len(verdicts) && sensorsComplete {
		return best
	}
	if bestStatus == runtimePresent {
		return best
	}
	// Everything left is unknown, plus possibly some negatives a partial sensor set or
	// an unknown sibling just vetoed. Report the veto, not the negative.
	if negatives > 0 {
		if sensorsComplete {
			return runtimeUnknownVerdict("no_evidence")
		}
		return runtimeUnknownVerdict("sensors_partial")
	}
	reason, _ := best["reason"].(string)
	return runtimeUnknownVerdict(reason)
}

func runtimeUnknownVerdict(reason string) map[string]interface{} {
	return map[string]interface{}{"status": runtimeUnknown, "reason": reason, "level": "unknown"}
}

// runtimeHeadlineRequested reads the headline flag STRICTLY, and deliberately not
// through truthy(): truthy reads any non-empty string as true, so headline="false"
// from a model that stringifies booleans would silently collapse the per-package rows
// into one verdict — dropping exactly the detail the caller asked to keep. Only a real
// true (or its usual string/number spellings) opts in; anything else, including an
// unparseable value, keeps the full result.
func runtimeHeadlineRequested(args map[string]interface{}) bool {
	if v, ok := argBool(args, "headline"); ok {
		return v
	}
	switch v := args["headline"].(type) {
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes":
			return true
		}
	case float64:
		return v != 0
	}
	return false
}

// registerRuntime registers the on-demand runtime package check.
func registerRuntime() {
	register(toolDef{
		name: "cloudsec_check_finding_runtime",
		description: "Ask whether the vulnerable code behind a package finding ACTUALLY RAN on the finding's cloud resource, using the endpoint telemetry LimaCharlie already retains. " +
			"INFORMATIONAL ONLY: it never changes the finding's lc_risk, status, fingerprint or disposition, and it is not a disposition you may act on as one. " +
			"The answer is one of exactly FIVE rungs and only one of them is negative: " +
			"'' (empty string) = unknown, no usable evidence (missing, stale, expired, unattributable or conflicting); " +
			"'present' = an agent is on the resource but the telemetry cannot carry a claim; " +
			"'not_observed' = a COMPLETE telemetry window saw the package never run; " +
			"'loaded' = the package is mapped into a running process; " +
			"'executing' = the package IS the running executable. " +
			"'not_observed' IS NOT A SAFETY CLAIM. It says a complete window did not see the code run — NOT that the package is gone, NOT that the finding is fixed, and NOT that the vulnerability is not exploitable. " +
			"Nothing this tool returns proves anything about exploitability, and no rung is a reason to close, suppress or deprioritise a finding on its own. " +
			"A TELEMETRY LAPSE NEVER PRODUCES A NEGATIVE: an interrupted or too-young window, a shed write, a truncated watch list, a package with no version, an unattributable package and a conflicting package inventory all come back as 'present' or unknown, each WITH a 'reason' naming the gate that failed — so read the reason before reporting an unknown. " +
			"Every row carries 'level' (observed | derived | unknown — never verified or asserted) and the window edges 'observed_at'/'stale_at', so state the freshness when you report a verdict. " +
			"'sensors_complete' false means the sensor set could not be fully enumerated, which makes every whole-resource negative impossible. " +
			"'complete' false with a 'retry_after' means a window is still maturing and asking again later could change the answer; any other unsettled state is final. " +
			"Set headline=true to get the ONE verdict to report instead of every row — do that rather than taking a maximum over the rows yourself, because the negative rung ranks BELOW 'present' on purpose so one incomplete package vetoes a whole-resource negative, and a maximum silently loses that veto. " +
			"The legacy 'dormant' spelling of 'not_observed' is decoded on read and never emitted. " +
			"NOTE this route is served by a gateway slice that may not be deployed in every datacenter yet; a 404/unknown-route error means exactly that and must not be reported as 'nothing ran'.",
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithString("finding_id",
				mcp.Required(),
				mcp.Description("The finding id (fnd_...) to check. Get one from cloudsec_list_findings")),
			mcp.WithBoolean("headline",
				mcp.Description("Return the single folded verdict instead of the per-package rows, using the backend's own aggregation (one incomplete package vetoes a whole-resource negative). Omit for the full result")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			findingID := argString(args, "finding_id")
			if findingID == "" {
				return tools.ErrorResult("finding_id parameter is required"), nil
			}
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}
			path := orgPath(org, "findings/"+url.PathEscape(findingID)+"/runtime-check")
			resp, err := postJSON(ctx, org, path, map[string]interface{}{}, defaultTimeout)
			if err != nil {
				// Deliberately an error, not an empty verdict: a runtime check that
				// quietly answers from nothing is the failure this whole package exists
				// to prevent.
				return tools.ErrorResultf("cloudsec request to %s failed: %s", path, describeErr(err)), nil
			}
			if runtimeHeadlineRequested(args) {
				return tools.SuccessResult(runtimeHeadline(resp)), nil
			}
			return tools.SuccessResult(normalizeRuntimeResult(resp)), nil
		},
	})
}

// normalizeRuntimeResult decodes each row's status onto the public ladder and leaves
// everything else untouched. The ONLY transformation is the one the contract mandates:
// a legacy `dormant` becomes `not_observed` and an unrecognized token becomes unknown,
// so a stale backend cannot put a spelling on the wire that a model then reasons about
// as if it were a rung. Rows are sorted by key for a stable answer.
func normalizeRuntimeResult(resp map[string]interface{}) map[string]interface{} {
	rows, ok := resp["packages"].([]interface{})
	if !ok {
		return resp
	}
	for _, row := range rows {
		entry, ok := row.(map[string]interface{})
		if !ok {
			continue
		}
		verdict, ok := entry["verdict"].(map[string]interface{})
		if !ok {
			continue
		}
		status, recognized := decodeRuntimeStatus(verdict["status"])
		verdict["status"] = status
		if !recognized {
			// Say so rather than passing off an unreadable token as a plain unknown.
			verdict["reason"] = "no_evidence"
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, _ := rows[i].(map[string]interface{})
		b, _ := rows[j].(map[string]interface{})
		ka, _ := a["key"].(string)
		kb, _ := b["key"].(string)
		return ka < kb
	})
	return resp
}
