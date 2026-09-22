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
	// unattributable or conflicting. Go's zero value is the empty string, so an unset
	// status is unknown by construction; a public API RENDERS it as
	// wireRuntimeUnknown, which is what a live response actually carries.
	runtimeUnknown = ""
	// wireRuntimeUnknown is how findings.WireRuntimeStatus spells the unknown rung on a
	// public API: an empty string in a JSON enum reads as a missing field rather than as
	// an answer. Every status the backend emits goes through that renderer, so refusing
	// this token would classify 100% of legitimate unknowns as malformed input — and, in
	// a reader that reacted to that, destroy the verdict's reason.
	wireRuntimeUnknown = "unknown"
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

// decodeRuntimeStatus folds any stored or wire spelling onto the public ladder,
// mirroring findings.DecodeRuntimeStatus. It accepts BOTH spellings of the unknown rung
// — the rendered wireRuntimeUnknown and Go's zero value — folds the legacy `dormant`
// token to not_observed, and reads an unrecognized token as unknown rather than as a
// verdict. The second return is false when the input was not a known token at all, so a
// caller can count malformed input instead of silently treating it as unknown. Nothing
// here can return the legacy token.
func decodeRuntimeStatus(v interface{}) (string, bool) {
	raw, ok := v.(string)
	if !ok {
		return runtimeUnknown, v == nil
	}
	switch token := strings.ToLower(strings.TrimSpace(raw)); token {
	case runtimeUnknown, wireRuntimeUnknown:
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
// running. Callers ask through this rather than testing "not loaded and not executing":
// those are different statements and only this one has been earned.
func isRuntimeNegative(status string) bool { return status == runtimeNotObserved }

func isRuntimePositive(status string) bool {
	return status == runtimeLoaded || status == runtimeExecuting
}

// runtimeLevels are the D1 evidence levels this lane may state. Nothing here is ever
// `verified` or `asserted`, so a level this build does not know is reported as unknown
// rather than echoed as a stronger claim than it is.
var runtimeLevels = map[string]bool{"observed": true, "derived": true, "unknown": true}

func runtimeLevel(v interface{}) string {
	if s, ok := v.(string); ok {
		if token := strings.ToLower(strings.TrimSpace(s)); runtimeLevels[token] {
			return token
		}
	}
	return "unknown"
}

// runtimeVerdict reads the SERVER's whole-resource verdict out of a check response.
//
// THERE IS DELIBERATELY NO CLIENT-SIDE FOLD. The backend already computes the verdict
// (runtimeevidence.CheckResult.Headline) and publishes it at the top of the `runtime`
// object, so this reads it. Re-deriving it here would be a permanent drift surface, and
// the obvious hand-rolled fold is wrong in one specific and dangerous way: the negative
// rung ranks BELOW `present`, so taking the strongest per-package answer reports a
// whole-machine negative whenever nothing positive turned up — losing the veto that one
// incomplete package, or a sensor set that could not be fully enumerated, must exercise.
// That is exactly the mistake a model handed the raw rows would make, which is why the
// tool offers this instead.
//
// The coverage fields ride along, because the description tells the model to read them:
// a verdict with no `sensors_complete`, `complete` or freshness is not reportable.
func runtimeVerdict(resp map[string]interface{}) map[string]interface{} {
	runtime, _ := resp["runtime"].(map[string]interface{})
	if runtime == nil {
		// `runtime: null` (unknown finding id), or a payload this build cannot read.
		// Either way there is no verdict, and inventing one is the failure this whole
		// package exists to prevent.
		runtime = map[string]interface{}{}
	}
	status, recognized := decodeRuntimeStatus(runtime["status"])
	out := map[string]interface{}{
		"status": status,
		// Whether the token was one this build knows. A caller can count malformed input
		// instead of reading it as a plain unknown.
		"status_recognized": recognized,
		// The server's reason, passed through AS STATED. It is deliberately not replaced
		// with a vocabulary token when the status is unreadable: `no_evidence` means "no
		// summary exists for this sensor", and asserting that would invent a coverage
		// fact nobody established while destroying what the server actually said.
		"reason":   stringOr(runtime["reason"], ""),
		"level":    runtimeLevel(runtime["level"]),
		"source":   stringOr(runtime["source"], ""),
		"accepted": resp["accepted"] == true,
	}
	// Coverage and freshness, copied only when the server stated them so an absent field
	// is not reported as a zero.
	for _, key := range []string{
		"resource_urn", "sensors", "sensors_complete", "complete",
		"retry_after_seconds", "checked_at",
	} {
		if v, present := runtime[key]; present {
			out[key] = v
		}
	}
	return out
}

func stringOr(v interface{}, fallback string) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fallback
}

// registerRuntime registers the on-demand runtime package check.
func registerRuntime() {
	register(toolDef{
		name: "cloudsec_check_finding_runtime",
		description: "Ask whether the vulnerable code behind a package finding ACTUALLY RAN on the finding's cloud resource, using the endpoint telemetry LimaCharlie already retains. " +
			"INFORMATIONAL ONLY: it never changes the finding's lc_risk, status, fingerprint or disposition, and it is not a disposition you may act on as one. " +
			"The answer is one of exactly FIVE rungs and only one of them is negative: " +
			"'unknown' = no usable evidence (missing, stale, expired, unattributable or conflicting); " +
			"'present' = an agent is on the resource but the telemetry cannot carry a claim; " +
			"'not_observed' = a COMPLETE telemetry window saw the package never run; " +
			"'loaded' = the package is mapped into a running process; " +
			"'executing' = the package IS the running executable. " +
			"'not_observed' IS NOT A SAFETY CLAIM. It says a complete window did not see the code run — NOT that the package is gone, NOT that the finding is fixed, and NOT that the vulnerability is not exploitable. " +
			"Nothing this tool returns proves anything about exploitability, and no rung is a reason to close, suppress or deprioritise a finding on its own. " +
			"A TELEMETRY LAPSE NEVER PRODUCES A NEGATIVE: an interrupted or too-young window, a shed write, a truncated watch list, a package with no version, an unattributable package and a conflicting package inventory all come back as 'present' or unknown, each WITH a 'reason' naming the gate that failed — so read the reason before reporting an unknown. " +
			"READ 'accepted' BEFORE 'status'. False means the check DID NOT RUN, and 'reason' is then an availability reason rather than a verdict: 'feature_disabled' (the runtime-evidence feature is DEFAULT-OFF, so this is the answer for most orgs today), 'no_resource', 'no_packages', 'no_sensors' or 'cache_unavailable'. None of those is a statement that nothing ran. An unknown finding id returns 'runtime': null. " +
			"ASKING IS WHAT STARTS THE MEASUREMENT, which is why this is a POST: the check publishes the finding's packages as relevant so the agents begin summarizing them, and evidence accumulates over the following minutes. A COLD FIRST CALL IS EXPECTED TO BE INCONCLUSIVE — 'complete' false with 'retry_after_seconds' means the window has not matured yet, so ask again rather than reporting it as a finished answer. " +
			"Each row carries 'level' (observed | derived | unknown — never verified or asserted) and, where known, 'observed_at'/'stale_at', so state the freshness when you report a verdict. 'sensors_complete' false means the sensor set could not be fully enumerated, which makes every whole-resource negative impossible. " +
			"Set verdict=true to get the ONE verdict to report: the server's own whole-resource verdict plus the coverage it rests on. Do that rather than reducing the per-package rows yourself, because the negative rung ranks BELOW 'present' on purpose so one incomplete package vetoes a whole-resource negative, and taking the strongest row loses that veto. " +
			"The legacy 'dormant' spelling of 'not_observed' is decoded on read and never emitted. " +
			"NOTE this route is served by a gateway slice that may not be deployed in every datacenter yet; a 404/unknown-route error means exactly that and must not be reported as 'nothing ran'.",
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithString("finding_id",
				mcp.Required(),
				mcp.Description("The finding id (fnd_...) to check. Get one from cloudsec_list_findings")),
			mcp.WithBoolean("verdict",
				mcp.Description("Return the server's single whole-resource verdict plus its coverage, instead of the per-package rows. Prefer this over reducing the rows yourself: one incomplete package vetoes a whole-resource negative, and the strongest row loses that veto. Omit for the full result")),
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
			// The body is EMPTY and must stay so. Plan §9: every target is derived from
			// the finding id server-side, so a caller cannot name a sensor, a resource or
			// a package — and the only way to keep that true from here is to send nothing.
			resp, err := postJSON(ctx, org, path, map[string]interface{}{}, defaultTimeout)
			if err != nil {
				// Deliberately an error, not an empty verdict: a runtime check that
				// quietly answers from nothing is the failure this whole package exists
				// to prevent. Note the backend answers its own no-verdict cases with a
				// 200 and accepted:false, which runtimeVerdict surfaces rather than
				// converting into a rung.
				return tools.ErrorResultf("cloudsec request to %s failed: %s", path, describeErr(err)), nil
			}
			if runtimeVerdictRequested(args) {
				return tools.SuccessResult(runtimeVerdict(resp)), nil
			}
			return tools.SuccessResult(normalizeRuntimeResult(resp)), nil
		},
	})
}

// runtimeVerdictRequested reads the flag STRICTLY, and deliberately not through truthy():
// truthy reads any non-empty string as true, so verdict="false" from a model that
// stringifies booleans would silently collapse the per-package rows into one verdict,
// dropping exactly the detail the caller asked to keep. Only a real true (or its usual
// string/number spellings) opts in; anything else, including an unparseable value, keeps
// the full result.
func runtimeVerdictRequested(args map[string]interface{}) bool {
	if v, ok := argBool(args, "verdict"); ok {
		return v
	}
	switch v := args["verdict"].(type) {
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes":
			return true
		}
	case float64:
		return v != 0
	case int:
		return v != 0
	case int64:
		return v != 0
	}
	return false
}

// normalizeRuntimeResult folds every status in the response onto the public ladder and
// leaves everything else alone.
//
// The ONLY transformations are the ones the contract mandates: the legacy `dormant`
// spelling becomes not_observed, the rendered `unknown` spelling becomes the unknown
// rung, and a token this build does not recognize becomes unknown WITH an explicit
// `status_recognized: false` beside it — not a rewritten `reason`, because overwriting
// the server's reason with a vocabulary token would destroy what it said and assert a
// coverage fact nobody established.
//
// The shape is the gateway's: `{"accepted":…, "runtime":{…, "packages":[FLAT rows]}}`.
// Rows are sorted by package key for a stable answer.
func normalizeRuntimeResult(resp map[string]interface{}) map[string]interface{} {
	runtime, ok := resp["runtime"].(map[string]interface{})
	if !ok {
		return resp
	}
	if status, recognized := decodeRuntimeStatus(runtime["status"]); runtime["status"] != nil || !recognized {
		runtime["status"] = status
		if !recognized {
			runtime["status_recognized"] = false
		}
	}
	rows, ok := runtime["packages"].([]interface{})
	if !ok {
		return resp
	}
	for _, row := range rows {
		entry, ok := row.(map[string]interface{})
		if !ok {
			continue
		}
		status, recognized := decodeRuntimeStatus(entry["status"])
		entry["status"] = status
		if !recognized {
			entry["status_recognized"] = false
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
