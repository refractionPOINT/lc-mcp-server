package cloudsec

import (
	"regexp"
	"strings"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests pin the properties the runtime ladder exists FOR, not its shape:
//
//   - "Decode legacy dormant as not_observed but never emit it"; and
//   - "Runtime negative only on complete window; telemetry lapse yields unknown", which
//     on this side means the tool must never manufacture a negative and must never
//     report an unavailable check as one.
//
// WIRE shape: the gateway route returns {"accepted": bool, "runtime": {...}|null} with
// FLAT per-package rows and the unknown rung rendered as the literal "unknown".

// legacyToken is spelled out here rather than reused from the package constant: a test
// asserting that a token can never come back out should not depend on the production
// code's own name for it.
const legacyToken = "dormant"

// row is one FLAT per-package row, exactly as runtimeVerdictWire emits it.
func row(key, status, reason string) map[string]interface{} {
	return map[string]interface{}{
		"key": key, "status": status, "reason": reason,
		"level": "derived", "source": "endpoint_runtime_package",
	}
}

// envelope is the full response: {"accepted":…, "runtime":{headline…, packages:[…]}}.
func envelope(status, reason string, sensorsComplete bool, rows ...map[string]interface{}) map[string]interface{} {
	packages := make([]interface{}, 0, len(rows))
	for _, r := range rows {
		packages = append(packages, r)
	}
	return map[string]interface{}{
		"accepted": true,
		"runtime": map[string]interface{}{
			"resource_urn":     "lcrn:cloud:gcp:proj:instance/vm-1",
			"status":           status,
			"reason":           reason,
			"level":            "derived",
			"source":           "endpoint_runtime_package",
			"sensors":          float64(1),
			"sensors_complete": sensorsComplete,
			"complete":         true,
			"checked_at":       "2026-09-22T20:00:00Z",
			"packages":         packages,
		},
	}
}

// ---------------------------------------------------------------------------
// The ladder and the decoder
// ---------------------------------------------------------------------------

func TestRuntimeLadderIsExactlyFiveRungsInEvidenceOrder(t *testing.T) {
	// A sixth rung here without one in findings.RuntimeStatuses() is how a surface
	// starts claiming something the backend never said.
	assert.Equal(t, []string{"", "present", "not_observed", "loaded", "executing"}, runtimeStatuses)
	// …and the wire spells the unknown rung, because an empty string in a JSON enum
	// reads as a missing field rather than as an answer.
	assert.Equal(t, "unknown", wireRuntimeUnknown)
}

func TestOnlySightingsArePositiveAndOnlyNotObservedIsNegative(t *testing.T) {
	var positive, negative []string
	for _, s := range runtimeStatuses {
		if isRuntimePositive(s) {
			positive = append(positive, s)
		}
		if isRuntimeNegative(s) {
			negative = append(negative, s)
		}
	}
	assert.Equal(t, []string{"loaded", "executing"}, positive)
	assert.Equal(t, []string{"not_observed"}, negative)
	// "not loaded and not executing" is NOT the negative rung.
	assert.False(t, isRuntimeNegative(runtimePresent))
	assert.False(t, isRuntimeNegative(runtimeUnknown))
}

func TestTheRenderedUnknownSpellingIsRecognised(t *testing.T) {
	// THIS IS WHAT A LIVE RESPONSE CARRIES. findings.WireRuntimeStatus renders the
	// unknown rung as the literal token and the backend puts every status through it, so
	// refusing it would classify 100% of legitimate unknowns as malformed input.
	for _, token := range []string{"unknown", "UNKNOWN", "  Unknown  "} {
		status, recognized := decodeRuntimeStatus(token)
		assert.Equal(t, runtimeUnknown, status, token)
		assert.True(t, recognized, token)
	}
}

func TestLegacyDormantDecodesToNotObservedAndCanNeverBeEmitted(t *testing.T) {
	for _, token := range []string{legacyToken, "DORMANT", "  Dormant  "} {
		status, recognized := decodeRuntimeStatus(token)
		assert.Equal(t, runtimeNotObserved, status, token)
		assert.True(t, recognized, token)
	}
	// Structurally: no input can make the decoder yield the legacy token.
	for _, in := range []interface{}{legacyToken, "", nil, "unknown", "sixth_rung", 7, []string{}} {
		status, _ := decodeRuntimeStatus(in)
		assert.NotEqual(t, legacyToken, status)
		assert.Contains(t, runtimeStatuses, status)
	}
	assert.NotContains(t, runtimeStatuses, legacyToken)

	// And neither reader can smuggle it out of a whole response.
	assert.Equal(t, runtimeNotObserved,
		runtimeVerdict(envelope(legacyToken, "complete_window", true))["status"])
	normalized := normalizeRuntimeResult(envelope(runtimePresent, "window_short", true,
		row("deb|openssl|3.0.2", legacyToken, "complete_window")))
	rows := normalized["runtime"].(map[string]interface{})["packages"].([]interface{})
	assert.Equal(t, runtimeNotObserved, rows[0].(map[string]interface{})["status"])
}

func TestAbsentOrEmptyStatusIsAlsoUnknown(t *testing.T) {
	// Go's zero value. Both spellings must decode or the round trip is not total.
	for _, in := range []interface{}{nil, "", "   "} {
		status, recognized := decodeRuntimeStatus(in)
		assert.Equal(t, runtimeUnknown, status)
		assert.True(t, recognized, "an empty status is a spelling of unknown, not malformed input")
	}
}

func TestAnUnrecognisedTokenIsUnknownAndReportedAsUnrecognised(t *testing.T) {
	// A rung invented by a newer backend must not be rendered as one of ours, and above
	// all must not land on the negative.
	for _, in := range []interface{}{"sixth_rung", "not observed", "safe", 7, true} {
		status, recognized := decodeRuntimeStatus(in)
		assert.Equal(t, runtimeUnknown, status)
		assert.False(t, recognized)
	}
}

func TestRuntimeLevelIsNarrowedRatherThanEchoed(t *testing.T) {
	// Nothing on this lane is ever `verified` or `asserted`. Echoing a level this build
	// does not know would let the backend assert a stronger claim than the client can
	// reason about.
	assert.Equal(t, "observed", runtimeLevel("OBSERVED"))
	assert.Equal(t, "derived", runtimeLevel(" derived "))
	for _, in := range []interface{}{"verified", "asserted", "", nil, 7} {
		assert.Equal(t, "unknown", runtimeLevel(in))
	}
}

// ---------------------------------------------------------------------------
// Reading the SERVER's verdict
// ---------------------------------------------------------------------------

func TestTheVerdictIsReadFromTheServersHeadlineNotReDerived(t *testing.T) {
	// The backend computes CheckResult.Headline() and puts it at the top of `runtime`.
	// The rows below deliberately say something different: a client that folded them
	// itself would have to get the negative veto right forever, and the obvious fold
	// (strongest row wins) would answer `executing` here instead of the server's
	// `present`.
	v := runtimeVerdict(envelope(runtimePresent, "telemetry_absent", true,
		row("deb|openssl|3.0.2", runtimeExecuting, "observed_executing"),
		row("deb|zlib1g|1.2.11", runtimeNotObserved, "complete_window"),
	))
	assert.Equal(t, runtimePresent, v["status"])
	assert.Equal(t, "telemetry_absent", v["reason"])
	assert.Equal(t, "endpoint_runtime_package", v["source"])
	assert.Equal(t, "lcrn:cloud:gcp:proj:instance/vm-1", v["resource_urn"])
	assert.Equal(t, true, v["accepted"])
}

func TestTheRenderedUnknownRungSurvivesTheEnvelopeWithItsReasonIntact(t *testing.T) {
	v := runtimeVerdict(envelope(wireRuntimeUnknown, "inventory_conflict", true))
	assert.Equal(t, runtimeUnknown, v["status"])
	assert.Equal(t, true, v["status_recognized"])
	// The reason is the only thing that makes an unknown actionable. Losing it — by
	// treating the rendered token as malformed and rewriting the reason — is the quiet
	// failure here.
	assert.Equal(t, "inventory_conflict", v["reason"])
}

func TestAnUnavailableCheckIsReportedAsNotRunAndNeverAsANegative(t *testing.T) {
	// The feature is DEFAULT-OFF, so this is the answer for most orgs today. It must not
	// read as "nothing ran", and it must not be attributed to a sensor-enumeration
	// failure either.
	resp := map[string]interface{}{
		"accepted": false,
		"runtime": map[string]interface{}{
			"status": wireRuntimeUnknown, "reason": "feature_disabled",
			"level": "unknown", "sensors": float64(0),
			"sensors_complete": false, "complete": false,
		},
	}
	v := runtimeVerdict(resp)
	assert.Equal(t, false, v["accepted"])
	assert.Equal(t, runtimeUnknown, v["status"])
	assert.False(t, isRuntimeNegative(v["status"].(string)))
	assert.Equal(t, "feature_disabled", v["reason"])
	assert.Equal(t, false, v["sensors_complete"])
}

func TestAnUnknownFindingIdYieldsANullRuntimeAndStillReadsAsUnknown(t *testing.T) {
	v := runtimeVerdict(map[string]interface{}{"accepted": false, "runtime": nil})
	assert.Equal(t, runtimeUnknown, v["status"])
	assert.Equal(t, false, v["accepted"])
	assert.False(t, isRuntimeNegative(v["status"].(string)))
}

func TestAnImmatureWindowReportsTheRetryTheServerStatedInSeconds(t *testing.T) {
	// Asking is what STARTS the measurement, so a cold first call is expected to be
	// inconclusive. The field is retry_after_seconds — seconds, not a Go duration.
	resp := envelope(runtimePresent, "window_short", true)
	runtime := resp["runtime"].(map[string]interface{})
	runtime["complete"] = false
	runtime["retry_after_seconds"] = float64(241)
	v := runtimeVerdict(resp)
	assert.Equal(t, false, v["complete"])
	assert.Equal(t, float64(241), v["retry_after_seconds"])
}

func TestASettledAnswerCarriesNoRetryKeyAtAll(t *testing.T) {
	// Absent must stay absent: reporting retry_after_seconds: 0 would say "ask again
	// immediately" about an answer that is final.
	assert.NotContains(t, runtimeVerdict(envelope(runtimeNotObserved, "complete_window", true)),
		"retry_after_seconds")
}

func TestVerdictToleratesAMalformedOrEmptyEnvelope(t *testing.T) {
	for _, resp := range []map[string]interface{}{
		{},
		{"runtime": "not a map"},
		{"runtime": map[string]interface{}{}},
		{"accepted": true},
	} {
		v := runtimeVerdict(resp)
		assert.Equal(t, runtimeUnknown, v["status"])
		assert.False(t, isRuntimeNegative(v["status"].(string)))
		assert.Equal(t, "unknown", v["level"])
	}
}

func TestTheReaderDoesNotOverwriteTheServersReasonForAnUnreadableStatus(t *testing.T) {
	// `no_evidence` means "no summary exists for this sensor". Stamping it here would
	// assert a coverage fact nobody established and destroy what the server said.
	v := runtimeVerdict(envelope("sixth_rung", "relevance_truncated", true))
	assert.Equal(t, runtimeUnknown, v["status"])
	assert.Equal(t, false, v["status_recognized"])
	assert.Equal(t, "relevance_truncated", v["reason"])
}

// ---------------------------------------------------------------------------
// Normalizing the rows
// ---------------------------------------------------------------------------

func TestNormalizeWalksTheRealEnvelopeAndDecodesEveryStatus(t *testing.T) {
	// The regression this pins: a normalizer written against the internal struct shape
	// (top-level `packages`, rows with a nested `verdict`) is a NO-OP on the real wire,
	// so the whole decode layer silently never runs.
	out := normalizeRuntimeResult(envelope(wireRuntimeUnknown, "sensors_partial", false,
		row("deb|zlib1g|1.2.11", legacyToken, "complete_window"),
		row("deb|openssl|3.0.2", wireRuntimeUnknown, "unversioned"),
	))
	runtime := out["runtime"].(map[string]interface{})
	assert.Equal(t, runtimeUnknown, runtime["status"])
	rows := runtime["packages"].([]interface{})
	// Sorted by key, statuses folded onto the ladder.
	assert.Equal(t, "deb|openssl|3.0.2", rows[0].(map[string]interface{})["key"])
	assert.Equal(t, runtimeUnknown, rows[0].(map[string]interface{})["status"])
	assert.Equal(t, runtimeNotObserved, rows[1].(map[string]interface{})["status"])
	// The server's reasons survive untouched.
	assert.Equal(t, "unversioned", rows[0].(map[string]interface{})["reason"])
}

func TestNormalizeMarksAnUnreadableTokenWithoutDestroyingTheReason(t *testing.T) {
	out := normalizeRuntimeResult(envelope(runtimePresent, "window_short", true,
		row("deb|openssl|3.0.2", "sixth_rung", "relevance_truncated"),
	))
	entry := out["runtime"].(map[string]interface{})["packages"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, runtimeUnknown, entry["status"])
	assert.Equal(t, false, entry["status_recognized"])
	// NOT rewritten to `no_evidence`: that would assert a coverage fact nobody
	// established and throw away what the backend actually said.
	assert.Equal(t, "relevance_truncated", entry["reason"])
}

func TestNormalizeLeavesEverythingElseUntouched(t *testing.T) {
	in := envelope(runtimeLoaded, "observed_loaded", true, row("deb|openssl|3.0.2", runtimeLoaded, "observed_loaded"))
	runtime := in["runtime"].(map[string]interface{})
	runtime["retry_after_seconds"] = float64(241)
	out := normalizeRuntimeResult(in)
	got := out["runtime"].(map[string]interface{})
	assert.Equal(t, "lcrn:cloud:gcp:proj:instance/vm-1", got["resource_urn"])
	assert.Equal(t, float64(241), got["retry_after_seconds"])
	assert.Equal(t, "2026-09-22T20:00:00Z", got["checked_at"])
	assert.Equal(t, true, out["accepted"])
}

func TestNormalizeToleratesAMalformedPayload(t *testing.T) {
	assert.NotPanics(t, func() {
		normalizeRuntimeResult(map[string]interface{}{})
		normalizeRuntimeResult(map[string]interface{}{"runtime": nil})
		normalizeRuntimeResult(map[string]interface{}{"runtime": "not a map"})
		normalizeRuntimeResult(map[string]interface{}{"runtime": map[string]interface{}{"packages": "not a list"}})
		normalizeRuntimeResult(map[string]interface{}{"runtime": map[string]interface{}{
			"packages": []interface{}{nil, "x", map[string]interface{}{}},
		}})
	})
}

// ---------------------------------------------------------------------------
// The verdict flag
// ---------------------------------------------------------------------------

func TestVerdictFlagIsReadStrictlySoAStringifiedFalseDoesNotOptIn(t *testing.T) {
	// truthy() reads any non-empty string as true, so verdict:"false" from a model that
	// stringifies booleans would drop the per-package rows the caller asked to keep.
	assert.True(t, runtimeVerdictRequested(map[string]interface{}{"verdict": true}))
	assert.True(t, runtimeVerdictRequested(map[string]interface{}{"verdict": "true"}))
	assert.True(t, runtimeVerdictRequested(map[string]interface{}{"verdict": "YES"}))
	assert.True(t, runtimeVerdictRequested(map[string]interface{}{"verdict": float64(1)}))
	assert.True(t, runtimeVerdictRequested(map[string]interface{}{"verdict": 1}))
	for _, v := range []interface{}{false, "false", "FALSE", "no", "", float64(0), 0, nil, "maybe"} {
		assert.False(t, runtimeVerdictRequested(map[string]interface{}{"verdict": v}), v)
	}
	assert.False(t, runtimeVerdictRequested(map[string]interface{}{}))
}

// ---------------------------------------------------------------------------
// The tool's own description — the surface a model actually reads
// ---------------------------------------------------------------------------

// safetyClaims are constructions with NO honest use in this description. The list is
// deliberately short, because most of the loaded words are context-dependent: "the
// finding is fixed" and "not exploitable" both appear in the sentence that MAKES the
// description honest, so banning them outright would forbid the fix.
var safetyClaims = []string{
	"proves safe", "no risk", "safe to ignore", "no action needed",
	"is remediated", "treat it as remediated", "effectively fixed",
	"nothing further is required", "not affected", "is not vulnerable",
	"false positive", "you may close", "can be closed", "proves the vulnerability",
}

// negatedProve allows a proof claim about exploitability only when the negation comes
// BEFORE the verb: "nothing this tool returns proves anything about exploitability"
// passes, "proves the CVE is exploitable, nothing else does" does not. Matching the
// negation anywhere in the clause would not work — a dishonest sentence usually carries
// one somewhere else, which is exactly how this test's first version passed everything.
var negatedProve = regexp.MustCompile(`\b(?:nothing|not|never|cannot|no)\b[^.]{0,40}?prove`)

// requiredDenials are the statements the description must actually CONTAIN. The ban list
// catches an overclaim; only this catches silence, which is the other failure mode and
// which no ban list can detect.
var requiredDenials = []string{
	"not that the package is gone",
	"not that the finding is fixed",
	"not that the vulnerability is not exploitable",
	"proves anything about exploitability",
}

// affirmsNoSafety asserts the text never AFFIRMS safety while allowing it to deny safety.
//
// WHAT IT CANNOT DO: decide in general whether prose affirms or denies. The first version
// of this helper tried, with a bare `strings.Contains(clause, "not ")`, and was satisfied
// by accident in almost any sentence — `not_observed` contains "not", as do "nothing" and
// "cannot". So it asserts only what it can assert soundly, and the caller adds the part
// with the most teeth: that the denials are present.
func affirmsNoSafety(t *testing.T, text string) {
	t.Helper()
	lowered := strings.ToLower(text)
	for _, claim := range safetyClaims {
		assert.NotContains(t, lowered, claim, claim)
	}
	for _, clause := range strings.Split(strings.ReplaceAll(lowered, "\n", " "), ".") {
		if strings.Contains(clause, "exploit") && strings.Contains(clause, "prove") {
			assert.Regexp(t, negatedProve, clause,
				"a proof claim about exploitability must be negated before the verb")
		}
	}
}

// TestTheHonestyGuardRejectsDishonestCopy tests the test. A guard nothing can fail is not
// a guard, and the first version of affirmsNoSafety accepted every sample below.
func TestTheHonestyGuardRejectsDishonestCopy(t *testing.T) {
	for _, sample := range []string{
		"not_observed proves the vulnerability is not exploitable and the finding is fixed.",
		"Nothing further is required; treat it as remediated and close the finding.",
		"A not_observed rung means the finding is effectively fixed.",
		"An executing rung proves the CVE is exploitable, nothing else does.",
	} {
		fake := &testing.T{}
		affirmsNoSafety(fake, sample)
		assert.True(t, fake.Failed(), "the guard must reject: %s", sample)
	}
	// …and it accepts the real copy's shape, so it is not merely rejecting everything.
	honest := &testing.T{}
	affirmsNoSafety(honest, "not_observed says a complete window did not see the code run "+
		"— not that the package is gone, not that the finding is fixed, and not that the "+
		"vulnerability is not exploitable. Nothing this tool returns proves anything about "+
		"exploitability.")
	assert.False(t, honest.Failed())
}

func TestRuntimeToolDescriptionRefusesToClaimSafety(t *testing.T) {
	reg, ok := tools.GetTool("cloudsec_check_finding_runtime")
	require.True(t, ok, "the runtime check must be registered")
	desc := reg.Description

	// It names every rung, so a model never has to guess at the vocabulary.
	for _, rung := range []string{"present", "not_observed", "loaded", "executing", "unknown"} {
		assert.Contains(t, desc, rung, rung)
	}
	// It states the negative's precondition, and that a lapse is not one.
	assert.Contains(t, desc, "COMPLETE telemetry window")
	assert.Contains(t, desc, "NOT A SAFETY CLAIM")
	assert.Contains(t, desc, "NEVER PRODUCES A NEGATIVE")
	// It tells the model to read `accepted` first, and that the feature is default-off —
	// without which the single most common real answer reads as "nothing ran".
	assert.Contains(t, desc, "READ 'accepted' BEFORE 'status'")
	assert.Contains(t, desc, "feature_disabled")
	assert.Contains(t, desc, "DEFAULT-OFF")
	// And that asking starts the measurement, so a first call is expected to be
	// inconclusive rather than final.
	assert.Contains(t, desc, "ASKING IS WHAT STARTS THE MEASUREMENT")
	assert.Contains(t, desc, "retry_after_seconds")

	// Silence is the other way this goes wrong, so the denials must be PRESENT…
	lowered := strings.ToLower(desc)
	for _, denial := range requiredDenials {
		assert.Contains(t, lowered, denial, denial)
	}
	// …and nothing may affirm safety.
	affirmsNoSafety(t, desc)

	// Read-only, and annotated as such.
	require.NotNil(t, reg.Schema.Annotations.ReadOnlyHint)
	assert.True(t, *reg.Schema.Annotations.ReadOnlyHint)
	require.NotNil(t, reg.Schema.Annotations.DestructiveHint)
	assert.False(t, *reg.Schema.Annotations.DestructiveHint)
	// The extension gate note is appended by register(); assert it actually lands.
	assert.Contains(t, desc, "subscribe_to_extension")
}
