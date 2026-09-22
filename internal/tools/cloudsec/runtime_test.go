package cloudsec

import (
	"strings"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests pin the two properties the runtime ladder exists FOR, not its shape:
//
//   - plan 24 §14 — "Decode legacy dormant as not_observed but never emit it"; and
//   - plan 24 §18 gate 12 — "Runtime negative only on complete window; telemetry lapse
//     yields unknown", which at this grain means no fold over incomplete input may
//     produce not_observed.
//
// Authority: go-cloudsec findings/runtime.go + runtimeevidence/verdict.go
// (PR refractionPOINT/go-cloudsec#413).

// negated reports whether a clause denies rather than asserts. The checks below are
// about AFFIRMATIVE claims: the sentences that make the tool description honest are
// themselves denials ("NOT that the vulnerability is not exploitable", "nothing this
// tool returns proves anything about exploitability"), so a flat substring ban on the
// loaded words would forbid exactly the copy that fixes the problem.
func negated(clause string) bool {
	for _, marker := range []string{"not ", "never", "nothing", "cannot", "no rung"} {
		if strings.Contains(clause, marker) {
			return true
		}
	}
	return false
}

// legacyToken is spelled out here rather than reused from the package constant: a test
// asserting that a token can never come back out should not depend on the production
// code's own name for it.
const legacyToken = "dormant"

func verdictRow(key, status, reason string) map[string]interface{} {
	return map[string]interface{}{
		"key":     key,
		"verdict": map[string]interface{}{"status": status, "reason": reason, "level": "derived"},
	}
}

func result(sensorsComplete bool, rows ...map[string]interface{}) map[string]interface{} {
	packages := make([]interface{}, 0, len(rows))
	for _, r := range rows {
		packages = append(packages, r)
	}
	return map[string]interface{}{"packages": packages, "sensors_complete": sensorsComplete}
}

// ---------------------------------------------------------------------------
// The ladder and the legacy token
// ---------------------------------------------------------------------------

func TestRuntimeLadderIsExactlyFiveRungsInEvidenceOrder(t *testing.T) {
	// A sixth rung here without one in findings.RuntimeStatuses() is how a surface
	// starts claiming something the backend never said.
	assert.Equal(t, []string{"", "present", "not_observed", "loaded", "executing"}, runtimeStatuses)
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

func TestLegacyDormantDecodesToNotObservedAndCanNeverBeEmitted(t *testing.T) {
	for _, token := range []string{legacyToken, "DORMANT", "  Dormant  "} {
		status, recognized := decodeRuntimeStatus(token)
		assert.Equal(t, runtimeNotObserved, status, token)
		assert.True(t, recognized, token)
	}
	// Structurally: no input can make any of these paths yield the legacy token.
	for _, in := range []interface{}{legacyToken, "", nil, "sixth_rung", 7, []string{}} {
		status, _ := decodeRuntimeStatus(in)
		assert.NotEqual(t, legacyToken, status)
		assert.Contains(t, runtimeStatuses, status)
	}
	assert.NotContains(t, runtimeStatuses, legacyToken)

	// And neither the fold nor the row normalizer can smuggle it out.
	folded := runtimeHeadline(result(true, verdictRow("deb|openssl|3.0.2", legacyToken, "")))
	assert.Equal(t, runtimeNotObserved, folded["status"])

	normalized := normalizeRuntimeResult(result(true, verdictRow("deb|openssl|3.0.2", legacyToken, "")))
	rows := normalized["packages"].([]interface{})
	verdict := rows[0].(map[string]interface{})["verdict"].(map[string]interface{})
	assert.Equal(t, runtimeNotObserved, verdict["status"])
}

func TestAbsentOrEmptyStatusIsUnknownRatherThanAVerdict(t *testing.T) {
	for _, in := range []interface{}{nil, "", "   "} {
		status, recognized := decodeRuntimeStatus(in)
		assert.Equal(t, runtimeUnknown, status)
		assert.True(t, recognized, "an empty status is the wire spelling of unknown, not malformed input")
	}
}

func TestAnUnrecognisedTokenIsUnknownAndReportedAsUnrecognised(t *testing.T) {
	// A rung invented by a newer backend must not be rendered as one of ours, and above
	// all must not land on the negative. `recognized` lets a caller count that instead
	// of silently reading it as unknown.
	for _, in := range []interface{}{"sixth_rung", "not observed", "safe", 7, true} {
		status, recognized := decodeRuntimeStatus(in)
		assert.Equal(t, runtimeUnknown, status)
		assert.False(t, recognized)
	}
}

func TestNormalizeMarksAnUnreadableTokenRatherThanPassingItOffAsPlainUnknown(t *testing.T) {
	out := normalizeRuntimeResult(result(true, verdictRow("deb|openssl|3.0.2", "sixth_rung", "")))
	verdict := out["packages"].([]interface{})[0].(map[string]interface{})["verdict"].(map[string]interface{})
	assert.Equal(t, runtimeUnknown, verdict["status"])
	assert.Equal(t, "no_evidence", verdict["reason"])
}

func TestNormalizeSortsRowsAndLeavesEverythingElseUntouched(t *testing.T) {
	in := result(true,
		verdictRow("deb|zlib1g|1.2.11", runtimePresent, "window_short"),
		verdictRow("deb|openssl|3.0.2", runtimeLoaded, "observed_loaded"),
	)
	in["resource_urn"] = "lcrn:cloud:gcp:proj:instance/vm-1"
	in["retry_after"] = float64(240000000000)
	out := normalizeRuntimeResult(in)
	rows := out["packages"].([]interface{})
	assert.Equal(t, "deb|openssl|3.0.2", rows[0].(map[string]interface{})["key"])
	// Nothing else is reinterpreted — an unsettled answer stays unsettled.
	assert.Equal(t, "lcrn:cloud:gcp:proj:instance/vm-1", out["resource_urn"])
	assert.Equal(t, float64(240000000000), out["retry_after"])
}

func TestNormalizeToleratesAMalformedPayload(t *testing.T) {
	assert.NotPanics(t, func() {
		normalizeRuntimeResult(map[string]interface{}{"packages": "not a list"})
		normalizeRuntimeResult(map[string]interface{}{"packages": []interface{}{nil, "x", map[string]interface{}{}}})
		normalizeRuntimeResult(map[string]interface{}{})
	})
}

// ---------------------------------------------------------------------------
// The fold: no negative from incomplete input
// ---------------------------------------------------------------------------

func TestEmptyResultIsUnknownAndSaysWhichKindOfNothing(t *testing.T) {
	assert.Equal(t, map[string]interface{}{"status": "", "reason": "no_evidence", "level": "unknown"},
		runtimeHeadline(result(true)))
	// A partial sensor enumeration is a DIFFERENT nothing, and the reason says so.
	assert.Equal(t, "sensors_partial", runtimeHeadline(result(false))["reason"])
	assert.Equal(t, "sensors_partial", runtimeHeadline(map[string]interface{}{})["reason"])
}

func TestAPartialSensorSetVetoesAUnanimousNegative(t *testing.T) {
	// §18 gate 12 at the resource grain: the negative needs a complete window AND a
	// complete sensor enumeration.
	folded := runtimeHeadline(result(false, verdictRow("deb|openssl|3.0.2", runtimeNotObserved, "complete_window")))
	assert.Equal(t, runtimeUnknown, folded["status"])
	assert.Equal(t, "sensors_partial", folded["reason"])
}

func TestOneIncompletePackageVetoesAWholeResourceNegative(t *testing.T) {
	// THE REASON runtimeHeadline EXISTS. A naive maximum returns not_observed here; the
	// real ranking puts the negative BELOW present precisely so this veto works.
	folded := runtimeHeadline(result(true,
		verdictRow("deb|openssl|3.0.2", runtimeNotObserved, "complete_window"),
		verdictRow("deb|zlib1g|1.2.11", runtimePresent, "telemetry_absent"),
	))
	assert.Equal(t, runtimePresent, folded["status"])
	assert.Equal(t, "telemetry_absent", folded["reason"])
}

func TestOneUnknownSiblingAlsoVetoesTheNegative(t *testing.T) {
	folded := runtimeHeadline(result(true,
		verdictRow("deb|openssl|3.0.2", runtimeNotObserved, "complete_window"),
		verdictRow("deb|libxml2|2.9.13", runtimeUnknown, "inventory_conflict"),
	))
	assert.False(t, isRuntimeNegative(folded["status"].(string)))
	assert.Equal(t, runtimeUnknown, folded["status"])
}

func TestAUnanimousNegativeOverACompleteSensorSetSurvives(t *testing.T) {
	// The negative is reachable — it just has to be earned. A fold that could NEVER
	// return it would make the rung decorative and hide a real regression.
	folded := runtimeHeadline(result(true,
		verdictRow("deb|openssl|3.0.2", runtimeNotObserved, "complete_window"),
		verdictRow("deb|zlib1g|1.2.11", runtimeNotObserved, "complete_window"),
	))
	assert.Equal(t, runtimeNotObserved, folded["status"])
	assert.Equal(t, "complete_window", folded["reason"])
}

func TestASightingOnAnyPackageIsTheAnswerRegardlessOfCompleteness(t *testing.T) {
	// Incomplete evidence can hide a sighting; it cannot invent one.
	for _, sighting := range []string{runtimeLoaded, runtimeExecuting} {
		folded := runtimeHeadline(result(false,
			verdictRow("deb|zlib1g|1.2.11", runtimeNotObserved, "complete_window"),
			verdictRow("deb|openssl|3.0.2", sighting, "observed_loaded"),
		))
		assert.Equal(t, sighting, folded["status"])
	}
}

func TestExecutingOutranksLoaded(t *testing.T) {
	folded := runtimeHeadline(result(true,
		verdictRow("deb|a|1", runtimeLoaded, "observed_loaded"),
		verdictRow("deb|b|1", runtimeExecuting, "observed_executing"),
	))
	assert.Equal(t, runtimeExecuting, folded["status"])
}

func TestAnAllUnknownFoldKeepsARealReason(t *testing.T) {
	folded := runtimeHeadline(result(true, verdictRow("deb|openssl|3.0.2", runtimeUnknown, "unversioned")))
	assert.Equal(t, runtimeUnknown, folded["status"])
	assert.Equal(t, "unversioned", folded["reason"])
}

func TestTheClientFoldInventsNoProducerForAVerdictNoProducerEmitted(t *testing.T) {
	// runtimeevidence.Unknown() stamps Source because THERE it is the producer. Doing
	// the same here would fabricate provenance for a reduction performed in this server.
	assert.NotContains(t, runtimeHeadline(result(true)), "source")
}

func TestTheFoldToleratesMalformedRowsWithoutReadingThemAsAVerdict(t *testing.T) {
	folded := runtimeHeadline(map[string]interface{}{
		"packages": []interface{}{
			map[string]interface{}{"key": "deb|openssl|3.0.2"},
			nil,
			map[string]interface{}{"key": "x", "verdict": "not a map"},
		},
		"sensors_complete": true,
	})
	assert.Equal(t, runtimeUnknown, folded["status"])
	assert.False(t, isRuntimeNegative(folded["status"].(string)))
}

// ---------------------------------------------------------------------------
// The headline flag
// ---------------------------------------------------------------------------

func TestHeadlineFlagIsReadStrictlySoAStringifiedFalseDoesNotOptIn(t *testing.T) {
	// truthy() reads any non-empty string as true, so headline:"false" from a model that
	// stringifies booleans would drop the per-package rows the caller asked to keep.
	assert.True(t, runtimeHeadlineRequested(map[string]interface{}{"headline": true}))
	assert.True(t, runtimeHeadlineRequested(map[string]interface{}{"headline": "true"}))
	assert.True(t, runtimeHeadlineRequested(map[string]interface{}{"headline": "YES"}))
	assert.True(t, runtimeHeadlineRequested(map[string]interface{}{"headline": float64(1)}))
	for _, v := range []interface{}{false, "false", "FALSE", "no", "", float64(0), nil, "maybe"} {
		assert.False(t, runtimeHeadlineRequested(map[string]interface{}{"headline": v}), v)
	}
	assert.False(t, runtimeHeadlineRequested(map[string]interface{}{}))
}

// ---------------------------------------------------------------------------
// The tool's own description — the surface a model actually reads
// ---------------------------------------------------------------------------

func TestRuntimeToolDescriptionRefusesToClaimSafety(t *testing.T) {
	reg, ok := tools.GetTool("cloudsec_check_finding_runtime")
	require.True(t, ok, "the runtime check must be registered")
	desc := reg.Description

	// It names every rung, so a model never has to guess at the vocabulary.
	for _, rung := range []string{"present", "not_observed", "loaded", "executing", "unknown"} {
		assert.Contains(t, desc, rung, rung)
	}
	// It states the negative's precondition and that it is not a safety claim.
	assert.Contains(t, desc, "COMPLETE telemetry window")
	assert.Contains(t, desc, "NOT A SAFETY CLAIM")
	assert.Contains(t, desc, "NEVER PRODUCES A NEGATIVE")
	// It says unknown has a reason, which is the whole point of the closed vocabulary.
	assert.Contains(t, desc, "reason")

	// It must not claim the check proves anything about exploitability. Checked as an
	// AFFIRMATION, because the sentence that makes the description honest is itself a
	// denial ("NOT that the vulnerability is not exploitable") — a flat substring ban
	// would forbid exactly the fix.
	lowered := strings.ToLower(desc)
	for _, claim := range []string{
		"is safe", "proves safe", "no risk", "safe to ignore", "not affected",
		"means the finding is fixed", "you may close", "confirms the finding is",
	} {
		assert.NotContains(t, lowered, claim, claim)
	}
	for _, word := range []string{"exploit", "fixed"} {
		clauses := 0
		for _, clause := range strings.Split(lowered, ".") {
			if !strings.Contains(clause, word) {
				continue
			}
			clauses++
			assert.True(t, negated(clause),
				"every clause mentioning %q must be a denial, got: %s", word, clause)
		}
		assert.NotZero(t, clauses, "the description must address %q at all", word)
	}

	// Read-only, and annotated as such — it computes on demand and stores nothing.
	require.NotNil(t, reg.Schema.Annotations.ReadOnlyHint)
	assert.True(t, *reg.Schema.Annotations.ReadOnlyHint)
	require.NotNil(t, reg.Schema.Annotations.DestructiveHint)
	assert.False(t, *reg.Schema.Annotations.DestructiveHint)
}
