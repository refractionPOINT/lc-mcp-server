package cloudsec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testOID   = "b85fd2bd-ae21-4c1f-8a42-b90b51aeddeb"
	testRunID = "rem_cccccccccccccccccccccccccccccccc"
)

// fakeRemote is the gateway: it serves one run and records every decision that reaches it.
type fakeRemote struct {
	run       map[string]interface{}
	decisions []map[string]interface{}
	decideErr error
	getCalls  int
}

func (f *fakeRemote) oid() string { return testOID }

func (f *fakeRemote) getRun(ctx context.Context, runID string) (map[string]interface{}, error) {
	f.getCalls++
	b, _ := json.Marshal(map[string]interface{}{"result": map[string]interface{}{"run": f.run, "steps": []interface{}{}}})
	out := map[string]interface{}{}
	_ = json.Unmarshal(b, &out)
	return out, nil
}

func (f *fakeRemote) decide(ctx context.Context, runID, decision string, body map[string]interface{}) (map[string]interface{}, error) {
	if f.decideErr != nil {
		return nil, f.decideErr
	}
	f.decisions = append(f.decisions, map[string]interface{}{"run_id": runID, "decision": decision, "body": body})
	return map[string]interface{}{"result": map[string]interface{}{"state": "executing"}}, nil
}

func newRun(state string, generation int, digest string) *fakeRemote {
	return &fakeRemote{run: map[string]interface{}{
		"run_id": testRunID, "finding_id": "fnd_0123456789abcdef0123456789abcdef", "action": "open_fix_pr",
		"state": state, "generation": generation, "scope_digest": digest,
		"scope":       map[string]interface{}{"targets": []interface{}{map[string]interface{}{"kind": "image", "urn": "lcrn:img"}}},
		"deadline_at": "2026-09-30T00:00:00Z",
	}}
}

func resultJSON(t *testing.T, r *mcp.CallToolResult) (map[string]interface{}, bool) {
	t.Helper()
	require.NotEmpty(t, r.Content)
	text, ok := r.Content[0].(mcp.TextContent)
	require.True(t, ok)
	out := map[string]interface{}{}
	if json.Unmarshal([]byte(text.Text), &out) != nil {
		return map[string]interface{}{"error": text.Text}, r.IsError
	}
	return out, r.IsError
}

func review(t *testing.T, remote *fakeRemote, decision string) string {
	t.Helper()
	out, isErr := resultJSON(t, decideRemediation(context.Background(), remote, testRunID, decision, ""))
	require.False(t, isErr, out)
	assert.Equal(t, false, out["sent"])
	token, _ := out["confirmation"].(string)
	require.NotEmpty(t, token)
	return token
}

// TestReviewSendsNothing: the first call can never decide anything.
func TestReviewSendsNothing(t *testing.T) {
	remote := newRun("awaiting_approval", 3, strings.Repeat("d", 64))
	out, isErr := resultJSON(t, decideRemediation(context.Background(), remote, testRunID, "approve", ""))
	require.False(t, isErr)
	assert.Empty(t, remote.decisions)
	rev := out["review"].(map[string]interface{})
	assert.Equal(t, float64(3), rev["generation"])
	assert.NotNil(t, rev["targets"])
	assert.Contains(t, out["next"], "NOTHING WAS SENT")
}

func TestConfirmedDecisionSendsTheReviewedGenerationAndDigest(t *testing.T) {
	remote := newRun("awaiting_approval", 3, strings.Repeat("d", 64))
	token := review(t, remote, "approve")
	out, isErr := resultJSON(t, decideRemediation(context.Background(), remote, testRunID, "approve", token))
	require.False(t, isErr, out)
	require.Len(t, remote.decisions, 1)
	body := remote.decisions[0]["body"].(map[string]interface{})
	assert.Equal(t, int64(3), body["generation"])
	assert.Equal(t, strings.Repeat("d", 64), body["scope_digest"])
	assert.Equal(t, true, out["sent"])
}

// TestNoPathDecidesWithoutAValidConfirmation lists every way to reach the gateway without
// the reviewed token. Each must leave the fake gateway untouched.
func TestNoPathDecidesWithoutAValidConfirmation(t *testing.T) {
	digest := strings.Repeat("d", 64)
	cases := map[string]func() (*fakeRemote, string, string){
		"forged token": func() (*fakeRemote, string, string) {
			return newRun("awaiting_approval", 3, digest), "approve", "9999999999." + strings.Repeat("a", 64)
		},
		"self-computed sha256": func() (*fakeRemote, string, string) {
			sum := sha256.Sum256([]byte(testOID + "|" + testRunID + "|approve|3|" + digest))
			return newRun("awaiting_approval", 3, digest), "approve", "9999999999." + hex.EncodeToString(sum[:])
		},
		"malformed token": func() (*fakeRemote, string, string) {
			return newRun("awaiting_approval", 3, digest), "approve", "yes"
		},
		"generation changed": func() (*fakeRemote, string, string) {
			r := newRun("awaiting_approval", 3, digest)
			token := review(t, r, "approve")
			r.run["generation"] = 4
			return r, "approve", token
		},
		"targets changed": func() (*fakeRemote, string, string) {
			r := newRun("awaiting_approval", 3, digest)
			token := review(t, r, "approve")
			r.run["scope_digest"] = strings.Repeat("e", 64)
			return r, "approve", token
		},
		"token for another decision": func() (*fakeRemote, string, string) {
			r := newRun("awaiting_approval", 3, digest)
			return r, "approve", review(t, r, "reject")
		},
		"run no longer decidable": func() (*fakeRemote, string, string) {
			r := newRun("awaiting_approval", 3, digest)
			token := review(t, r, "approve")
			r.run["state"] = "monitoring"
			return r, "approve", token
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			remote, decision, token := mk()
			_, isErr := resultJSON(t, decideRemediation(context.Background(), remote, testRunID, decision, token))
			assert.True(t, isErr)
			assert.Empty(t, remote.decisions, "the gateway must not have been called")
		})
	}
}

func TestExpiredConfirmationIsRefused(t *testing.T) {
	remote := newRun("awaiting_approval", 3, strings.Repeat("d", 64))
	token := review(t, remote, "cancel")
	defer func() { nowFunc = time.Now }()
	nowFunc = func() time.Time { return time.Now().Add(confirmationTTL + time.Minute) }
	_, isErr := resultJSON(t, decideRemediation(context.Background(), remote, testRunID, "cancel", token))
	assert.True(t, isErr)
	assert.Empty(t, remote.decisions)
}

func TestATokenFromAnotherKeyIsRefused(t *testing.T) {
	remote := newRun("awaiting_approval", 3, strings.Repeat("d", 64))
	token := review(t, remote, "approve")
	saved := confirmationKey
	defer func() { confirmationKey = saved }()
	confirmationKey = []byte("another replica without the shared key")
	_, isErr := resultJSON(t, decideRemediation(context.Background(), remote, testRunID, "approve", token))
	assert.True(t, isErr)
	assert.Empty(t, remote.decisions)
}

func TestInvalidInputsNeverReachTheGateway(t *testing.T) {
	for _, tc := range []struct{ runID, decision string }{
		{"../status", "approve"}, {"rem_x", "cancel"}, {testRunID, "merge"}, {testRunID, ""},
	} {
		remote := newRun("awaiting_approval", 3, strings.Repeat("d", 64))
		_, isErr := resultJSON(t, decideRemediation(context.Background(), remote, tc.runID, tc.decision, ""))
		assert.True(t, isErr, tc)
		assert.Zero(t, remote.getCalls, tc)
		assert.Empty(t, remote.decisions, tc)
	}
}

// TestMissingRespondPermissionIsSurfaced: the confirmation adds no authority. A caller
// without cloudsec.respond gets the gateway's refusal as an error.
func TestMissingRespondPermissionIsSurfaced(t *testing.T) {
	remote := newRun("awaiting_approval", 3, strings.Repeat("d", 64))
	token := review(t, remote, "approve")
	remote.decideErr = &apiError{Status: 403, Body: `{"error":"missing_permission","permission":"cloudsec.respond"}`}
	out, isErr := resultJSON(t, decideRemediation(context.Background(), remote, testRunID, "approve", token))
	assert.True(t, isErr)
	assert.Contains(t, out["error"], "cloudsec.respond")
	assert.True(t, errors.As(remote.decideErr, new(*apiError)))
}

// ---------------------------------------------------------------------------
// Evidence reads: byte-identical copies of the server's pinned wire bodies.
// ---------------------------------------------------------------------------

func loadFixture(t *testing.T, name string) ([]byte, map[string]interface{}) {
	t.Helper()
	raw, err := os.ReadFile("testdata/evidence-chain/" + name)
	require.NoError(t, err)
	out := map[string]interface{}{}
	require.NoError(t, json.Unmarshal(raw, &out))
	return raw, out
}

func TestCountFixtureIsTheServersAndCountsPassThrough(t *testing.T) {
	raw, fx := loadFixture(t, "counts.json")
	sum := sha256.Sum256(raw)
	assert.Equal(t, "35f587893d633f8aec4b959f736b58adaa5f2a4a05ae25fc0cfc7203582a7824", hex.EncodeToString(sum[:]))
	expected := fx["expected"].(map[string]interface{})

	cov := annotateCoverage(fx["code_coverage"].(map[string]interface{}))
	lines := cov["coverage"].(map[string]interface{})["lines"].([]interface{})
	want := expected["coverage"].([]interface{})
	require.Len(t, lines, len(want))
	for i, raw := range lines {
		l, w := raw.(map[string]interface{}), want[i].(map[string]interface{})
		assert.Equal(t, w["metric"], l["metric"])
		assert.Equal(t, w["numerator"], l["numerator"])
		assert.Equal(t, w["denominator"], l["denominator"])
		if l["numerator"] == nil {
			assert.Equal(t, false, l["percent_shown"], l["metric"])
			assert.NotContains(t, l, "percent")
		}
	}
	chain := normalizeChain(fx["evidence_chain"].(map[string]interface{}))
	assert.Equal(t, expected["chain_gaps"], chain["chain"].(map[string]interface{})["gaps"])
}

func TestCoveragePercentOnlyOnCleanLines(t *testing.T) {
	_, body := loadFixture(t, "mssp-2.json")
	lines := annotateCoverage(body)["coverage"].(map[string]interface{})["lines"].([]interface{})
	first := lines[0].(map[string]interface{})
	assert.Equal(t, "coverage_incomplete", first["reason"])
	assert.Equal(t, false, first["percent_shown"])
	assert.NotContains(t, first, "percent")
	for _, l := range []map[string]interface{}{
		{"numerator": float64(5), "denominator": float64(5), "complete": false},
		{"numerator": float64(5), "denominator": float64(5), "complete": true, "truncated": true},
		{"numerator": float64(0), "denominator": float64(0), "complete": true},
		{"numerator": nil, "denominator": nil},
		{"numerator": float64(5), "denominator": float64(5), "complete": true, "reason": "coverage_stale"},
	} {
		_, shown := coveragePercent(l)
		assert.False(t, shown, l)
	}
}

func TestChainPassesReasonsVerbatimAndHidesAssertiveOutcomesOnGaps(t *testing.T) {
	_, body := loadFixture(t, "secops-7.json")
	var observed map[string]interface{}
	for _, s := range normalizeChain(body)["chain"].(map[string]interface{})["stages"].([]interface{}) {
		if st := s.(map[string]interface{}); st["stage"] == "observed" {
			observed = st
		}
	}
	assert.Equal(t, "sensor_quarantined", observed["reason"])
	assert.Equal(t, false, observed["reason_recognised"])
	assert.Equal(t, "review_reason", observed["action"])

	_, tampered := loadFixture(t, "appsec-8.json")
	for _, s := range tampered["chain"].(map[string]interface{})["stages"].([]interface{}) {
		if st := s.(map[string]interface{}); st["stage"] == "verified" {
			st["outcome"] = "verified"
		}
	}
	for _, s := range normalizeChain(tampered)["chain"].(map[string]interface{})["stages"].([]interface{}) {
		if st := s.(map[string]interface{}); st["stage"] == "verified" {
			assert.NotEqual(t, "verified", st["outcome"], "a partial verified stage must not say verified")
		}
	}
}
