package investigation

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sideOf is one side of an engine comparison, with the fields the compact form drops (usage, proof, unknowns).
func sideOf(outcome string) map[string]any {
	return map[string]any{
		"template": map[string]any{"name": "t", "version": 2}, "outcome": outcome, "verdict": "false_positive", "decided": true,
		"decided_by": map[string]any{"kind": "rule", "rule": "known_sender"}, "ai_may_decide": "off",
		"proof": map[string]any{"rule": "known_sender"}, "unknowns": []any{}, "skipped": []any{},
		"actions": []any{map[string]any{"class": "contain.email", "target": "m1"}},
		"usage":   map[string]any{"steps": 10},
	}
}

func comparisonOf(base, variant string) map[string]any {
	return map[string]any{
		"base": sideOf(base), "variant": sideOf(variant),
		"diff":         []any{map[string]any{"kind": "outcome", "path": "outcome", "base": base, "variant": variant}},
		"not_recorded": []any{map[string]any{"fact": "extra", "op": "x.y", "reason": "never_fetched"}},
		"clamped":      []any{},
	}
}

func TestCompareOneRunSendsTheEditAndCompactsTheAnswer(t *testing.T) {
	g := newGateway(t)
	var sent map[string]any
	g.on("POST runs/r1/compare", func(_ *http.Request, b []byte) (int, any) {
		sent = nil
		_ = json.Unmarshal(b, &sent)
		return 200, comparisonOf("closed_by_rule", "couldnt_tell")
	})
	res, body := run(t, "investigate_compare", map[string]interface{}{"run_id": "r1", "yaml": validPlan})
	require.False(t, res.IsError, text(res))
	assert.Equal(t, map[string]any{"inline": validPlan}, sent)
	base := body["base"].(map[string]any)
	assert.Equal(t, "closed_by_rule", base["outcome"])
	assert.NotContains(t, base, "usage", "the compact form drops usage")
	assert.NotContains(t, base, "proof")
	assert.Contains(t, base, "actions")
	assert.Equal(t, "off", base["ai_may_decide"], "a policy difference between the sides stays visible")
	assert.Len(t, body["diff"], 1)
	assert.Len(t, body["not_recorded"], 1, "what the replay could not reuse is kept")

	_, body = run(t, "investigate_compare", map[string]interface{}{"run_id": "r1", "template": "t-draft", "full": true})
	assert.Equal(t, map[string]any{"template": "t-draft"}, sent)
	assert.Contains(t, body["base"], "usage", "full keeps the raw comparison")
}

func TestCompareRunsBySelection(t *testing.T) {
	g := newGateway(t)
	var sent map[string]any
	g.on("POST compare", func(_ *http.Request, b []byte) (int, any) {
		sent = nil
		_ = json.Unmarshal(b, &sent)
		return 200, map[string]any{
			"results": []any{
				map[string]any{"run_id": "r1", "changed": true, "comparison": comparisonOf("closed_by_rule", "couldnt_tell")},
				map[string]any{"run_id": "r2", "changed": false, "error": map[string]any{"code": "conflict", "retryable": false}},
			},
			"summary":   map[string]any{"requested": 2, "compared": 1, "failed": 1, "changed": 1, "transitions": []any{}},
			"selection": map[string]any{"by": "run_ids"},
		}
	})
	res, body := run(t, "investigate_compare", map[string]interface{}{"template": "t2", "run_ids": []interface{}{"r1", "r2"}})
	require.False(t, res.IsError, text(res))
	assert.Equal(t, map[string]any{"template": "t2", "run_ids": []any{"r1", "r2"}}, sent)
	results := body["results"].([]any)
	first := results[0].(map[string]any)["comparison"].(map[string]any)
	assert.NotContains(t, first["base"], "usage")
	assert.Equal(t, "conflict", results[1].(map[string]any)["error"].(map[string]any)["code"], "a run that cannot be compared keeps its error")
	assert.EqualValues(t, 1, body["summary"].(map[string]any)["failed"])

	_, _ = run(t, "investigate_compare", map[string]interface{}{"yaml": validPlan, "last_template": "phish", "limit": float64(30)})
	assert.Equal(t, map[string]any{"inline": validPlan, "last": map[string]any{"template": "phish", "limit": float64(30)}}, sent)
	_, _ = run(t, "investigate_compare", map[string]interface{}{"last_template": "phish"})
	assert.Equal(t, map[string]any{"last": map[string]any{"template": "phish", "limit": float64(20)}}, sent, "limit defaults to 20")
}

func TestCompareRefusesABadSelectionBeforeAnyRequest(t *testing.T) {
	g := newGateway(t)
	many := make([]interface{}, 51)
	for i := range many {
		many[i] = "r" + strings.Repeat("x", i+1)
	}
	for name, args := range map[string]map[string]interface{}{
		"no selection":      {"yaml": validPlan},
		"two selections":    {"run_id": "r1", "run_ids": []interface{}{"r2"}},
		"run and last":      {"run_id": "r1", "last_template": "t"},
		"yaml and template": {"yaml": validPlan, "template": "t", "run_id": "r1"},
		"51 runs":           {"run_ids": many},
		"repeated run":      {"run_ids": []interface{}{"r1", "r1"}},
		"limit too large":   {"last_template": "t", "limit": float64(51)},
		"limit zero":        {"last_template": "t", "limit": float64(0)},
		"blank last":        {"last_template": "  "},
		"blank run id":      {"run_id": " ", "yaml": validPlan},
		"blank yaml":        {"run_id": "r1", "yaml": "  \n"},
		"blank template":    {"run_id": "r1", "template": " "},
		"blank id in list":  {"run_ids": []interface{}{"r1", " "}},
		"limit with run":    {"run_id": "r1", "limit": float64(5)},
		"bad run id":        {"run_id": "../x"},
		"bad id in list":    {"run_ids": []interface{}{"a/b"}},
		"yaml not a string": {"run_id": "r1", "yaml": float64(3)},
	} {
		res, _ := run(t, "investigate_compare", args)
		assert.True(t, res.IsError, name)
	}
	assert.Empty(t, g.calls())
}

func TestCoverageSendsTheTriggerAndAsActive(t *testing.T) {
	g := newGateway(t)
	g.reply("GET templates/coverage", 200, map[string]any{"rule": "specificity", "rows": []any{map[string]any{"picked": "a", "tie": true}}, "ties": 1})
	res, body := run(t, "investigate_coverage", map[string]interface{}{
		"category": "phishing", "rule": "r-1", "severity": "high", "source": "dr-rule", "tags": []interface{}{"mail", "vip"}, "as_active": "new-draft",
	})
	require.False(t, res.IsError, text(res))
	assert.EqualValues(t, 1, body["ties"])
	require.Len(t, g.calls(), 1)
	call := g.calls()[0]
	path, query, _ := strings.Cut(call, "?")
	assert.Equal(t, "GET templates/coverage", path)
	for _, want := range []string{"category=phishing", "rule=r-1", "severity=high", "source=dr-rule", "tags=mail%2Cvip", "as_active=new-draft"} {
		assert.Contains(t, query, want)
	}

	_, _ = run(t, "investigate_coverage", nil)
	assert.Equal(t, "GET templates/coverage", g.calls()[1], "no argument asks for the example triggers")

	res, _ = run(t, "investigate_coverage", map[string]interface{}{"source": "email"})
	assert.True(t, res.IsError)
	assert.Len(t, g.calls(), 2)
}

func TestStatsPassesTheWindowAndRefusesABadTime(t *testing.T) {
	g := newGateway(t)
	g.reply("GET stats", 200, map[string]any{"by_template": []any{map[string]any{"template": "t", "runs": 3}}, "deciding_rules": []any{}, "missing_reasons": []any{}})
	res, body := run(t, "investigate_stats", map[string]interface{}{"template": "t", "since": "2026-11-01T00:00:00Z", "until": "2026-11-20T00:00:00Z"})
	require.False(t, res.IsError, text(res))
	assert.Len(t, body["by_template"], 1)
	assert.Equal(t, "GET stats?since=2026-11-01T00%3A00%3A00Z&template=t&until=2026-11-20T00%3A00%3A00Z", g.calls()[0])

	for _, bad := range []string{"yesterday", "2026-11-01"} {
		res, _ = run(t, "investigate_stats", map[string]interface{}{"since": bad})
		assert.True(t, res.IsError, bad)
	}
	assert.Len(t, g.calls(), 1)
}

func TestListRunsFiltersPagesAndCompacts(t *testing.T) {
	g := newGateway(t)
	g.reply("GET runs", 200, map[string]any{"next_cursor": "c2", "runs": []any{
		map[string]any{
			"run_id": "r1", "state": "completed", "template": "phish", "template_version": 3, "created": "2026-11-20T10:00:00Z",
			"verdict":    map[string]any{"outcome": "closed_by_rule", "label": "false_positive", "decided": true, "decided_by": map[string]any{"kind": "rule", "rule": "known_sender", "say": "long sentence"}, "missing": []any{"x"}},
			"request":    map[string]any{"trigger": map[string]any{"source": "dr-rule", "label": "Invoice from acme", "detection_id": "d1", "severity": "high", "tags": []any{"x"}, "category": "phish", "priority": 7}, "inputs": map[string]any{"big": "value"}},
			"actions":    []any{map[string]any{"class": "contain.email"}, map[string]any{"class": "tag"}},
			"usage":      map[string]any{"time_to_verdict_ms": 1200, "steps": 9},
			"sensors":    []any{"s1"},
			"policy":     map[string]any{"applied": "lots"},
			"case_id":    "c1",
			"case_final": true, "opinion_hidden": true,
			"coalesced": 2,
		},
	}})
	res, body := run(t, "investigate_list_runs", map[string]interface{}{
		"template": "phish", "state": "completed", "outcome": "couldnt_tell", "sensor": "s1", "detection_id": "d1", "case_id": "c1",
		"message_id": "m1", "origin_run": "r0", "needs_person": false, "kind": "template", "since": "2026-11-01T00:00:00Z",
		"until": "2026-11-25T00:00:00Z", "sort": "-time_to_verdict", "limit": float64(10), "cursor": "c1",
	})
	require.False(t, res.IsError, text(res))
	assert.Equal(t, "c2", body["next_cursor"])
	_, rawQuery, _ := strings.Cut(g.calls()[0], "?")
	query, err := url.ParseQuery(rawQuery)
	require.NoError(t, err)
	assert.Equal(t, url.Values{
		"template": {"phish"}, "state": {"completed"}, "outcome": {"couldnt_tell"}, "sid": {"s1"}, "detection_id": {"d1"}, "case_id": {"c1"},
		"message_id": {"m1"}, "origin_run": {"r0"}, "needs_person": {"false"}, "kind": {"template"}, "since": {"2026-11-01T00:00:00Z"},
		"until": {"2026-11-25T00:00:00Z"}, "sort": {"-time_to_verdict"}, "limit": {"10"}, "cursor": {"c1"},
	}, query)
	row := body["runs"].([]any)[0].(map[string]any)
	assert.Equal(t, "r1", row["run_id"])
	assert.EqualValues(t, 2, row["actions"], "actions are counted, not listed")
	assert.EqualValues(t, 1200, row["time_to_verdict_ms"])
	assert.Equal(t, "Invoice from acme", row["trigger"].(map[string]any)["label"])
	assert.Equal(t, "high", row["trigger"].(map[string]any)["severity"], "a trigger keeps what coverage needs to reproduce it")
	assert.Equal(t, []any{"x"}, row["trigger"].(map[string]any)["tags"])
	assert.NotContains(t, row["trigger"], "priority")
	assert.Equal(t, true, row["case_final"])
	assert.Equal(t, true, row["opinion_hidden"], "a blind run is not shown as one with no verdict")
	assert.Equal(t, map[string]any{"kind": "rule", "rule": "known_sender"}, row["verdict"].(map[string]any)["decided_by"])
	assert.NotContains(t, row["verdict"], "missing")
	for _, dropped := range []string{"request", "usage", "policy", "coalesced"} {
		assert.NotContains(t, row, dropped)
	}

	_, body = run(t, "investigate_list_runs", map[string]interface{}{"full": true})
	assert.Contains(t, body["runs"].([]any)[0], "policy", "full returns the raw run")
	assert.Equal(t, "GET runs?limit=25", g.calls()[1], "the page defaults to 25")
}

func TestListRunsRefusesBadFiltersBeforeAnyRequest(t *testing.T) {
	g := newGateway(t)
	for name, args := range map[string]map[string]interface{}{
		"unknown outcome":  {"outcome": "benign"},
		"bad sort":         {"sort": "oldest"},
		"bad kind":         {"kind": "run"},
		"bad since":        {"since": "last week"},
		"limit 0":          {"limit": float64(0)},
		"limit 201":        {"limit": float64(201)},
		"fractional limit": {"limit": 1.5},
		"needs_person str": {"needs_person": "yes"},
		"template not str": {"template": float64(1)},
	} {
		res, _ := run(t, "investigate_list_runs", args)
		assert.True(t, res.IsError, name)
	}
	assert.Empty(t, g.calls())
	g.reply("GET runs", 200, map[string]any{"runs": []any{}})
	res, _ := run(t, "investigate_list_runs", map[string]interface{}{"outcome": "undecided", "needs_person": true})
	assert.False(t, res.IsError)
	assert.Contains(t, g.calls()[0], "needs_person=true")
}

func TestLabelsReadAndSubmit(t *testing.T) {
	g := newGateway(t)
	g.reply("GET runs/r1/labels", 200, map[string]any{"labels": []any{}, "outcomes": []any{map[string]any{"assessment": "threat"}}, "outcomes_truncated": false})
	_, body := run(t, "investigate_get_labels", map[string]interface{}{"run_id": "r1"})
	assert.Len(t, body["outcomes"], 1)
	_, _ = run(t, "investigate_get_labels", map[string]interface{}{"run_id": "r1", "all": true})
	assert.Equal(t, []string{"GET runs/r1/labels", "GET runs/r1/labels?all=true"}, g.calls())

	var sent map[string]any
	g.on("POST runs/r1/labels", func(_ *http.Request, b []byte) (int, any) {
		sent = nil
		_ = json.Unmarshal(b, &sent)
		return 200, map[string]any{"outcome": map[string]any{"assessment": "benign"}}
	})
	res, body := run(t, "investigate_submit_label", map[string]interface{}{"run_id": "r1", "assessment": "benign", "revision": float64(2)})
	require.False(t, res.IsError, text(res))
	assert.Equal(t, map[string]any{"assessment": "benign", "revision": float64(2)}, sent)
	assert.Equal(t, "benign", body["outcome"].(map[string]any)["assessment"])

	before := len(g.calls())
	for name, args := range map[string]map[string]interface{}{
		"unknown assessment": {"run_id": "r1", "assessment": "fine", "revision": float64(1)},
		"no revision":        {"run_id": "r1", "assessment": "benign"},
		"revision zero":      {"run_id": "r1", "assessment": "benign", "revision": float64(0)},
		"revision negative":  {"run_id": "r1", "assessment": "benign", "revision": float64(-1)},
		"revision fraction":  {"run_id": "r1", "assessment": "benign", "revision": 1.5},
		"bad run id":         {"run_id": "r1/x", "assessment": "benign", "revision": float64(1)},
	} {
		res, _ := run(t, "investigate_submit_label", args)
		assert.True(t, res.IsError, name)
	}
	assert.Len(t, g.calls(), before)
}

func TestCancelSendsOnlyWhatWasAsked(t *testing.T) {
	g := newGateway(t)
	var sent map[string]any
	g.on("POST runs/r1/cancel", func(_ *http.Request, b []byte) (int, any) {
		sent = nil
		_ = json.Unmarshal(b, &sent)
		if sent["revert_leases"] == true {
			return 200, map[string]any{"run_id": "r1", "state": "cancelled", "skipped_reverts": []any{map[string]any{"action_id": "a1", "class": "contain.network"}}}
		}
		return 200, map[string]any{"run_id": "r1", "state": "cancelled"}
	})
	res, body := run(t, "investigate_cancel", map[string]interface{}{"run_id": "r1"})
	require.False(t, res.IsError, text(res))
	assert.Empty(t, sent, "leases stay unless asked")
	assert.NotContains(t, body, "skipped_reverts")
	_, body = run(t, "investigate_cancel", map[string]interface{}{"run_id": "r1", "revert_leases": true})
	assert.Equal(t, map[string]any{"revert_leases": true}, sent)
	assert.Len(t, body["skipped_reverts"], 1, "what could not be reverted reaches the caller")

	for _, args := range []map[string]interface{}{{"run_id": "../x"}, {"run_id": "r1", "revert_leases": "yes"}, {}} {
		res, _ := run(t, "investigate_cancel", args)
		assert.True(t, res.IsError)
	}
	assert.Len(t, g.calls(), 2)
}

func TestCompareHoldsTheCallLongerThanAnOrdinaryRead(t *testing.T) {
	g := newGateway(t)
	slow := func(answer any) func(*http.Request, []byte) (int, any) {
		return func(*http.Request, []byte) (int, any) { time.Sleep(300 * time.Millisecond); return 200, answer }
	}
	g.on("POST runs/r1/compare", slow(comparisonOf("closed_by_rule", "closed_by_rule")))
	g.on("POST compare", slow(map[string]any{"results": []any{}, "summary": map[string]any{}}))
	g.on("GET stats", slow(map[string]any{}))

	origTimeout, origCompare := requestTimeout, compareTimeout
	t.Cleanup(func() { requestTimeout, compareTimeout = origTimeout, origCompare })
	requestTimeout, compareTimeout = 100*time.Millisecond, 3*time.Second

	res, _ := run(t, "investigate_compare", map[string]interface{}{"run_id": "r1"})
	assert.False(t, res.IsError, "one-run compare outlives the ordinary timeout: %s", text(res))
	res, _ = run(t, "investigate_compare", map[string]interface{}{"run_ids": []interface{}{"r1", "r2"}})
	assert.False(t, res.IsError, "batch compare outlives the ordinary timeout: %s", text(res))
	res, _ = run(t, "investigate_stats", nil)
	assert.True(t, res.IsError, "an ordinary read still times out at requestTimeout")
}

func TestLabelRevisionIsALosslessInt64(t *testing.T) {
	g := newGateway(t)
	var raw string
	g.on("POST runs/r1/labels", func(_ *http.Request, b []byte) (int, any) { raw = string(b); return 200, map[string]any{} })
	for revision, want := range map[interface{}]string{
		float64(7):            `"revision":7`,
		"9223372036854775807": `"revision":9223372036854775807`,
		" 12 ":                `"revision":12`,
	} {
		res, _ := run(t, "investigate_submit_label", map[string]interface{}{"run_id": "r1", "assessment": "threat", "revision": revision})
		require.False(t, res.IsError, text(res))
		assert.Contains(t, raw, want)
	}
	before := len(g.calls())
	for _, bad := range []interface{}{"0", "-3", "1.5", "abc", "9223372036854775808", float64(1 << 60), true} {
		res, _ := run(t, "investigate_submit_label", map[string]interface{}{"run_id": "r1", "assessment": "threat", "revision": bad})
		assert.True(t, res.IsError, "%v", bad)
	}
	assert.Len(t, g.calls(), before)
}

func TestListTemplatesAsksForStoredAndValidation(t *testing.T) {
	g := newGateway(t)
	g.reply("GET templates", 200, map[string]any{"templates": []any{
		map[string]any{"name": "ok", "status": "active", "loaded": true, "validation": map[string]any{"valid": true}},
		map[string]any{"name": "broken", "loaded": false, "load_error": "yaml"},
	}})
	_, body := run(t, "investigate_list_templates", map[string]interface{}{"stored": true, "validation": true})
	assert.Len(t, body["templates"], 2)
	assert.Equal(t, "GET templates?stored=true&validation=true", g.calls()[0])
	_, body = run(t, "investigate_list_templates", map[string]interface{}{"stored": true, "status": "draft"})
	assert.Equal(t, "GET templates?stored=true", g.calls()[1])
	assert.Len(t, body["templates"], 1, "the status filter still applies to stored records")
	res, _ := run(t, "investigate_list_templates", map[string]interface{}{"stored": "yes"})
	assert.True(t, res.IsError)
}

// An agent that reads any one of the tools of the live loop learns the whole loop, and the authoring tools point at it.
func TestToolsTeachTheTuningLoop(t *testing.T) {
	for _, n := range []string{"investigate_compare", "investigate_stats", "investigate_list_runs", "investigate_coverage", "investigate_get_labels"} {
		reg, ok := tools.GetTool(n)
		require.True(t, ok, n)
		for _, step := range []string{"investigate_stats", "investigate_list_runs", "investigate_compare", "investigate_test_plan", "investigate_save_plan"} {
			assert.Contains(t, reg.Description, step, "%s's description must teach the loop", n)
		}
	}
	for _, n := range []string{"investigate_authoring_kit", "investigate_validate_plan", "investigate_save_plan"} {
		reg, _ := tools.GetTool(n)
		for _, step := range []string{"investigate_stats", "investigate_compare", "investigate_coverage"} {
			assert.Contains(t, reg.Description, step, "%s must teach the live part of the loop", n)
		}
	}
	// There is no tool for the policy: a person sets it.
	for _, n := range allTools {
		for _, gone := range []string{"action mode", "approver", "pause"} {
			reg, _ := tools.GetTool(n)
			assert.NotContains(t, strings.ToLower(reg.Description), gone, "%s must not teach the policy layer", n)
		}
	}
}
