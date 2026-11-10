package investigation

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

const (
	defaultTestWait = 60
	maxTestWait     = 180
	// pollWaitSeconds is how long one get_test_plan long-poll waits (the engine caps it at 10).
	pollWaitSeconds = 10
)

// now is the clock the polling loop uses; a test replaces it.
var now = time.Now

func handleTestPlan(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	testID, err := optString(args, "test_id")
	if err != nil {
		return fail(err)
	}
	includeSteps, err := optBool(args, "include_steps")
	if err != nil {
		return fail(err)
	}
	wait := defaultTestWait
	if w, given, err := optInt(args, "wait_seconds"); err != nil {
		return fail(err)
	} else if given {
		wait = w
	}
	if wait < 0 || wait > maxTestWait {
		return tools.ErrorResultf("wait_seconds must be between 0 and %d", maxTestWait), nil
	}
	deadline := now().Add(time.Duration(wait) * time.Second)

	var test map[string]interface{}
	if testID != "" {
		if err := pathID("test_id", testID); err != nil {
			return fail(err)
		}
		for _, other := range []string{"yaml", "template", "samples"} {
			if _, ok := args[other]; ok && args[other] != nil {
				return tools.ErrorResultf("test_id continues a test already started: do not also give %s", other), nil
			}
		}
		if test, err = fetchTest(ctx, testID, 0, 0); err != nil {
			return fail(err)
		}
	} else {
		body, err := testPlanBody(args)
		if err != nil {
			return fail(err)
		}
		if test, err = call(ctx, engineCall{method: http.MethodPost, suffix: "test-plan", body: body}); err != nil {
			return fail(err)
		}
	}

	// Poll until the test is terminal or this call's wait is spent. Results are accumulated by index: the
	// engine may answer with all of them or only the new ones.
	acc := newAccumulator()
	acc.add(test)
	for !acc.terminal() && now().Before(deadline) {
		poll := pollWaitSeconds
		if left := int(deadline.Sub(now()).Seconds()); left < poll {
			poll = left
		}
		if poll < 0 {
			poll = 0
		}
		next, err := fetchTest(ctx, acc.id(), acc.seen(), poll)
		if err != nil {
			return fail(err)
		}
		acc.add(next)
		if poll == 0 {
			break
		}
	}
	return tools.SuccessResult(acc.compact(includeSteps)), nil
}

// testPlanBody builds the engine's test_plan request from the tool's arguments.
func testPlanBody(args map[string]interface{}) (map[string]interface{}, error) {
	src, err := optString(args, "yaml")
	if err != nil {
		return nil, err
	}
	template, err := optString(args, "template")
	if err != nil {
		return nil, err
	}
	if (src == "") == (template == "") {
		return nil, fmt.Errorf("give exactly one of yaml (a draft in progress) or template (a stored template), or test_id to continue a test")
	}
	samples, err := optObjects(args, "samples")
	if err != nil {
		return nil, err
	}
	if len(samples) == 0 {
		return nil, fmt.Errorf("samples is required: objects with one of detection_id, case_id, {detect_cat, last} or {inputs, expected}")
	}
	mode, err := optString(args, "mode")
	if err != nil {
		return nil, err
	}
	if mode != "" && mode != "triage" && mode != "full" {
		return nil, fmt.Errorf("mode must be triage or full")
	}
	strict, err := optBool(args, "strict")
	if err != nil {
		return nil, err
	}
	overrides, err := optObject(args, "overrides")
	if err != nil {
		return nil, err
	}
	body := map[string]interface{}{"samples": samples, "wait_seconds": 5}
	if src != "" {
		body["inline"] = src
	} else {
		body["template"] = template
	}
	if mode != "" {
		body["mode"] = mode
	}
	if strict {
		body["strict"] = true
	}
	if overrides != nil {
		body["overrides"] = overrides
	}
	return body, nil
}

func fetchTest(ctx context.Context, id string, after, wait int) (map[string]interface{}, error) {
	q := url.Values{}
	q.Set("after", strconv.Itoa(after))
	q.Set("wait", strconv.Itoa(wait))
	return call(ctx, engineCall{method: http.MethodGet, suffix: "test-plan/" + url.PathEscape(id), query: q})
}

// accumulator folds the successive answers of one test into the latest view of it.
type accumulator struct {
	latest  map[string]interface{}
	results map[int]map[string]interface{}
}

func newAccumulator() *accumulator {
	return &accumulator{results: map[int]map[string]interface{}{}}
}

func (a *accumulator) add(test map[string]interface{}) {
	a.latest = test
	list, _ := test["results"].([]interface{})
	for _, r := range list {
		if row, ok := r.(map[string]interface{}); ok {
			if idx, ok := row["index"].(float64); ok {
				a.results[int(idx)] = row
			}
		}
	}
}

func (a *accumulator) id() string { return str(a.latest["test_id"]) }

// seen is the number of results already held: the `after` of the next poll.
func (a *accumulator) seen() int { return len(a.results) }

func (a *accumulator) terminal() bool {
	if d, ok := a.latest["done"].(bool); ok && d {
		return true
	}
	switch str(a.latest["state"]) {
	case "done", "failed", "invalid":
		return true
	}
	return false
}

// compact is the answer the agent reads: the engine's test object without the bulk, plus the indexes of the
// samples that need a look.
func (a *accumulator) compact(includeSteps bool) map[string]interface{} {
	t := a.latest
	out := pick(t, "test_id", "state", "error", "template", "samples_total", "samples_done", "summary")
	if sum, ok := out["summary"].(map[string]interface{}); ok {
		sum = pickAll(sum)
		if c, ok := sum["cost"].(map[string]interface{}); ok {
			sum["cost"] = compactCost(c)
		}
		out["summary"] = sum
	}
	out["done"] = a.terminal()
	if p, ok := t["policy"].(map[string]interface{}); ok {
		out["policy_clamped"] = p["clamped"]
	}
	if v, ok := t["validation"].(map[string]interface{}); ok {
		if str(t["state"]) == "invalid" {
			out["validation"] = v
		} else if w, ok := v["warnings"].([]interface{}); ok && len(w) > 0 {
			out["validation_warnings"] = w
		}
	}
	idxs := make([]int, 0, len(a.results))
	for i := range a.results {
		idxs = append(idxs, i)
	}
	sort.Ints(idxs)
	results := make([]interface{}, 0, len(idxs))
	var disagree, undecided, failed []int
	for _, i := range idxs {
		r := compactResult(a.results[i], includeSteps)
		results = append(results, r)
		switch {
		case r["state"] == "error":
			failed = append(failed, i)
		case r["agreement"] == "disagree":
			disagree = append(disagree, i)
		case r["agreement"] == "undecided" || verdictUndecided(r):
			undecided = append(undecided, i)
		}
	}
	out["results"] = results
	if len(disagree) > 0 {
		out["disagree"] = disagree
	}
	if len(undecided) > 0 {
		out["undecided"] = undecided
	}
	if len(failed) > 0 {
		out["failed_samples"] = failed
	}
	if !a.terminal() {
		out["next_step"] = "The test is still running. Call investigate_test_plan again with test_id " + a.id() + " to keep waiting."
	}
	return out
}

// verdictUndecided is a sample the plan could not settle: no verdict, or an inconclusive one.
func verdictUndecided(r map[string]interface{}) bool {
	v, ok := r["verdict"].(map[string]interface{})
	return ok && (v["decided"] == false || v["label"] == "inconclusive")
}

// compactCost keeps the cost figures an author weighs: the engine's usage object has some thirty scheduling
// counters that mean nothing to the author of a plan.
func compactCost(c map[string]interface{}) map[string]interface{} {
	return pick(c, "steps", "steps_by_class", "search_events", "llm_tokens", "llm_usd", "cost_basis", "wall_ms")
}

// pickAll is a shallow copy.
func pickAll(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// compactResult keeps what the author acts on. The steps that succeeded are dropped unless asked for: they
// are the bulk, and only the ones that did not succeed explain an unknown.
func compactResult(r map[string]interface{}, includeSteps bool) map[string]interface{} {
	out := pick(r, "index", "sample", "state", "error", "code", "verdict", "proof", "unknowns", "expected", "agreement", "wall_ms")
	if c, ok := r["cost"].(map[string]interface{}); ok {
		out["cost"] = compactCost(c)
	}
	if w, ok := r["would_propose"].([]interface{}); ok && len(w) > 0 {
		out["would_propose"] = w
	}
	steps, _ := r["steps"].([]interface{})
	if includeSteps {
		out["steps"] = steps
		return out
	}
	var problems []interface{}
	for _, s := range steps {
		if row, ok := s.(map[string]interface{}); ok && row["status"] != "ok" {
			problems = append(problems, pick(row, "fact", "op", "status", "reason"))
		}
	}
	if len(problems) > 0 {
		out["problem_steps"] = problems
	}
	return out
}
