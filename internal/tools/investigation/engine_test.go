package investigation

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testOID = "11111111-1111-4111-8111-111111111111"

var fakeAPI *testutil.FakeAPI

func TestMain(m *testing.M) {
	api, stop := testutil.InstallFakeAPI()
	fakeAPI = api
	code := m.Run()
	stop()
	os.Exit(code)
}

// gateway is a stateful stand-in for the LimaCharlie gateway: the investigate routes (answers are set per
// test) and the hive routes of the investigation_plan hive.
type gateway struct {
	mu sync.Mutex
	// engine answers by "METHOD route-suffix" (the part after /v1/investigate/{oid}/), status and body.
	engine map[string]func(r *http.Request, body []byte) (int, any)
	// hive records by key: the hive's {data, sys_mtd, usr_mtd}.
	records map[string]map[string]any
	// hive writes seen: key -> decoded request.
	writes []map[string]any
	// engineCalls records "METHOD suffix?query".
	engineCalls []string
	// onMtdRead runs when the hive's metadata of a record is read (the first step of SetRecord), before the
	// answer is computed: a test uses it to change the record between this tool's checks and its write.
	onMtdRead func()
}

func newGateway(t *testing.T) *gateway {
	g := &gateway{engine: map[string]func(*http.Request, []byte) (int, any){}, records: map[string]map[string]any{}}
	fakeAPI.Handle(t, g.serve)
	return g
}

func (g *gateway) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	g.mu.Lock()
	defer g.mu.Unlock()
	path := r.URL.EscapedPath()
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	if rest, ok := strings.CutPrefix(path, "/v1/investigate/"+testOID+"/"); ok {
		key := r.Method + " " + rest
		g.engineCalls = append(g.engineCalls, key+queryOf(r))
		h := g.engine[key]
		if h == nil {
			reply(404, map[string]string{"error": "no fake for " + key})
			return
		}
		status, v := h(r, body)
		reply(status, v)
		return
	}
	// Hive: /v1/hive/investigation_plan/<oid>/<key>/(data|mtd)
	parts := strings.Split(strings.TrimPrefix(path, "/v1/hive/"), "/")
	if len(parts) == 4 && parts[0] == planHive && parts[1] == testOID {
		key, kind := parts[2], parts[3]
		if kind == "mtd" && r.Method == http.MethodGet && g.onMtdRead != nil {
			g.onMtdRead()
		}
		rec, exists := g.records[key]
		switch {
		case r.Method == http.MethodGet && !exists:
			reply(404, map[string]string{"error": "RECORD_NOT_FOUND"})
		case r.Method == http.MethodGet:
			reply(200, rec)
		case r.Method == http.MethodPost && kind == "data":
			form, _ := url.ParseQuery(string(body))
			req := map[string]any{}
			for k, v := range form {
				req[k] = v[0]
			}
			if len(form) == 0 {
				_ = json.Unmarshal(body, &req)
			}
			if gz, ok := req["gzdata"].(string); ok {
				req["data"] = decodeGz(gz)
			}
			if raw, ok := req["usr_mtd"].(string); ok { // the SDK form-encodes it as JSON
				var m map[string]any
				_ = json.Unmarshal([]byte(raw), &m)
				req["usr_mtd"] = m
			}
			g.writes = append(g.writes, req)
			if want, ok := req["etag"].(string); ok && exists && rec["sys_mtd"].(map[string]any)["etag"] != want {
				reply(409, map[string]string{"error": "ETAG_MISMATCH"})
				return
			}
			next := map[string]any{"data": req["data"], "sys_mtd": map[string]any{"etag": "etag-" + key + "-2", "last_author": "agent-key"}, "usr_mtd": map[string]any{"enabled": true}}
			if um, ok := req["usr_mtd"]; ok {
				next["usr_mtd"] = um
			} else if exists {
				next["usr_mtd"] = rec["usr_mtd"]
			}
			g.records[key] = next
			reply(200, map[string]any{})
		default:
			reply(404, map[string]string{"error": "unexpected hive call " + r.Method + " " + path})
		}
		return
	}
	reply(404, map[string]string{"error": "unexpected call " + r.Method + " " + path})
}

func queryOf(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return ""
	}
	return "?" + r.URL.RawQuery
}

func decodeGz(s string) map[string]any {
	raw, _ := base64.StdEncoding.DecodeString(s)
	z, _ := gzip.NewReader(bytes.NewReader(raw))
	var out map[string]any
	_ = json.NewDecoder(z).Decode(&out)
	return out
}

func (g *gateway) on(route string, h func(r *http.Request, body []byte) (int, any)) {
	g.engine[route] = h
}

func (g *gateway) reply(route string, status int, v any) {
	g.on(route, func(*http.Request, []byte) (int, any) { return status, v })
}

func (g *gateway) hiveWrites() []map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]map[string]any(nil), g.writes...)
}

func (g *gateway) calls() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.engineCalls...)
}

func run(t *testing.T, name string, args map[string]interface{}) (*mcp.CallToolResult, map[string]interface{}) {
	t.Helper()
	ctx := fakeAPI.Context(t, auth.AuthModeNormal, testOID)
	reg, ok := tools.GetTool(name)
	require.True(t, ok, "tool %s is not registered", name)
	res, err := reg.Invoke(ctx, args)
	require.NoError(t, err)
	var body map[string]interface{}
	_ = json.Unmarshal([]byte(text(res)), &body)
	return res, body
}

func text(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

const validPlan = `description: Test plan
applies_to:
  detect_cat: ['x']
facts:
  host: {op: entity.resolve, args: {sensor_id: $sid}}
`

var allTools = []string{
	"investigate_operators", "investigate_authoring_kit", "investigate_validate_plan", "investigate_test_plan",
	"investigate_save_plan", "investigate_list_templates", "investigate_start", "investigate_get", "investigate_wave",
}

func TestToolsAreInTheEngineProfiles(t *testing.T) {
	full := map[string]bool{}
	for _, n := range tools.ProfileDefinitions[Profile] {
		full[n] = true
	}
	for _, n := range allTools {
		assert.True(t, full[n], "%s must be in profile %s", n, Profile)
		reg, ok := tools.GetTool(n)
		require.True(t, ok, n)
		assert.Equal(t, Profile, reg.Profile, n)
		assert.True(t, reg.RequiresOID, n)
	}
	// The read-only profile holds exactly the tools that change nothing.
	readOnly := map[string]bool{}
	for _, n := range tools.ProfileDefinitions[Profile+"_readonly"] {
		readOnly[n] = true
		a, ok := tools.AnnotationFor(n)
		require.True(t, ok, n)
		assert.True(t, a.ReadOnly, n)
	}
	for _, n := range []string{"investigate_save_plan", "investigate_test_plan", "investigate_start", "investigate_wave"} {
		assert.False(t, readOnly[n], "%s must not be in the read-only profile", n)
	}
}

func TestAuthoringToolsTeachTheLoop(t *testing.T) {
	for _, n := range []string{"investigate_authoring_kit", "investigate_validate_plan", "investigate_test_plan", "investigate_save_plan", "investigate_operators", "investigate_wave"} {
		reg, _ := tools.GetTool(n)
		for _, step := range []string{"investigate_authoring_kit", "investigate_validate_plan", "investigate_test_plan", "investigate_save_plan", "DRAFT"} {
			assert.Contains(t, reg.Description, step, "%s's description must teach the loop", n)
		}
	}
}

func TestKitPassesSectionsAndRefusesUnknownOnes(t *testing.T) {
	g := newGateway(t)
	g.reply("GET authoring-kit", 200, map[string]any{"kit_version": 1, "guide": "g"})

	res, body := run(t, "investigate_authoring_kit", map[string]interface{}{"sections": []interface{}{"schema", "guide"}})
	require.False(t, res.IsError, text(res))
	assert.EqualValues(t, 1, body["kit_version"])
	assert.Equal(t, []string{"GET authoring-kit?sections=schema%2Cguide"}, g.calls())

	_, _ = run(t, "investigate_authoring_kit", map[string]interface{}{"sections": "operators, codes"})
	assert.Equal(t, "GET authoring-kit?sections=operators%2Ccodes", g.calls()[1])

	before := len(g.calls())
	res, _ = run(t, "investigate_authoring_kit", map[string]interface{}{"sections": []interface{}{"schema", "nope"}})
	assert.True(t, res.IsError)
	assert.Contains(t, text(res), `unknown section "nope"`)
	assert.Len(t, g.calls(), before, "an unknown section is refused before any request")

	_, _ = run(t, "investigate_authoring_kit", nil)
	assert.Equal(t, "GET authoring-kit", g.calls()[before])
}

func TestOperatorsFilterAndBrief(t *testing.T) {
	g := newGateway(t)
	g.reply("GET operators", 200, map[string]any{"operators": []any{
		map[string]any{"name": "entity.resolve", "class": "index", "description": "Resolve an entity", "available": true, "args": []any{"x"}, "output": map[string]any{}},
		map[string]any{"name": "search.exists", "class": "scan", "description": "Does a search match", "available": false, "why": "denied by policy", "args": []any{"y"}},
	}})
	_, body := run(t, "investigate_operators", map[string]interface{}{"filter": "SEARCH", "brief": true})
	rows := body["operators"].([]any)
	require.Len(t, rows, 1)
	row := rows[0].(map[string]any)
	assert.Equal(t, "search.exists", row["name"])
	assert.Equal(t, "denied by policy", row["why"])
	assert.NotContains(t, row, "args", "brief keeps only the index fields")
	assert.EqualValues(t, 1, body["count"])

	_, body = run(t, "investigate_operators", map[string]interface{}{"names": []interface{}{"entity.resolve"}})
	rows = body["operators"].([]any)
	require.Len(t, rows, 1)
	assert.Contains(t, rows[0], "args", "names returns the full row")
	assert.Equal(t, "entity.resolve", rows[0].(map[string]any)["name"])
}

func TestValidatePlanSendsTheYAMLAndReturnsTheReport(t *testing.T) {
	g := newGateway(t)
	var got map[string]any
	g.on("POST plans/validate", func(_ *http.Request, b []byte) (int, any) {
		_ = json.Unmarshal(b, &got)
		return 200, map[string]any{"valid": false, "errors": []any{map[string]any{"code": "unknown_field", "path": "facts.host.args.sid", "suggestion": "sensor_id"}}}
	})
	res, body := run(t, "investigate_validate_plan", map[string]interface{}{"yaml": validPlan})
	require.False(t, res.IsError)
	assert.Equal(t, validPlan, got["yaml"])
	assert.Equal(t, false, body["valid"])

	res, _ = run(t, "investigate_validate_plan", map[string]interface{}{"yaml": "  "})
	assert.True(t, res.IsError)
}

func TestEngineErrorsReachTheCallerInTheEnginesWords(t *testing.T) {
	g := newGateway(t)
	g.reply("GET templates", 503, map[string]string{"error": "storage unavailable, retry"})
	res, _ := run(t, "investigate_list_templates", nil)
	require.True(t, res.IsError)
	assert.Contains(t, text(res), "HTTP 503: storage unavailable, retry")
}

func TestListTemplatesFilters(t *testing.T) {
	g := newGateway(t)
	g.reply("GET templates", 200, map[string]any{"templates": []any{
		map[string]any{"name": "managed-a", "managed": true, "status": "active"},
		map[string]any{"name": "mine-draft"},
		map[string]any{"name": "mine-active", "status": "active"},
	}})
	names := func(args map[string]interface{}) []string {
		_, body := run(t, "investigate_list_templates", args)
		var out []string
		for _, r := range body["templates"].([]any) {
			out = append(out, r.(map[string]any)["name"].(string))
		}
		return out
	}
	assert.Equal(t, []string{"managed-a", "mine-draft", "mine-active"}, names(nil))
	assert.Equal(t, []string{"mine-draft"}, names(map[string]interface{}{"status": "draft"}), "a template with no status is a draft")
	assert.Equal(t, []string{"mine-draft", "mine-active"}, names(map[string]interface{}{"include_managed": false}))
}

func testObject(state string, done bool, total int, results ...any) map[string]any {
	return map[string]any{"test_id": "test-1", "state": state, "done": done, "samples_total": total, "samples_done": len(results),
		"template": map[string]any{"name": "t", "status": "draft"}, "results": results,
		"policy": map[string]any{"clamped": []any{"dry_run.autonomy"}}}
}

func sampleResult(index int, agreement string, decided bool, steps ...any) map[string]any {
	return map[string]any{"index": index, "sample": map[string]any{"detection_id": "d"}, "state": "ok",
		"verdict": map[string]any{"label": "false_positive", "decided": decided}, "agreement": agreement,
		"cost": map[string]any{"steps": 3}, "wall_ms": 100, "steps": steps}
}

func TestTestPlanStartsPollsAndCompacts(t *testing.T) {
	g := newGateway(t)
	var started map[string]any
	g.on("POST test-plan", func(_ *http.Request, b []byte) (int, any) {
		_ = json.Unmarshal(b, &started)
		return 200, testObject("running", false, 3, sampleResult(0, "agree", true))
	})
	polls := 0
	g.on("GET test-plan/test-1", func(r *http.Request, _ []byte) (int, any) {
		polls++
		if polls == 1 {
			// only the new result, as `after` asks for
			assert.Equal(t, "1", r.URL.Query().Get("after"))
			assert.Equal(t, "10", r.URL.Query().Get("wait"))
			return 200, testObject("running", false, 3, sampleResult(1, "disagree", true,
				map[string]any{"fact": "a", "op": "x", "status": "ok"}))
		}
		final := testObject("done", true, 3, sampleResult(2, "undecided", false,
			map[string]any{"fact": "b", "op": "y", "status": "unknown", "reason": "index_lag", "ms": 5}))
		final["summary"] = map[string]any{"samples": 3, "agreement_rate": 0.5}
		return 200, final
	})

	res, body := run(t, "investigate_test_plan", map[string]interface{}{
		"yaml": validPlan, "samples": []interface{}{map[string]interface{}{"detect_cat": "c", "last": float64(3)}}, "mode": "triage", "wait_seconds": float64(60),
	})
	require.False(t, res.IsError, text(res))
	assert.Equal(t, validPlan, started["inline"])
	assert.NotContains(t, started, "template")
	assert.EqualValues(t, 5, started["wait_seconds"])
	assert.Equal(t, "triage", started["mode"])

	assert.Equal(t, "done", body["state"])
	assert.Equal(t, true, body["done"])
	assert.Len(t, body["results"], 3, "results from every poll are kept")
	assert.Equal(t, []any{float64(1)}, body["disagree"])
	assert.Equal(t, []any{float64(2)}, body["undecided"])
	assert.EqualValues(t, 0.5, body["summary"].(map[string]any)["agreement_rate"])
	assert.Equal(t, []any{"dry_run.autonomy"}, body["policy_clamped"])

	results := body["results"].([]any)
	assert.NotContains(t, results[1], "steps", "successful steps are dropped")
	assert.NotContains(t, results[1], "problem_steps")
	problems := results[2].(map[string]any)["problem_steps"].([]any)
	require.Len(t, problems, 1)
	assert.Equal(t, "index_lag", problems[0].(map[string]any)["reason"])
	assert.NotContains(t, problems[0], "ms")

	_, withSteps := run(t, "investigate_test_plan", map[string]interface{}{"template": "t", "samples": []interface{}{map[string]interface{}{"case_id": "1"}}, "include_steps": true, "wait_seconds": float64(0)})
	_ = withSteps
}

func TestTestPlanStillRunningTellsTheCallerHowToContinue(t *testing.T) {
	g := newGateway(t)
	g.reply("POST test-plan", 200, testObject("running", false, 2, sampleResult(0, "agree", true)))
	_, body := run(t, "investigate_test_plan", map[string]interface{}{
		"template": "t", "samples": []interface{}{map[string]interface{}{"case_id": "1"}}, "wait_seconds": float64(0),
	})
	assert.Equal(t, false, body["done"])
	assert.Contains(t, body["next_step"], "test_id test-1")
	assert.Len(t, g.calls(), 1, "wait_seconds 0 never polls")

	// Continue by id, with nothing else.
	g.reply("GET test-plan/test-1", 200, testObject("done", true, 2, sampleResult(0, "agree", true), sampleResult(1, "agree", true)))
	_, body = run(t, "investigate_test_plan", map[string]interface{}{"test_id": "test-1"})
	assert.Equal(t, true, body["done"])
	assert.Len(t, body["results"], 2)
	assert.NotContains(t, body, "next_step")
}

func TestTestPlanInvalidTemplateReturnsTheValidationReport(t *testing.T) {
	g := newGateway(t)
	obj := testObject("invalid", false, 0)
	obj["validation"] = map[string]any{"valid": false, "errors": []any{map[string]any{"code": "unknown_operator", "path": "facts.a.op"}}}
	g.reply("POST test-plan", 200, obj)
	_, body := run(t, "investigate_test_plan", map[string]interface{}{"yaml": "facts: {}", "samples": []interface{}{map[string]interface{}{"case_id": "1"}}})
	assert.Equal(t, "invalid", body["state"])
	assert.Equal(t, true, body["done"], "an invalid test is finished: there is nothing to wait for")
	assert.Contains(t, body, "validation")
	assert.Len(t, g.calls(), 1)
}

func TestTestPlanArgumentErrorsNeverReachTheEngine(t *testing.T) {
	g := newGateway(t)
	sample := []interface{}{map[string]interface{}{"case_id": "1"}}
	for name, args := range map[string]map[string]interface{}{
		"neither yaml nor template": {"samples": sample},
		"both yaml and template":    {"yaml": validPlan, "template": "t", "samples": sample},
		"no samples":                {"yaml": validPlan},
		"sample not an object":      {"yaml": validPlan, "samples": []interface{}{"d-1"}},
		"bad mode":                  {"yaml": validPlan, "samples": sample, "mode": "turbo"},
		"wait too long":             {"yaml": validPlan, "samples": sample, "wait_seconds": float64(999)},
		"fractional wait":           {"yaml": validPlan, "samples": sample, "wait_seconds": 1.5},
		"test_id with yaml":         {"test_id": "test-1", "yaml": validPlan},
		"test_id path escape":       {"test_id": "../x"},
	} {
		res, _ := run(t, "investigate_test_plan", args)
		assert.True(t, res.IsError, name)
	}
	assert.Empty(t, g.calls())
}

func TestStartAndGetMapTheirArguments(t *testing.T) {
	g := newGateway(t)
	var started map[string]any
	g.on("POST runs", func(_ *http.Request, b []byte) (int, any) {
		_ = json.Unmarshal(b, &started)
		return 201, map[string]any{"run": map[string]any{"run_id": "r1"}, "joined": false}
	})
	res, body := run(t, "investigate_start", map[string]interface{}{"template": "t", "detection_id": "d1", "inputs": map[string]interface{}{"a": "b"}, "wait_seconds": float64(5)})
	require.False(t, res.IsError, text(res))
	assert.Equal(t, "r1", body["run"].(map[string]any)["run_id"])
	assert.Equal(t, map[string]any{"detection_id": "d1"}, started["trigger"])
	assert.Equal(t, map[string]any{"template": "t"}, started["plan"])
	assert.EqualValues(t, 5, started["wait_seconds"])

	for name, args := range map[string]map[string]interface{}{
		"no trigger":        {"template": "t"},
		"no plan":           {"detection_id": "d"},
		"template and auto": {"template": "t", "auto": true, "detection_id": "d"},
	} {
		res, _ := run(t, "investigate_start", args)
		assert.True(t, res.IsError, name)
	}

	g.reply("GET runs/r1/events", 200, map[string]any{"events": []any{}, "next": 4, "done": true})
	_, body = run(t, "investigate_get", map[string]interface{}{"run_id": "r1", "view": "events", "after": float64(4), "wait": float64(3)})
	assert.Equal(t, true, body["done"])
	assert.Contains(t, g.calls(), "GET runs/r1/events?after=4&wait=3")

	res, _ = run(t, "investigate_get", map[string]interface{}{"run_id": "../x"})
	assert.True(t, res.IsError)
	res, _ = run(t, "investigate_get", map[string]interface{}{"run_id": "r1", "view": "graph"})
	assert.True(t, res.IsError)
}

func TestWaveSendsTheStepsOnly(t *testing.T) {
	g := newGateway(t)
	var got map[string]any
	g.on("POST waves", func(_ *http.Request, b []byte) (int, any) {
		_ = json.Unmarshal(b, &got)
		return 200, map[string]any{"results": []any{}}
	})
	res, _ := run(t, "investigate_wave", map[string]interface{}{"steps": []interface{}{map[string]interface{}{"id": "a", "op": "entity.resolve", "args": map[string]interface{}{"sensor_id": "s"}}}, "deadline_ms": float64(5000)})
	require.False(t, res.IsError, text(res))
	assert.EqualValues(t, 5000, got["deadline_ms"])
	assert.Len(t, got["steps"], 1)

	res, _ = run(t, "investigate_wave", map[string]interface{}{"steps": []interface{}{}})
	assert.True(t, res.IsError)
}

// --- save ---

// savePlanGateway is a gateway where validate says valid and the org has one managed and one active template.
func savePlanGateway(t *testing.T) *gateway {
	g := newGateway(t)
	g.reply("POST plans/validate", 200, map[string]any{"valid": true, "errors": []any{}, "warnings": []any{map[string]any{"code": "unused_fact"}}})
	g.reply("GET templates", 200, map[string]any{"templates": []any{
		map[string]any{"name": "managed-one", "managed": true, "status": "active"},
		map[string]any{"name": "live-one", "status": "active"},
		map[string]any{"name": "old-draft", "status": "draft"},
	}})
	return g
}

func saveArgs(name string) map[string]interface{} {
	return map[string]interface{}{"name": name, "yaml": validPlan, "test_summary": "10 samples, agreement 0.9"}
}

func TestSavePlanWritesADraftAndReadsItBack(t *testing.T) {
	g := savePlanGateway(t)
	var validated map[string]any
	g.on("POST plans/validate", func(_ *http.Request, b []byte) (int, any) {
		_ = json.Unmarshal(b, &validated)
		return 200, map[string]any{"valid": true, "errors": []any{}, "warnings": []any{}}
	})

	res, body := run(t, "investigate_save_plan", saveArgs("my-plan"))
	require.False(t, res.IsError, text(res))
	assert.Equal(t, true, body["saved"])
	assert.Equal(t, "draft", body["status"])
	assert.Equal(t, "agent-key", body["last_author"])
	assert.Contains(t, body["next_step"], "promotes")

	writes := g.hiveWrites()
	require.Len(t, writes, 1)
	data := writes[0]["data"].(map[string]any)
	assert.Equal(t, "draft", data["status"], "the stored record is a draft")
	assert.Equal(t, "Test plan", data["description"])
	assert.Equal(t, createOnlyETag, writes[0]["etag"], "a new record is written on the condition that none exists")
	usr, _ := writes[0]["usr_mtd"].(map[string]any)
	assert.Equal(t, "10 samples, agreement 0.9", usr["comment"])
	assert.Equal(t, []any{"ai-draft"}, usr["tags"])

	// What the engine validated is what was stored, status included.
	assert.Contains(t, validated["yaml"], "status: draft")
}

func TestDraftRecordKeepsDatesAsWritten(t *testing.T) {
	data, normalized, err := draftRecord("description: d\nfacts:\n  a: {op: x, args: {since: 2026-01-01, n: 5, ok: true, ratio: 0.5, list: [a, 2]}}\n")
	require.NoError(t, err)
	args := data["facts"].(map[string]interface{})["a"].(map[string]interface{})["args"].(map[string]interface{})
	assert.Equal(t, "2026-01-01", args["since"], "an unquoted date stays the text the author wrote, not a time.Time")
	assert.EqualValues(t, 5, args["n"])
	assert.Equal(t, true, args["ok"])
	assert.Equal(t, 0.5, args["ratio"])
	assert.Equal(t, []interface{}{"a", 2}, args["list"])
	assert.Contains(t, normalized, "status: draft")
	_, err = json.Marshal(data)
	require.NoError(t, err, "the record must encode as JSON")
}

func TestSavePlanNeverWritesActive(t *testing.T) {
	g := savePlanGateway(t)
	for _, status := range []string{"active", "Active ", "enabled", "paused"} {
		args := saveArgs("my-plan")
		args["yaml"] = "status: " + status + "\n" + validPlan
		res, _ := run(t, "investigate_save_plan", args)
		assert.True(t, res.IsError, "status %q must be refused", status)
	}
	assert.Empty(t, g.hiveWrites())
	assert.Empty(t, g.calls(), "a template that claims a status is refused before any request")

	// `status: draft` is the same as no status.
	args := saveArgs("my-plan")
	args["yaml"] = "status: draft\n" + validPlan
	res, body := run(t, "investigate_save_plan", args)
	require.False(t, res.IsError, text(res))
	assert.Equal(t, "draft", body["status"])
}

func TestSavePlanRefusesManagedActiveAndExistingNames(t *testing.T) {
	g := savePlanGateway(t)
	g.records["hand-promoted"] = map[string]any{"data": map[string]any{"status": "active"}, "sys_mtd": map[string]any{"etag": "e1"}, "usr_mtd": map[string]any{"enabled": true}}
	g.records["my-draft"] = map[string]any{"data": map[string]any{"status": "draft"}, "sys_mtd": map[string]any{"etag": "e2"}, "usr_mtd": map[string]any{"enabled": true, "comment": "keep"}}

	for name, wantReason := range map[string]string{
		"managed-one":   "platform-managed",
		"live-one":      "active",
		"hand-promoted": "active",
		"my-draft":      "overwrite=true",
		"old-draft":     "", // listed by the engine as a draft, no hive record: allowed
	} {
		res, body := run(t, "investigate_save_plan", saveArgs(name))
		if wantReason == "" {
			assert.False(t, res.IsError, name+": "+text(res))
			continue
		}
		require.True(t, res.IsError, name)
		assert.Equal(t, false, body["saved"], name)
		assert.Contains(t, body["reason"], wantReason, name)
	}
	for _, w := range g.hiveWrites() {
		assert.Equal(t, "Test plan", w["data"].(map[string]any)["description"])
	}
	assert.Len(t, g.hiveWrites(), 1)
	assert.Equal(t, "active", g.records["hand-promoted"]["data"].(map[string]any)["status"], "an active record is untouched")
}

func TestSavePlanOverwritesADraftOnlyWithTheFlagAndItsEtag(t *testing.T) {
	g := savePlanGateway(t)
	g.records["my-draft"] = map[string]any{"data": map[string]any{"status": "draft", "description": "old"}, "sys_mtd": map[string]any{"etag": "e2"}, "usr_mtd": map[string]any{"enabled": true}}
	args := saveArgs("my-draft")
	args["overwrite"] = true
	res, _ := run(t, "investigate_save_plan", args)
	require.False(t, res.IsError, text(res))
	writes := g.hiveWrites()
	require.Len(t, writes, 1)
	assert.Equal(t, "e2", writes[0]["etag"], "the replace is conditional on the draft that was read")
	assert.Equal(t, "Test plan", g.records["my-draft"]["data"].(map[string]any)["description"])
}

func TestSavePlanLosesTheRaceWhenAPersonPromotedMeanwhile(t *testing.T) {
	g := savePlanGateway(t)
	g.records["my-draft"] = map[string]any{"data": map[string]any{"status": "draft"}, "sys_mtd": map[string]any{"etag": "e2"}, "usr_mtd": map[string]any{"enabled": true}}
	// A person promotes the draft between this tool's read and its write.
	g.on("POST plans/validate", func(*http.Request, []byte) (int, any) {
		g.records["my-draft"] = map[string]any{"data": map[string]any{"status": "active"}, "sys_mtd": map[string]any{"etag": "e3"}, "usr_mtd": map[string]any{"enabled": true}}
		return 200, map[string]any{"valid": true, "errors": []any{}}
	})
	// The tool reads the record after validating, so it sees e3 and refuses; had it read first, the etag
	// precondition would make the hive refuse the write.
	args := saveArgs("my-draft")
	args["overwrite"] = true
	res, body := run(t, "investigate_save_plan", args)
	require.True(t, res.IsError)
	assert.Equal(t, false, body["saved"])
	assert.Equal(t, "active", g.records["my-draft"]["data"].(map[string]any)["status"])
	assert.Empty(t, g.hiveWrites())
}

func TestSavePlanDoesNotSaveATemplateThatDoesNotValidate(t *testing.T) {
	g := savePlanGateway(t)
	g.reply("POST plans/validate", 200, map[string]any{"valid": false, "errors": []any{map[string]any{"code": "unknown_field"}}})
	res, body := run(t, "investigate_save_plan", saveArgs("my-plan"))
	require.True(t, res.IsError)
	assert.Equal(t, false, body["saved"])
	assert.Contains(t, body, "validation")
	assert.Empty(t, g.hiveWrites())
}

func TestSavePlanFailsClosedWhenItCannotCheck(t *testing.T) {
	g := savePlanGateway(t)
	g.reply("GET templates", 503, map[string]string{"error": "unavailable"})
	res, _ := run(t, "investigate_save_plan", saveArgs("my-plan"))
	assert.True(t, res.IsError)
	assert.Empty(t, g.hiveWrites(), "no write when the engine cannot say what exists")

	g = savePlanGateway(t)
	g.on("POST plans/validate", func(*http.Request, []byte) (int, any) { return 502, map[string]string{"error": "bridge down"} })
	res, _ = run(t, "investigate_save_plan", saveArgs("my-plan"))
	assert.True(t, res.IsError)
	assert.Empty(t, g.hiveWrites())
}

func TestSavePlanRejectsBadInput(t *testing.T) {
	g := savePlanGateway(t)
	long := strings.Repeat("x", maxTestSummaryRunes+1)
	for name, args := range map[string]map[string]interface{}{
		"uppercase name":   {"name": "My-Plan", "yaml": validPlan},
		"path in name":     {"name": "../x", "yaml": validPlan},
		"empty name":       {"name": "", "yaml": validPlan},
		"empty yaml":       {"name": "p", "yaml": " "},
		"not yaml":         {"name": "p", "yaml": "a: [b"},
		"yaml list":        {"name": "p", "yaml": "- a\n- b"},
		"name key in yaml": {"name": "p", "yaml": "name: other\n" + validPlan},
		"summary too long": {"name": "p", "yaml": validPlan, "test_summary": long},
		"overwrite string": {"name": "p", "yaml": validPlan, "overwrite": "yes"},
	} {
		res, _ := run(t, "investigate_save_plan", args)
		assert.True(t, res.IsError, name)
	}
	assert.Empty(t, g.hiveWrites())
	assert.Empty(t, g.calls())
}

func TestNowIsTheClockOfThePollingLoop(t *testing.T) {
	// The loop must stop at its deadline even when the test never finishes.
	g := newGateway(t)
	g.reply("POST test-plan", 200, testObject("running", false, 2))
	polls := 0
	g.on("GET test-plan/test-1", func(*http.Request, []byte) (int, any) {
		polls++
		return 200, testObject("running", false, 2)
	})
	clock := time.Now()
	orig := now
	t.Cleanup(func() { now = orig })
	now = func() time.Time { clock = clock.Add(7 * time.Second); return clock }
	_, body := run(t, "investigate_test_plan", map[string]interface{}{"template": "t", "samples": []interface{}{map[string]interface{}{"case_id": "1"}}, "wait_seconds": float64(20)})
	assert.Equal(t, false, body["done"])
	assert.NotZero(t, polls)
	assert.Less(t, polls, 10)
}

func TestSavePlanCreateDoesNotOverwriteARecordThatAppearedMeanwhile(t *testing.T) {
	g := savePlanGateway(t)
	// A person creates the active template between this tool's existence check and its write.
	g.onMtdRead = func() {
		g.records["raced"] = map[string]any{"data": map[string]any{"status": "active", "description": "mine"}, "sys_mtd": map[string]any{"etag": "e9"}, "usr_mtd": map[string]any{"enabled": true}}
	}
	res, _ := run(t, "investigate_save_plan", saveArgs("raced"))
	require.True(t, res.IsError, "the hive refuses the conditional create: %s", text(res))
	assert.Equal(t, "mine", g.records["raced"]["data"].(map[string]any)["description"], "the person's record is untouched")
	assert.Equal(t, "active", g.records["raced"]["data"].(map[string]any)["status"])
}

func TestSaveOverwriteReplacesOnlyDraftsAndKeepsAPersonsTags(t *testing.T) {
	g := savePlanGateway(t)
	g.records["odd"] = map[string]any{"data": map[string]any{"status": "Active"}, "sys_mtd": map[string]any{"etag": "e1"}, "usr_mtd": map[string]any{"enabled": true}}
	g.records["legacy"] = map[string]any{"data": map[string]any{"description": "no status"}, "sys_mtd": map[string]any{"etag": "e2"}, "usr_mtd": map[string]any{"enabled": true, "tags": []any{"reviewed", "ai-draft"}, "comment": "old"}}
	g.records["mine"] = map[string]any{"data": map[string]any{"status": "draft"}, "sys_mtd": map[string]any{"etag": "e3"}, "usr_mtd": map[string]any{"enabled": true, "tags": []any{"team-a"}}}

	args := saveArgs("odd")
	args["overwrite"] = true
	res, body := run(t, "investigate_save_plan", args)
	require.True(t, res.IsError)
	assert.Contains(t, body["reason"], `status "Active"`, "a status this tool does not know is not a draft")
	assert.Empty(t, g.hiveWrites())

	for name, want := range map[string][]any{"legacy": {"reviewed", "ai-draft"}, "mine": {"team-a", "ai-draft"}} {
		args := saveArgs(name)
		args["overwrite"] = true
		res, _ := run(t, "investigate_save_plan", args)
		require.False(t, res.IsError, name+": "+text(res))
		assert.Equal(t, want, g.records[name]["usr_mtd"].(map[string]any)["tags"], name)
	}
}

// A call that asks the engine to hold the answer is given that long, not the ordinary timeout: abandoning it
// would leave a run or a wave going on, unseen.
func TestHeldCallsOutliveTheOrdinaryTimeout(t *testing.T) {
	g := newGateway(t)
	slow := func(answer any) func(*http.Request, []byte) (int, any) {
		return func(*http.Request, []byte) (int, any) { time.Sleep(300 * time.Millisecond); return 200, answer }
	}
	g.on("POST runs", slow(map[string]any{"run": map[string]any{"run_id": "r1"}}))
	g.on("POST waves", slow(map[string]any{"results": []any{}}))
	g.on("GET templates", slow(map[string]any{"templates": []any{}}))

	origTimeout, origMargin := requestTimeout, waitMargin
	t.Cleanup(func() { requestTimeout, waitMargin = origTimeout, origMargin })
	requestTimeout, waitMargin = 100*time.Millisecond, 0

	res, _ := run(t, "investigate_start", map[string]interface{}{"template": "t", "detection_id": "d", "wait_seconds": float64(2)})
	assert.False(t, res.IsError, "wait_seconds 2 holds the call: %s", text(res))
	res, _ = run(t, "investigate_wave", map[string]interface{}{"steps": []interface{}{map[string]interface{}{"id": "a", "op": "x"}}, "deadline_ms": float64(2000)})
	assert.False(t, res.IsError, "deadline_ms 2000 holds the call: %s", text(res))
	res, _ = run(t, "investigate_list_templates", nil)
	assert.True(t, res.IsError, "an ordinary call still times out at requestTimeout")
}

func TestTestPlanCompactsCostsAndFlagsInconclusiveSamples(t *testing.T) {
	g := newGateway(t)
	r := sampleResult(0, "none", true)
	r["verdict"] = map[string]any{"label": "inconclusive", "decided": true}
	r["cost"] = map[string]any{"steps": 4, "llm_usd": 0.01, "usage_version": 2, "speculation_efficiency": 0.5, "span_ms": 9}
	obj := testObject("done", true, 1, r)
	obj["summary"] = map[string]any{"samples": 1, "cost": map[string]any{"steps": 4, "concurrency": 0.9, "work_ms": 3}}
	g.reply("POST test-plan", 200, obj)
	_, body := run(t, "investigate_test_plan", map[string]interface{}{"template": "t", "samples": []interface{}{map[string]interface{}{"case_id": "1"}}})
	assert.Equal(t, []any{float64(0)}, body["undecided"], "an inconclusive verdict is undecided even when the engine says decided")
	cost := body["results"].([]any)[0].(map[string]any)["cost"].(map[string]any)
	assert.EqualValues(t, 4, cost["steps"])
	assert.NotContains(t, cost, "speculation_efficiency")
	assert.NotContains(t, body["summary"].(map[string]any)["cost"], "concurrency")
}

func TestDraftRecordRefusesYAMLAliases(t *testing.T) {
	bomb := "a: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]\nd: [*c, *c, *c, *c, *c, *c, *c, *c, *c]\n"
	for name, src := range map[string]string{
		"self reference":    "a: &x [*x]\n",
		"expanding aliases": bomb,
		"plain alias":       "a: &x 1\nb: *x\n",
		"merge key":         "base: &base {op: x}\nfacts:\n  f:\n    <<: *base\n",
	} {
		done := make(chan error, 1)
		go func() { _, _, err := draftRecord(src); done <- err }()
		select {
		case err := <-done:
			require.Error(t, err, name)
			assert.Contains(t, err.Error(), "aliases", name)
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: draftRecord did not return", name)
		}
	}
}
