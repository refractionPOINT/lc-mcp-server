package investigation

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const answerToken = "tok-0123456789abcdef-secret"

var testAnswer = map[string]interface{}{"verdict": "benign", "rationale": "the installer is signed"}

// runIn runs a tool as the stdio server does (a process that IS the session's, so its environment is the session's)
// or as the shared HTTP server does (it is not).
func runIn(t *testing.T, name string, args map[string]interface{}, insideSession bool) (*mcp.CallToolResult, map[string]interface{}) {
	t.Helper()
	ctx := fakeAPI.Context(t, auth.AuthModeNormal, testOID)
	if insideSession {
		ctx = auth.WithLocalFilesystemAccess(ctx)
	}
	reg, ok := tools.GetTool(name)
	require.True(t, ok, name)
	res, err := reg.Invoke(ctx, args)
	require.NoError(t, err)
	var body map[string]interface{}
	_ = json.Unmarshal([]byte(text(res)), &body)
	return res, body
}

func setSessionEnv(t *testing.T) {
	t.Setenv(envRunID, "run-1")
	t.Setenv(envRequestID, "rq0123456789abcdef0123456789abcdef")
	t.Setenv(envAnswerToken, answerToken)
}

type answerGateway struct {
	*gateway
	body map[string]any
}

func answering(t *testing.T, status int, reply any) *answerGateway {
	g := &answerGateway{gateway: newGateway(t)}
	g.on("POST runs/run-1/agent-answers/rq0123456789abcdef0123456789abcdef", func(_ *http.Request, b []byte) (int, any) {
		_ = json.Unmarshal(b, &g.body)
		return status, reply
	})
	return g
}

func TestAnswerSendsTheTokenAndTheAnswerOnceAndNeverEchoesTheToken(t *testing.T) {
	setSessionEnv(t)
	g := answering(t, 200, map[string]any{"run_id": "run-1", "request_id": "rq0123456789abcdef0123456789abcdef", "state": "answered"})
	res, body := runIn(t, "investigate_answer", map[string]interface{}{"answer": testAnswer}, true)
	require.False(t, res.IsError, text(res))
	assert.Equal(t, "answered", body["state"])
	assert.Equal(t, map[string]any{"token": answerToken, "answer": map[string]any{"verdict": "benign", "rationale": "the installer is signed"}}, g.body)
	assert.Len(t, g.calls(), 1, "an answer is sent once")
	assert.NotContains(t, g.calls()[0], answerToken, "the token is in the body only, never the URL")
	assert.NotContains(t, text(res), answerToken)
}

func TestAnswerDefaultsComeFromTheSessionEnvironmentOnlyInsideTheSession(t *testing.T) {
	setSessionEnv(t)
	g := answering(t, 200, map[string]any{"state": "answered"})
	// The shared HTTP server's environment is the operator's: it is never read for a caller.
	res, _ := runIn(t, "investigate_answer", map[string]interface{}{"answer": testAnswer}, false)
	assert.True(t, res.IsError)
	assert.Contains(t, text(res), "run_id is required")
	assert.Empty(t, g.calls())
	assert.NotContains(t, text(res), answerToken)
}

func TestAnswerArgumentsOverrideTheEnvironment(t *testing.T) {
	setSessionEnv(t)
	g := newGateway(t)
	var sent map[string]any
	g.on("POST runs/r2/agent-answers/rq2", func(_ *http.Request, b []byte) (int, any) {
		_ = json.Unmarshal(b, &sent)
		return 200, map[string]any{"state": "answered"}
	})
	res, _ := runIn(t, "investigate_answer", map[string]interface{}{"answer": testAnswer, "run_id": "r2", "request_id": "rq2", "token": "arg-token-0123456789"}, true)
	require.False(t, res.IsError, text(res))
	assert.Equal(t, "arg-token-0123456789", sent["token"])
	assert.NotContains(t, text(res), "arg-token-0123456789")
}

func TestAnswerNeedsEveryValueBeforeAnyCall(t *testing.T) {
	for _, missing := range []string{envRunID, envRequestID, envAnswerToken} {
		t.Run(missing, func(t *testing.T) {
			setSessionEnv(t)
			t.Setenv(missing, "")
			g := answering(t, 200, map[string]any{"state": "answered"})
			res, _ := runIn(t, "investigate_answer", map[string]interface{}{"answer": testAnswer}, true)
			assert.True(t, res.IsError)
			assert.Contains(t, text(res), missing)
			assert.NotContains(t, text(res), answerToken)
			assert.Empty(t, g.calls())
		})
	}
}

func TestAnswerRefusesBadInputBeforeAnyCall(t *testing.T) {
	setSessionEnv(t)
	g := answering(t, 200, map[string]any{"state": "answered"})
	for name, args := range map[string]map[string]interface{}{
		"no answer":         {},
		"answer a list":     {"answer": []interface{}{1}},
		"answer a string":   {"answer": "benign"},
		"run id with slash": {"answer": testAnswer, "run_id": "a/b"},
		"request id dots":   {"answer": testAnswer, "request_id": ".."},
		"token a number":    {"answer": testAnswer, "token": float64(5)},
	} {
		t.Run(name, func(t *testing.T) {
			res, _ := runIn(t, "investigate_answer", args, true)
			assert.True(t, res.IsError, text(res))
			assert.NotContains(t, text(res), answerToken)
		})
	}
	assert.Empty(t, g.calls())
}

func TestAnswerRefusalsSayWhatTheyMeanAndNeverShowTheToken(t *testing.T) {
	for _, tc := range []struct {
		status  int
		code    string
		meaning string
	}{
		{400, "invalid_answer", "Nothing was recorded"},
		{403, "forbidden", "token does not match"},
		{404, "not_found", "no such request"},
		{409, "already_answered", "never taken"},
		{409, "deadline_passed", "deadline passed"},
		{409, "not_waiting", "no longer waits"},
		{501, "not_implemented", "does not take AI agent answers yet"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			setSessionEnv(t)
			// A gateway that echoes the token in its message must still not get it into the result.
			reply := map[string]any{"error": "refused " + answerToken, "error_code": tc.code, "http_status": tc.status}
			if tc.code == "invalid_answer" {
				reply["fields"] = map[string]any{"verdict": "required"}
			}
			answering(t, tc.status, reply)
			res, _ := runIn(t, "investigate_answer", map[string]interface{}{"answer": testAnswer}, true)
			require.True(t, res.IsError)
			out := text(res)
			assert.Contains(t, out, tc.meaning)
			assert.Contains(t, out, `"error_code":"`+tc.code+`"`)
			if tc.code == "invalid_answer" {
				assert.Contains(t, out, `"fields":{"verdict":"required"}`, "an agent fixes the named fields")
			}
			assert.NotContains(t, out, answerToken)
		})
	}
}

func TestAnswerAPermissionRefusalWithNoEngineCodeNamesThePermission(t *testing.T) {
	setSessionEnv(t)
	answering(t, 403, map[string]any{"error": "forbidden"})
	res, _ := runIn(t, "investigate_answer", map[string]interface{}{"answer": testAnswer}, true)
	require.True(t, res.IsError)
	assert.Contains(t, text(res), "investigation.get")
}

func TestAnswerSuccessNeverCarriesTheTokenEvenIfTheGatewayEchoedIt(t *testing.T) {
	setSessionEnv(t)
	answering(t, 200, map[string]any{"state": "answered", "note": []any{"x " + answerToken}})
	res, _ := runIn(t, "investigate_answer", map[string]interface{}{"answer": testAnswer}, true)
	require.False(t, res.IsError)
	assert.NotContains(t, text(res), answerToken)
	assert.True(t, strings.Contains(text(res), redacted))
}

func TestAnswerIsAWriteAndOnlyInTheFullProfile(t *testing.T) {
	a, ok := tools.AnnotationFor("investigate_answer")
	require.True(t, ok)
	assert.False(t, a.ReadOnly)
	assert.False(t, readOnlyTools["investigate_answer"])
	reg, _ := tools.GetTool("investigate_answer")
	for _, word := range []string{"LC_IE_RUN_ID", "LC_IE_ANSWER_TOKEN", "invalid_answer", "already_answered", "never repeats it"} {
		assert.Contains(t, reg.Description, word)
	}
}

func TestStartNamesTheRunThatStartedTheSession(t *testing.T) {
	for name, tc := range map[string]struct {
		env, arg string
		inside   bool
		want     string
	}{
		"inside the session, from the environment": {env: "run-1", inside: true, want: "run-1"},
		"inside the session, the argument wins":    {env: "run-1", arg: "run-9", inside: true, want: "run-9"},
		"a server outside the session, argument":   {arg: "run-9", want: "run-9"},
		"a server outside never reads its own env": {env: "run-1", want: ""},
		"outside any session":                      {inside: true, want: ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(envRunID, tc.env)
			g := newGateway(t)
			var sent map[string]any
			g.on("POST runs", func(_ *http.Request, b []byte) (int, any) {
				_ = json.Unmarshal(b, &sent)
				return 200, map[string]any{"run": map[string]any{"run_id": "r2"}}
			})
			args := map[string]interface{}{"template": "t", "detection_id": "d1"}
			if tc.arg != "" {
				args["parent_run"] = tc.arg
			}
			res, _ := runIn(t, "investigate_start", args, tc.inside)
			require.False(t, res.IsError, text(res))
			if tc.want == "" {
				assert.NotContains(t, sent, "parent_run")
			} else {
				assert.Equal(t, tc.want, sent["parent_run"])
			}
		})
	}
}

func TestStartRefusesABadParentRun(t *testing.T) {
	g := newGateway(t)
	for _, bad := range []interface{}{"a/b", float64(3)} {
		res, _ := runIn(t, "investigate_start", map[string]interface{}{"template": "t", "detection_id": "d1", "parent_run": bad}, false)
		assert.True(t, res.IsError)
	}
	assert.Empty(t, g.calls())
}

// The engine's real queue answers (its RPC reference): nulls where a time or a cap would be, a person's start as a
// by_rule row with no rule, and a repeated flush answered by the first with replayed: true.
func TestQueueAndFlushPassTheEnginesRealAnswersThroughWhole(t *testing.T) {
	g := newGateway(t)
	queue := map[string]any{
		"queued": 1, "claimed": 0, "running": 0, "max_parallel_runs": 100, "oldest_enqueued_at": nil, "oldest_wait_ms": 0,
		"by_band":     map[string]any{"medium": 1},
		"by_rule":     []any{map[string]any{"queued": 1, "oldest_enqueued_at": "2026-11-26T19:03:00Z"}},
		"by_template": []any{map[string]any{"template": "t", "queued": 1, "oldest_enqueued_at": "2026-11-26T19:03:00Z"}},
		"hour":        map[string]any{"started": 0, "runs_per_hour": nil, "flushed": 0, "capped": 0, "start_failed": 0, "resets_at": "2026-11-26T20:00:00Z"},
		"flushes":     []any{}, "as_of": "2026-11-26T19:05:15Z",
	}
	g.on("GET queue", func(*http.Request, []byte) (int, any) { return 200, queue })
	res, body := run(t, "investigate_queue", nil)
	require.False(t, res.IsError, text(res))
	assert.Contains(t, body, "oldest_enqueued_at")
	assert.Nil(t, body["oldest_enqueued_at"])
	assert.Nil(t, body["hour"].(map[string]any)["runs_per_hour"])
	assert.NotContains(t, body["by_rule"].([]any)[0], "rule")

	flush := map[string]any{"flush_id": "f1", "scope": map[string]any{"rule": "r"}, "by": "user:u", "actor": "a@example.com", "note": "n",
		"at": "2026-11-26T19:00:00Z", "cutoff": "2026-11-26T19:00:00Z", "flushed": 12, "done": true, "done_at": "2026-11-26T19:00:03Z", "replayed": true}
	g.on("POST queue/flush", func(*http.Request, []byte) (int, any) { return 200, flush })
	res, body = run(t, "investigate_flush_queue", map[string]interface{}{"rule": "r", "note": "n"})
	require.False(t, res.IsError, text(res))
	assert.Equal(t, true, body["replayed"])
	assert.EqualValues(t, 12, body["flushed"])

	reg, _ := tools.GetTool("investigate_flush_queue")
	assert.Contains(t, reg.Description, "replayed: true")
	assert.Contains(t, reg.Description, "THIS call flushed nothing")
}

func TestAnswerRefusesATokenThatCannotBeTheEnginesAndAnAnswerThatHoldsIt(t *testing.T) {
	setSessionEnv(t)
	g := answering(t, 200, map[string]any{"state": "answered"})
	res, _ := runIn(t, "investigate_answer", map[string]interface{}{"answer": testAnswer, "token": "a"}, true)
	assert.True(t, res.IsError)
	assert.Contains(t, text(res), "too short")
	res, _ = runIn(t, "investigate_answer", map[string]interface{}{"answer": map[string]interface{}{"verdict": "benign", "rationale": "token is " + answerToken}}, true)
	assert.True(t, res.IsError)
	assert.Contains(t, text(res), "contains the answer token")
	assert.NotContains(t, text(res), answerToken)
	assert.Empty(t, g.calls(), "nothing is sent")
}

func TestAnswerScrubsATokenThatJSONEncodingWouldEscape(t *testing.T) {
	setSessionEnv(t)
	odd := `tok"<odd>&\0123456789`
	t.Setenv(envAnswerToken, odd)
	answering(t, 409, map[string]any{"error": "x", "error_code": "already_answered", "path": odd})
	res, _ := runIn(t, "investigate_answer", map[string]interface{}{"answer": testAnswer}, true)
	require.True(t, res.IsError)
	out := text(res)
	encoded, _ := json.Marshal(odd)
	assert.NotContains(t, out, odd)
	assert.NotContains(t, out, strings.Trim(string(encoded), `"`))
}

func TestAnswerAKeyWithoutAKeyIDIsNotToldItLacksThePermission(t *testing.T) {
	setSessionEnv(t)
	answering(t, 403, map[string]any{"error": "this API key has no key id, so it cannot own investigation runs"})
	res, _ := runIn(t, "investigate_answer", map[string]interface{}{"answer": testAnswer}, true)
	require.True(t, res.IsError)
	assert.Contains(t, text(res), "key id")
	assert.Contains(t, text(res), "see the message")
}
