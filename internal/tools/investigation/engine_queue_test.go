package investigation

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var queueAnswer = map[string]any{
	"queued": 1240, "claimed": 2, "running": 25, "max_parallel_runs": 25, "oldest_wait_ms": 184000,
	"by_rule":     []any{map[string]any{"rule": "suspicious-powershell", "queued": 1200}},
	"by_template": []any{map[string]any{"template": "suspicious-process", "queued": 1200}},
}

func TestQueueReadsTheQueueAndSendsNothing(t *testing.T) {
	g := newGateway(t)
	var sent []byte
	g.on("GET queue", func(_ *http.Request, b []byte) (int, any) {
		sent = b
		return 200, queueAnswer
	})
	res, body := run(t, "investigate_queue", map[string]interface{}{"ignored": "x"})
	require.False(t, res.IsError, text(res))
	assert.EqualValues(t, 1240, body["queued"])
	assert.Len(t, body["by_rule"], 1, "the breakdowns reach the agent whole")
	assert.Equal(t, []string{"GET queue"}, g.calls())
	assert.Empty(t, sent)
}

func TestFlushQueueSendsExactlyOneScope(t *testing.T) {
	for name, tc := range map[string]struct {
		args map[string]interface{}
		want map[string]any
	}{
		"rule":     {map[string]interface{}{"rule": "suspicious-powershell"}, map[string]any{"rule": "suspicious-powershell"}},
		"template": {map[string]interface{}{"template": "suspicious-process", "note": "rule fixed"}, map[string]any{"template": "suspicious-process", "note": "rule fixed"}},
		"all":      {map[string]interface{}{"all": true, "note": "n"}, map[string]any{"all": true, "note": "n"}},
	} {
		t.Run(name, func(t *testing.T) {
			g := newGateway(t)
			var sent map[string]any
			g.on("POST queue/flush", func(_ *http.Request, b []byte) (int, any) {
				_ = json.Unmarshal(b, &sent)
				return 200, map[string]any{"flush_id": "f1", "flushed": 12, "done": true}
			})
			res, body := run(t, "investigate_flush_queue", tc.args)
			require.False(t, res.IsError, text(res))
			assert.Equal(t, tc.want, sent)
			assert.EqualValues(t, 12, body["flushed"])
			assert.Equal(t, []string{"POST queue/flush"}, g.calls(), "a flush is sent once")
		})
	}
}

// A flush discards queued work: anything but exactly one well formed scope is refused before any call, and for the
// right reason.
func TestFlushQueueRefusesAnythingButOneScopeBeforeAnyCall(t *testing.T) {
	g := newGateway(t)
	for name, tc := range map[string]struct {
		args   map[string]interface{}
		reason string
	}{
		"nothing":         {map[string]interface{}{}, "exactly one of"},
		"only a note":     {map[string]interface{}{"note": "x"}, "exactly one of"},
		"two scopes":      {map[string]interface{}{"rule": "r", "template": "t"}, "exactly one of"},
		"rule and all":    {map[string]interface{}{"rule": "r", "all": true}, "exactly one of"},
		"all false":       {map[string]interface{}{"all": false}, "all must be true"},
		"all false+rule":  {map[string]interface{}{"rule": "r", "all": false}, "all must be true"},
		"all as a string": {map[string]interface{}{"all": "true"}, "all must be a boolean"},
		"empty rule":      {map[string]interface{}{"rule": ""}, "rule must not be empty"},
		"blank template":  {map[string]interface{}{"template": "  "}, "template must not be empty"},
		"rule as number":  {map[string]interface{}{"rule": float64(1)}, "rule must be a string"},
		"note as number":  {map[string]interface{}{"rule": "r", "note": float64(5)}, "note must be a string"},
		"null scopes":     {map[string]interface{}{"rule": nil, "all": nil}, "exactly one of"},
	} {
		res, _ := run(t, "investigate_flush_queue", tc.args)
		require.True(t, res.IsError, name)
		assert.Contains(t, text(res), tc.reason, name)
	}
	assert.Empty(t, g.calls())
}

func TestQueueToolsSayPlainlyWhenTheEngineDoesNotServeTheQueueYet(t *testing.T) {
	for tool, route := range map[string]string{"investigate_queue": "GET queue", "investigate_flush_queue": "POST queue/flush"} {
		t.Run(tool, func(t *testing.T) {
			g := newGateway(t)
			g.reply(route, 501, map[string]any{
				"error":       "the investigation engine of this organization's region does not support the run queue yet",
				"error_code":  "not_implemented",
				"http_status": 501,
			})
			res, _ := run(t, tool, map[string]interface{}{"all": true})
			require.True(t, res.IsError)
			assert.Contains(t, text(res), queueNotAvailable)
			assert.Contains(t, text(res), `"error_code":"not_implemented"`)
			assert.Contains(t, text(res), `"http_status":501`)
		})
	}
}

func TestQueueRefusalsKeepTheEngineMessage(t *testing.T) {
	g := newGateway(t)
	g.reply("POST queue/flush", 403, map[string]any{"error": "forbidden", "error_code": "forbidden"})
	res, _ := run(t, "investigate_flush_queue", map[string]interface{}{"rule": "r"})
	require.True(t, res.IsError)
	assert.Contains(t, text(res), "HTTP 403: forbidden")
	assert.NotContains(t, text(res), queueNotAvailable)
}

// What the tools publish to a client decides its scope and its confirmation prompts.
func TestQueueToolsPublishTheirClass(t *testing.T) {
	queue, ok := tools.AnnotationFor("investigate_queue")
	require.True(t, ok)
	assert.True(t, queue.ReadOnly)
	flush, ok := tools.AnnotationFor("investigate_flush_queue")
	require.True(t, ok)
	assert.False(t, flush.ReadOnly)
	assert.True(t, flush.Destructive, "a flush cancels work and cannot be undone")
	assert.False(t, flush.Idempotent, "a later flush cancels more")
	reg, _ := tools.GetTool("investigate_flush_queue")
	assert.Contains(t, reg.Description, "CANNOT BE UNDONE")
	assert.Contains(t, reg.Description, "CANCEL")
	assert.Contains(t, reg.Description, "Running investigations are not touched")
	for _, p := range []string{"rule", "template", "all", "note"} {
		assert.Contains(t, reg.Schema.InputSchema.Properties, p)
	}
}

// A flush that got no answer may have been recorded by the engine: the agent is told to look before it flushes again.
func TestAFlushWithNoAnswerTellsTheAgentToCheckBeforeFlushingAgain(t *testing.T) {
	g := newGateway(t)
	g.on("POST queue/flush", func(*http.Request, []byte) (int, any) { panic(http.ErrAbortHandler) })
	res, _ := run(t, "investigate_flush_queue", map[string]interface{}{"all": true})
	require.True(t, res.IsError)
	assert.Contains(t, text(res), "may have been applied")
	assert.Contains(t, text(res), "investigate_queue")
	assert.Equal(t, []string{"POST queue/flush"}, g.calls(), "and the flush was not repeated")
}

func TestOnlyTheNotImplementedAnswerIsRewritten(t *testing.T) {
	g := newGateway(t)
	g.reply("GET queue", 501, map[string]any{"error": "queue disabled by the operator", "error_code": "feature_disabled"})
	res, _ := run(t, "investigate_queue", nil)
	require.True(t, res.IsError)
	assert.Contains(t, text(res), "HTTP 501: queue disabled by the operator")
	assert.NotContains(t, text(res), queueNotAvailable)
}
