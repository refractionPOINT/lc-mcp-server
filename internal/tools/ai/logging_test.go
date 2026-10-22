package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureDefaultLog routes the default slog logger, at INFO like prod, into a
// buffer for the rest of the test.
func captureDefaultLog(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// findLogLine returns the first JSON log line with the given message.
func findLogLine(t *testing.T, logs string, msg string) map[string]interface{} {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry["msg"] == msg {
			return entry
		}
	}
	t.Fatalf("no log line %q in:\n%s", msg, logs)
	return nil
}

// toolCallContext is a request context with an org and a request ID but no
// SDK cache, so a handler logs its call and then fails before reaching
// LimaCharlie or the AI provider.
func toolCallContext() context.Context {
	ctx := auth.WithAuthContext(context.Background(), &auth.AuthContext{
		Mode:   auth.AuthModeNormal,
		OID:    "test-oid",
		APIKey: "test-api-key",
	})
	return auth.WithRequestID(ctx, "req-123")
}

// The AI generators' INFO line must say which tool ran, for which org and
// request, and how long the request was, but never what the user asked.
func TestGeneratorToolCallLogsOmitTheRequest(t *testing.T) {
	// Never reach the AI provider, whatever the environment.
	t.Setenv("ANTHROPIC_KEY", "")

	generators := []string{
		"generate_lcql_query",
		"generate_dr_rule_detection",
		"generate_dr_rule_respond",
		"generate_sensor_selector",
		"generate_python_playbook",
	}
	for _, name := range generators {
		t.Run(name, func(t *testing.T) {
			logs := captureDefaultLog(t)
			request := "show me logins for secret-host-" + name

			tool, ok := tools.GetTool(name)
			require.True(t, ok)
			result, err := tool.Handler(toolCallContext(), map[string]interface{}{"query": request})
			require.NoError(t, err)
			require.True(t, result.IsError, "handler should fail without an SDK cache or prompt")

			out := logs.String()
			assert.NotContains(t, out, "secret-host-", "the user's request must not be logged")

			entry := findLogLine(t, out, "Tool called: "+name)
			assert.Equal(t, "INFO", entry["level"])
			assert.Equal(t, "test-oid", entry["oid"])
			assert.Equal(t, "req-123", entry["request_id"])
			assert.EqualValues(t, len(request), entry["query_len"])
			assert.NotContains(t, entry, "query")
		})
	}
}

// set_ai_memory and delete_ai_memory log the call without the agent key or
// the memory name the caller chose.
func TestMemoryToolCallLogsOmitKeyAndName(t *testing.T) {
	for _, name := range []string{"set_ai_memory", "delete_ai_memory"} {
		t.Run(name, func(t *testing.T) {
			logs := captureDefaultLog(t)
			key := "agent-secret-key"
			memoryName := "memory-secret-name"

			tool, ok := tools.GetTool(name)
			require.True(t, ok)
			result, err := tool.Handler(toolCallContext(), map[string]interface{}{
				"key":         key,
				"memory_name": memoryName,
				"content":     "memory-secret-content",
			})
			require.NoError(t, err)
			require.True(t, result.IsError, "handler should fail without an SDK cache")

			out := logs.String()
			assert.NotContains(t, out, "-secret-", "memory keys, names and content must not be logged")

			entry := findLogLine(t, out, "Tool called: "+name)
			assert.Equal(t, "test-oid", entry["oid"])
			assert.Equal(t, "req-123", entry["request_id"])
			assert.EqualValues(t, len(key), entry["key_len"])
			assert.EqualValues(t, len(memoryName), entry["memory_name_len"])
		})
	}
}

// start_ai_session logs the call without the definition name the caller chose.
func TestStartAISessionLogOmitsDefinitionName(t *testing.T) {
	logs := captureDefaultLog(t)
	definitionName := "definition-secret-name"

	tool, ok := tools.GetTool("start_ai_session")
	require.True(t, ok)
	result, err := tool.Handler(toolCallContext(), map[string]interface{}{
		"definition_name": definitionName,
		"prompt":          "prompt-secret-text",
	})
	require.NoError(t, err)
	require.True(t, result.IsError, "handler should fail without an SDK cache")

	out := logs.String()
	assert.NotContains(t, out, "-secret-", "the definition name and prompt must not be logged")

	entry := findLogLine(t, out, "Tool called: start_ai_session")
	assert.Equal(t, "test-oid", entry["oid"])
	assert.Equal(t, "req-123", entry["request_id"])
	assert.EqualValues(t, len(definitionName), entry["definition_name_len"])
}
