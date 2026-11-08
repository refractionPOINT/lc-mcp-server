package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const outcomeTool = "zz_http_outcome"
const outcomePrivate = "private-prompt-answer-error-sentinel"

func registerOutcomeTool(t *testing.T, requiresOID bool, handler tools.ToolHandler) {
	t.Helper()
	tools.RegisterTool(&tools.ToolRegistration{
		Name: outcomeTool, Profile: "core", RequiresOID: requiresOID,
		Schema: mcp.NewTool(outcomeTool), Handler: handler,
	})
	t.Cleanup(func() { tools.UnregisterTool(outcomeTool) })
}

func captureOutcomeLogs(s *Server) *bytes.Buffer {
	b := new(bytes.Buffer)
	s.logger = slog.New(slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return b
}

func assertCompletion(t *testing.T, b *bytes.Buffer, tool, class string) {
	t.Helper()
	var completions []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		var entry map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &entry))
		if strings.HasPrefix(entry["msg"].(string), "Tool call completed") {
			completions = append(completions, entry)
		}
	}
	require.Len(t, completions, 1, "logs: %s", b.String())
	entry := completions[0]
	assert.Equal(t, "Tool call completed", entry["msg"])
	assert.Equal(t, tool, entry["tool"])
	assert.Equal(t, class, entry["error_class"])
	wantOutcome, wantLevel := "error", "WARN"
	if class == "none" {
		wantOutcome, wantLevel = "success", "INFO"
	}
	assert.Equal(t, wantOutcome, entry["outcome"])
	assert.Equal(t, wantLevel, entry["level"])
	assert.NotEmpty(t, entry["request_id"])
	assert.GreaterOrEqual(t, entry["total_duration_ms"].(float64), float64(0))
	// An allowlist prevents adding raw error/result/argument fields later.
	assert.ElementsMatch(t, []string{"time", "level", "msg", "request_id", "tool", "outcome", "error_class", "total_duration_ms"}, mapKeys(entry))
	completionJSON, err := json.Marshal(entry)
	require.NoError(t, err)
	assert.NotContains(t, string(completionJSON), outcomePrivate, "no arbitrary client content may enter completion logs")
}

// Exercise the real HTTP routing and tool invocation under both wire formats.
func TestHTTPToolOutcomeCompletion(t *testing.T) {
	for _, modern := range []bool{false, true} {
		era := "legacy"
		if modern {
			era = "modern"
		}
		for _, tc := range []struct {
			mode, class string
			isError     bool
		}{
			{"success", "none", false}, {"is_error", "tool_error", true},
			{"go_error", "handler_error", true},
		} {
			t.Run(era+"/"+tc.mode, func(t *testing.T) {
				s := newProtocolTestServer(t)
				logs := captureOutcomeLogs(s)
				runs := 0
				registerOutcomeTool(t, false, func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
					runs++
					require.Equal(t, outcomePrivate, args["prompt"])
					switch tc.mode {
					case "is_error":
						return tools.ErrorResult(outcomePrivate), nil
					case "go_error":
						return nil, errors.New(outcomePrivate)
					default:
						return tools.SuccessResult(outcomePrivate), nil
					}
				})
				params := map[string]any{"name": outcomeTool, "arguments": map[string]any{"prompt": outcomePrivate}}
				body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}
				headers := credHeaders()
				if modern {
					body, headers = modernRequest(1, "tools/call", params)
				}
				headers["X-MCP-Tools"] = outcomeTool
				resp := postJSON(t, s, "/mcp", body, headers)
				require.Equal(t, http.StatusOK, resp.Status)
				text, isError := toolText(t, resp)
				assert.Contains(t, text, outcomePrivate, "the caller still receives the tool content/error")
				assert.Equal(t, tc.isError, isError)
				assert.Equal(t, 1, runs)
				assertCompletion(t, logs, outcomeTool, tc.class)
				assert.NotContains(t, logs.String(), outcomePrivate, "no prompt, answer or raw error may enter handler logs")
			})
		}
	}
}

// Directly invoke the tools/call handler to also cover malformed params that
// protocol validation might reject before dispatch on some protocol revisions.
func TestHTTPToolOutcomeEarlyRejections(t *testing.T) {
	for _, tc := range []struct {
		name, class, params string
		setup               func(*testing.T, *Server, *http.Request)
	}{
		{name: "malformed params", class: "invalid_params", params: `{"name":`},
		{name: "missing name", class: "invalid_params", params: `{}`},
		{name: "invalid name", class: "invalid_params", params: `{"name":123}`},
		{name: "empty name", class: "invalid_params", params: `{"name":""}`},
		{name: "authentication", class: "authentication", setup: func(t *testing.T, s *Server, r *http.Request) { s.serverAuthCtx = nil }},
		{name: "unknown tool", class: "unknown_tool", params: `{"name":"zz_not_registered"}`},
		{name: "private unknown name", class: "unknown_tool", params: `{"name":"` + outcomePrivate + `"}`},
		{name: "private name before auth", class: "authentication", params: `{"name":"` + outcomePrivate + `"}`, setup: func(t *testing.T, s *Server, r *http.Request) { s.serverAuthCtx = nil }},
		{name: "invalid selection", class: "invalid_tool_selection", setup: func(t *testing.T, s *Server, r *http.Request) { r.Header.Set("X-MCP-Tools", "zz_not_registered") }},
		{name: "outside allowed set", class: "tool_not_allowed", setup: func(t *testing.T, s *Server, r *http.Request) { r.Header.Set("X-MCP-Tools", protoEchoTool) }},
		{name: "scope", class: "insufficient_scope", setup: func(t *testing.T, s *Server, r *http.Request) {
			s.serverAuthCtx.Scopes = auth.NewScopeGrant(auth.ScopeRead)
		}},
		{name: "oid switching", class: "invalid_oid", params: `{"name":"` + outcomeTool + `","arguments":{"oid":"aaaaaaaa-1111-2222-3333-444444444444"}}`},
		{name: "missing jwt oid", class: "invalid_oid", setup: func(t *testing.T, s *Server, r *http.Request) {
			fakeLCJWTs(t, map[string]*auth.LCClaims{"outcome.jwt.sig": {OIDs: []string{testOID}}})
			r.Header.Set("Authorization", "Bearer outcome.jwt.sig")
		}},
		{name: "permission", class: "permission_denied", setup: func(t *testing.T, s *Server, r *http.Request) {
			s.config.Features.EnforceAIAgentOperate = true
			s.permissionCache = auth.NewPermissionCache(time.Minute, s.logger)
			t.Cleanup(s.permissionCache.Close)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newProtocolTestServer(t)
			logs := captureOutcomeLogs(s)
			s.serverAuthCtx = &auth.AuthContext{Mode: auth.AuthModeNormal, OID: testOID, APIKey: testAPIKey}
			runs := 0
			registerOutcomeTool(t, true, func(context.Context, map[string]interface{}) (*mcp.CallToolResult, error) {
				runs++
				return tools.SuccessResult("unexpected"), nil
			})
			r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			r.Header.Set("X-MCP-Tools", outcomeTool)
			if tc.setup != nil {
				tc.setup(t, s, r)
			}
			params := tc.params
			if params == "" {
				params = `{"name":"` + outcomeTool + `","arguments":{"prompt":"` + outcomePrivate + `"}}`
			}
			w := httptest.NewRecorder()
			s.handleToolCall(w, r, &mcpCall{id: json.RawMessage(`1`), method: "tools/call", params: json.RawMessage(params)})
			assert.Zero(t, runs)
			var response map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			if tc.class == "invalid_oid" {
				assert.Equal(t, true, response["result"].(map[string]any)["isError"])
			} else {
				assert.NotNil(t, response["error"], "a rejection still reaches the caller")
			}
			wantTool := outcomeTool
			if tc.class == "invalid_params" || tc.class == "unknown_tool" || tc.class == "authentication" {
				wantTool = "unknown"
			}
			assertCompletion(t, logs, wantTool, tc.class)
		})
	}
}

func TestHTTPToolOutcomeInvokeScopeErrorAndPanic(t *testing.T) {
	for _, panics := range []bool{false, true} {
		name := "indirect scope error"
		if panics {
			name = "panic"
		}
		t.Run(name, func(t *testing.T) {
			s := newProtocolTestServer(t)
			logs := captureOutcomeLogs(s)
			s.serverAuthCtx = serverOrgCreds()
			registerOutcomeTool(t, false, func(context.Context, map[string]interface{}) (*mcp.CallToolResult, error) {
				if panics {
					panic(outcomePrivate)
				}
				return nil, &auth.InsufficientScopeError{Tool: outcomeTool, Required: auth.ScopeWrite, Granted: auth.ScopeRead}
			})
			r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			r.Header.Set("X-MCP-Tools", outcomeTool)
			w := httptest.NewRecorder()
			invoke := func() {
				s.handleToolCall(w, r, &mcpCall{id: json.RawMessage(`1`), method: "tools/call", params: json.RawMessage(`{"name":"` + outcomeTool + `"}`)})
			}
			if panics {
				assert.PanicsWithValue(t, outcomePrivate, invoke)
				assertCompletion(t, logs, outcomeTool, "panic")
			} else {
				invoke()
				assert.Equal(t, http.StatusForbidden, w.Code)
				assert.Contains(t, w.Header().Get("WWW-Authenticate"), "insufficient_scope")
				assertCompletion(t, logs, outcomeTool, "insufficient_scope")
			}
		})
	}
}
