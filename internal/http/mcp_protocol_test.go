package http

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/endpoints"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Wire-level tests for the dual-era MCP protocol handling: 2026-07-28 modern
// requests and the initialize-based legacy revisions, served side by side.

const (
	testOID    = "11111111-2222-3333-4444-555555555555"
	testAPIKey = "local-test-key-for-profile-check"

	protoEchoTool    = "zz_proto_echo"
	protoFailTool    = "zz_proto_fail"
	protoIsErrorTool = "zz_proto_iserror"
	protoMetaTool    = "zz_proto_meta"
)

// registerProtocolTestTools registers network-free tools the tests can call.
func registerProtocolTestTools(t *testing.T) {
	t.Helper()
	reg := func(name string, handler tools.ToolHandler, opts ...mcp.ToolOption) {
		tools.RegisterTool(&tools.ToolRegistration{
			Name:        name,
			Description: "protocol test tool " + name,
			Profile:     "core",
			Schema:      mcp.NewTool(name, append([]mcp.ToolOption{mcp.WithDescription("protocol test tool " + name)}, opts...)...),
			Handler:     handler,
		})
		t.Cleanup(func() { tools.UnregisterTool(name) })
	}
	reg(protoEchoTool, func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
		return tools.SuccessResult(map[string]any{"echo": args}), nil
	}, mcp.WithString("message"), mcp.WithReadOnlyHintAnnotation(true), mcp.WithTitleAnnotation("Echo"))
	reg(protoFailTool, func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
		return nil, errors.New("backend exploded: quota exhausted")
	})
	reg(protoIsErrorTool, func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
		return tools.ErrorResult("tool said no"), nil
	})
	reg(protoMetaTool, func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
		res := tools.SuccessResult(map[string]any{"ok": true})
		res.Meta = mcp.NewMetaFromMap(map[string]any{"com.example/trace": "abc"})
		return res, nil
	})
}

// newProtocolTestServer returns a server routing profiles by URL, with the
// test tools registered.
func newProtocolTestServer(t *testing.T) *Server {
	t.Helper()
	srv := createTestServer(t)
	t.Cleanup(srv.sdkCache.Close)
	srv.profile = ""
	registerProtocolTestTools(t)
	return srv
}

func credHeaders() map[string]string {
	return map[string]string{"X-LC-OID": testOID, "X-LC-API-KEY": testAPIKey}
}

func modernMeta() map[string]any {
	return map[string]any{
		mcp.MetaKeyProtocolVersion:    "2026-07-28",
		mcp.MetaKeyClientInfo:         map[string]any{"name": "proto-test", "version": "9.9.9"},
		mcp.MetaKeyClientCapabilities: map[string]any{},
	}
}

// modernRequest builds a well-formed 2026-07-28 request body and its headers.
func modernRequest(id any, method string, params map[string]any) (map[string]any, map[string]string) {
	if params == nil {
		params = map[string]any{}
	}
	if _, ok := params["_meta"]; !ok {
		params["_meta"] = modernMeta()
	}
	headers := map[string]string{
		"MCP-Protocol-Version": "2026-07-28",
		"Mcp-Method":           method,
	}
	if name, ok := params["name"].(string); ok {
		headers["Mcp-Name"] = name
	}
	for k, v := range credHeaders() {
		headers[k] = v
	}
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}, headers
}

type rpcResponse struct {
	Status int
	Header http.Header
	Raw    []byte
	Body   map[string]any
}

func (r rpcResponse) result(t *testing.T) map[string]any {
	t.Helper()
	require.Nil(t, r.Body["error"], "unexpected error: %s", r.Raw)
	res, ok := r.Body["result"].(map[string]any)
	require.True(t, ok, "missing result: %s", r.Raw)
	return res
}

func (r rpcResponse) errorCode(t *testing.T) int {
	t.Helper()
	e, ok := r.Body["error"].(map[string]any)
	require.True(t, ok, "missing error: %s", r.Raw)
	return int(e["code"].(float64))
}

func (r rpcResponse) errorObj(t *testing.T) map[string]any {
	t.Helper()
	e, ok := r.Body["error"].(map[string]any)
	require.True(t, ok, "missing error: %s", r.Raw)
	return e
}

func postRaw(t *testing.T, srv *Server, path string, body []byte, headers map[string]string) rpcResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	out := rpcResponse{Status: w.Code, Header: w.Header(), Raw: w.Body.Bytes()}
	if len(out.Raw) > 0 {
		require.NoError(t, json.Unmarshal(out.Raw, &out.Body), "response is not JSON: %s", out.Raw)
	}
	return out
}

func postJSON(t *testing.T, srv *Server, path string, body any, headers map[string]string) rpcResponse {
	t.Helper()
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	return postRaw(t, srv, path, encoded, headers)
}

// --- server/discover --------------------------------------------------------

func TestModernDiscover(t *testing.T) {
	srv := newProtocolTestServer(t)
	body, headers := modernRequest("discover-1", "server/discover", nil)
	resp := postJSON(t, srv, "/mcp", body, headers)

	require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Equal(t, "discover-1", resp.Body["id"], "string id must be echoed as sent")

	res := resp.result(t)
	assert.Equal(t, "complete", res["resultType"])
	assert.Equal(t, []any{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}, res["supportedVersions"])
	assert.Equal(t, map[string]any{"tools": map[string]any{}}, res["capabilities"])
	assert.Equal(t, float64(300000), res["ttlMs"])
	assert.Equal(t, "private", res["cacheScope"])
	meta := res["_meta"].(map[string]any)
	assert.Equal(t, map[string]any{"name": "LimaCharlie MCP Server", "version": "1.0.0"}, meta[mcp.MetaKeyServerInfo])
	assert.NotContains(t, res, "protocolVersion", "discover is not an initialize result")
	assert.NotContains(t, res, "serverInfo", "modern results identify the server in _meta")
}

func TestModernDiscoverRequiresCredentials(t *testing.T) {
	s, _ := createOAuthTestServer(t)
	body, headers := modernRequest(7, "server/discover", nil)
	delete(headers, "X-LC-OID")
	delete(headers, "X-LC-API-KEY")
	resp := postJSON(t, s, "/mcp", body, headers)

	require.Equal(t, http.StatusUnauthorized, resp.Status)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`)
	assert.Equal(t, float64(7), resp.Body["id"])
}

func TestDiscoverWithLegacyVersionInMeta(t *testing.T) {
	// A dual-era client may name a legacy version in _meta; discovery still
	// answers with the modern result shape.
	srv := newProtocolTestServer(t)
	body, headers := modernRequest(1, "server/discover", nil)
	meta := body["params"].(map[string]any)["_meta"].(map[string]any)
	meta[mcp.MetaKeyProtocolVersion] = "2025-11-25"
	headers["MCP-Protocol-Version"] = "2025-11-25"

	resp := postJSON(t, srv, "/mcp", body, headers)
	require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
	res := resp.result(t)
	assert.Equal(t, "complete", res["resultType"])
	assert.NotEmpty(t, res["supportedVersions"])
	assert.Contains(t, res["_meta"], mcp.MetaKeyServerInfo)
}

// --- modern request validation ---------------------------------------------

func TestModernRequestValidation(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		params     map[string]any
		mutate     func(body map[string]any, headers map[string]string)
		wantStatus int
		wantCode   int
		wantMsg    string
	}{
		{
			name:       "missing protocol version header",
			method:     "tools/list",
			mutate:     func(_ map[string]any, h map[string]string) { delete(h, "MCP-Protocol-Version") },
			wantStatus: http.StatusBadRequest, wantCode: -32020, wantMsg: "MCP-Protocol-Version",
		},
		{
			name:       "header version differs from _meta",
			method:     "tools/list",
			mutate:     func(_ map[string]any, h map[string]string) { h["MCP-Protocol-Version"] = "2025-11-25" },
			wantStatus: http.StatusBadRequest, wantCode: -32020, wantMsg: "does not match",
		},
		{
			name:       "missing Mcp-Method",
			method:     "tools/list",
			mutate:     func(_ map[string]any, h map[string]string) { delete(h, "Mcp-Method") },
			wantStatus: http.StatusBadRequest, wantCode: -32020, wantMsg: "Mcp-Method",
		},
		{
			name:       "Mcp-Method differs from body",
			method:     "tools/list",
			mutate:     func(_ map[string]any, h map[string]string) { h["Mcp-Method"] = "tools/call" },
			wantStatus: http.StatusBadRequest, wantCode: -32020, wantMsg: "Mcp-Method",
		},
		{
			name:       "tools/call missing Mcp-Name",
			method:     "tools/call",
			params:     map[string]any{"name": protoEchoTool, "arguments": map[string]any{}},
			mutate:     func(_ map[string]any, h map[string]string) { delete(h, "Mcp-Name") },
			wantStatus: http.StatusBadRequest, wantCode: -32020, wantMsg: "Mcp-Name",
		},
		{
			// The case gateways care about: routing on one tool while the
			// body calls another.
			name:       "Mcp-Name differs from body tool",
			method:     "tools/call",
			params:     map[string]any{"name": protoEchoTool, "arguments": map[string]any{}},
			mutate:     func(_ map[string]any, h map[string]string) { h["Mcp-Name"] = protoFailTool },
			wantStatus: http.StatusBadRequest, wantCode: -32020, wantMsg: "Mcp-Name",
		},
		{
			name:       "Mcp-Name with invalid base64 sentinel",
			method:     "tools/call",
			params:     map[string]any{"name": protoEchoTool, "arguments": map[string]any{}},
			mutate:     func(_ map[string]any, h map[string]string) { h["Mcp-Name"] = "=?base64?!!!notbase64?=" },
			wantStatus: http.StatusBadRequest, wantCode: -32020, wantMsg: "Mcp-Name",
		},
		{
			name:   "unsupported version",
			method: "tools/list",
			mutate: func(b map[string]any, h map[string]string) {
				b["params"].(map[string]any)["_meta"].(map[string]any)[mcp.MetaKeyProtocolVersion] = "2099-01-01"
				h["MCP-Protocol-Version"] = "2099-01-01"
			},
			wantStatus: http.StatusBadRequest, wantCode: -32022, wantMsg: "Unsupported protocol version",
		},
		{
			name:   "missing clientCapabilities",
			method: "tools/list",
			mutate: func(b map[string]any, _ map[string]string) {
				delete(b["params"].(map[string]any)["_meta"].(map[string]any), mcp.MetaKeyClientCapabilities)
			},
			wantStatus: http.StatusBadRequest, wantCode: -32602, wantMsg: "Invalid params",
		},
		{
			name:   "clientCapabilities not an object",
			method: "tools/list",
			mutate: func(b map[string]any, _ map[string]string) {
				b["params"].(map[string]any)["_meta"].(map[string]any)[mcp.MetaKeyClientCapabilities] = "all of them"
			},
			wantStatus: http.StatusBadRequest, wantCode: -32602, wantMsg: "Invalid params",
		},
		{
			name:   "protocolVersion not a string",
			method: "tools/list",
			mutate: func(b map[string]any, _ map[string]string) {
				b["params"].(map[string]any)["_meta"].(map[string]any)[mcp.MetaKeyProtocolVersion] = 20260728
			},
			wantStatus: http.StatusBadRequest, wantCode: -32602, wantMsg: "Invalid params",
		},
		{
			name:   "_meta not an object",
			method: "tools/list",
			mutate: func(b map[string]any, _ map[string]string) {
				b["params"].(map[string]any)["_meta"] = "2026-07-28"
			},
			wantStatus: http.StatusBadRequest, wantCode: -32602, wantMsg: "Invalid params",
		},
		{
			name:   "modern header but no _meta",
			method: "tools/list",
			mutate: func(b map[string]any, _ map[string]string) {
				delete(b["params"].(map[string]any), "_meta")
			},
			wantStatus: http.StatusBadRequest, wantCode: -32602, wantMsg: "Invalid params",
		},
		{
			name:   "server/discover without _meta",
			method: "server/discover",
			mutate: func(b map[string]any, h map[string]string) {
				delete(b["params"].(map[string]any), "_meta")
				delete(h, "MCP-Protocol-Version")
			},
			wantStatus: http.StatusBadRequest, wantCode: -32602, wantMsg: "Invalid params",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newProtocolTestServer(t)
			body, headers := modernRequest("req-1", tc.method, tc.params)
			if tc.mutate != nil {
				tc.mutate(body, headers)
			}
			resp := postJSON(t, srv, "/mcp", body, headers)
			require.Equal(t, tc.wantStatus, resp.Status, "%s", resp.Raw)
			assert.Equal(t, tc.wantCode, resp.errorCode(t))
			e := resp.errorObj(t)
			assert.Contains(t, e["message"].(string)+" "+jsonString(e["data"]), tc.wantMsg)
			assert.Equal(t, "req-1", resp.Body["id"], "errors on a readable request must carry its id")
		})
	}
}

func jsonString(v any) string {
	if v == nil {
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func TestModernUnsupportedVersionListsSupported(t *testing.T) {
	srv := newProtocolTestServer(t)
	body, headers := modernRequest(1, "tools/list", nil)
	body["params"].(map[string]any)["_meta"].(map[string]any)[mcp.MetaKeyProtocolVersion] = "1900-01-01"
	headers["MCP-Protocol-Version"] = "1900-01-01"

	resp := postJSON(t, srv, "/mcp", body, headers)
	require.Equal(t, http.StatusBadRequest, resp.Status)
	e := resp.errorObj(t)
	assert.Equal(t, float64(-32022), e["code"])
	assert.Equal(t, map[string]any{
		"supported": []any{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"},
		"requested": "1900-01-01",
	}, e["data"])
}

func TestModernBase64EncodedMcpNameAccepted(t *testing.T) {
	srv := newProtocolTestServer(t)
	body, headers := modernRequest(1, "tools/call", map[string]any{"name": protoEchoTool, "arguments": map[string]any{}})
	headers["Mcp-Name"] = "=?base64?" + base64.StdEncoding.EncodeToString([]byte(protoEchoTool)) + "?="
	headers["X-MCP-Tools"] = protoEchoTool

	resp := postJSON(t, srv, "/mcp", body, headers)
	require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
	assert.Equal(t, "complete", resp.result(t)["resultType"])
}

func TestModernHeaderNamesAreCaseInsensitive(t *testing.T) {
	srv := newProtocolTestServer(t)
	body, _ := modernRequest(1, "tools/list", nil)
	headers := map[string]string{
		"mcp-protocol-version": "2026-07-28",
		"MCP-METHOD":           "tools/list",
	}
	resp := postJSON(t, srv, "/mcp", body, headers)
	require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
}

func TestModernRemovedAndUnknownMethodsAre404(t *testing.T) {
	// 2026-07-28 removed ping, initialize and logging/setLevel; resources,
	// prompts and subscriptions are not offered by this server.
	for _, method := range []string{"ping", "initialize", "logging/setLevel", "resources/list", "prompts/list", "subscriptions/listen", "no/such_method"} {
		t.Run(method, func(t *testing.T) {
			srv := newProtocolTestServer(t)
			body, headers := modernRequest(3, method, nil)
			resp := postJSON(t, srv, "/mcp", body, headers)
			require.Equal(t, http.StatusNotFound, resp.Status, "%s", resp.Raw)
			assert.Equal(t, -32601, resp.errorCode(t))
			assert.Equal(t, float64(3), resp.Body["id"])
		})
	}
}

// --- modern tools ------------------------------------------------------------

func TestModernToolsList(t *testing.T) {
	srv := newProtocolTestServer(t)
	body, headers := modernRequest(1, "tools/list", nil)
	headers["X-MCP-Tools"] = protoEchoTool + "," + protoFailTool

	resp := postJSON(t, srv, "/mcp", body, headers)
	require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
	res := resp.result(t)
	assert.Equal(t, "complete", res["resultType"])
	assert.Equal(t, float64(300000), res["ttlMs"])
	assert.Equal(t, "private", res["cacheScope"])
	assert.Contains(t, res["_meta"], mcp.MetaKeyServerInfo)
	assert.NotContains(t, res, "nextCursor")

	listed := res["tools"].([]any)
	require.Len(t, listed, 2)
	assert.Equal(t, protoEchoTool, listed[0].(map[string]any)["name"])
	assert.Equal(t, protoFailTool, listed[1].(map[string]any)["name"])
}

func TestModernToolCallSuccess(t *testing.T) {
	srv := newProtocolTestServer(t)
	body, headers := modernRequest(int64(9007199254740993), "tools/call", map[string]any{
		"name": protoEchoTool, "arguments": map[string]any{"message": "hi"},
	})
	headers["X-MCP-Tools"] = protoEchoTool

	resp := postJSON(t, srv, "/mcp", body, headers)
	require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
	// Large integer ids survive the round trip byte for byte.
	assert.Contains(t, string(resp.Raw), `"id":9007199254740993`)

	res := resp.result(t)
	assert.Equal(t, "complete", res["resultType"])
	assert.Contains(t, res["_meta"], mcp.MetaKeyServerInfo)
	assert.NotContains(t, res, "isError")
	assert.NotContains(t, res, "ttlMs", "tool results are not cacheable")
	content := res["content"].([]any)[0].(map[string]any)
	assert.Equal(t, "text", content["type"])
	assert.JSONEq(t, `{"echo":{"message":"hi"}}`, content["text"].(string))
}

func TestModernToolCallPreservesToolMeta(t *testing.T) {
	srv := newProtocolTestServer(t)
	body, headers := modernRequest(1, "tools/call", map[string]any{"name": protoMetaTool})
	headers["X-MCP-Tools"] = protoMetaTool

	resp := postJSON(t, srv, "/mcp", body, headers)
	require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
	meta := resp.result(t)["_meta"].(map[string]any)
	assert.Equal(t, "abc", meta["com.example/trace"])
	assert.Contains(t, meta, mcp.MetaKeyServerInfo)
}

func TestModernToolCallWithoutCredentials(t *testing.T) {
	s, _ := createOAuthTestServer(t)
	body, headers := modernRequest("c-1", "tools/call", map[string]any{"name": "list_sensors", "arguments": map[string]any{}})
	delete(headers, "X-LC-OID")
	delete(headers, "X-LC-API-KEY")
	resp := postJSON(t, s, "/mcp", body, headers)
	require.Equal(t, http.StatusUnauthorized, resp.Status)
	assert.NotEmpty(t, resp.Header.Get("WWW-Authenticate"))
	assert.Equal(t, "c-1", resp.Body["id"])
}

// --- tools/call semantics (both eras) --------------------------------------

func TestToolCallErrorsInBothEras(t *testing.T) {
	type eraCase struct {
		name   string
		modern bool
	}
	eras := []eraCase{{"legacy", false}, {"modern", true}}

	build := func(era eraCase, params map[string]any, toolsHeader string) (map[string]any, map[string]string) {
		if era.modern {
			b, h := modernRequest(5, "tools/call", params)
			if toolsHeader != "" {
				h["X-MCP-Tools"] = toolsHeader
			}
			return b, h
		}
		h := credHeaders()
		if toolsHeader != "" {
			h["X-MCP-Tools"] = toolsHeader
		}
		return map[string]any{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params}, h
	}

	for _, era := range eras {
		t.Run(era.name, func(t *testing.T) {
			t.Run("go error becomes a tool execution error", func(t *testing.T) {
				srv := newProtocolTestServer(t)
				body, headers := build(era, map[string]any{"name": protoFailTool, "arguments": map[string]any{}}, protoFailTool)
				resp := postJSON(t, srv, "/mcp", body, headers)
				require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
				res := resp.result(t)
				assert.Equal(t, true, res["isError"])
				text := res["content"].([]any)[0].(map[string]any)["text"].(string)
				assert.Equal(t, "backend exploded: quota exhausted", text)
				if era.modern {
					assert.Equal(t, "complete", res["resultType"])
				} else {
					assert.NotContains(t, res, "resultType")
				}
			})

			t.Run("isError result passes through", func(t *testing.T) {
				srv := newProtocolTestServer(t)
				body, headers := build(era, map[string]any{"name": protoIsErrorTool}, protoIsErrorTool)
				resp := postJSON(t, srv, "/mcp", body, headers)
				require.Equal(t, http.StatusOK, resp.Status)
				res := resp.result(t)
				assert.Equal(t, true, res["isError"])
				assert.Equal(t, "tool said no", res["content"].([]any)[0].(map[string]any)["text"])
			})

			t.Run("unknown tool is invalid params", func(t *testing.T) {
				srv := newProtocolTestServer(t)
				body, headers := build(era, map[string]any{"name": "zz_no_such_tool"}, "")
				resp := postJSON(t, srv, "/mcp", body, headers)
				require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
				assert.Equal(t, -32602, resp.errorCode(t))
				assert.Equal(t, "Unknown tool: zz_no_such_tool", resp.errorObj(t)["message"])
				assert.Equal(t, float64(5), resp.Body["id"])
			})

			t.Run("tool outside the endpoint's set is unknown", func(t *testing.T) {
				srv := newProtocolTestServer(t)
				body, headers := build(era, map[string]any{"name": protoFailTool}, protoEchoTool)
				resp := postJSON(t, srv, "/mcp", body, headers)
				require.Equal(t, http.StatusOK, resp.Status)
				assert.Equal(t, -32602, resp.errorCode(t))
			})

			t.Run("arguments null is an empty object", func(t *testing.T) {
				srv := newProtocolTestServer(t)
				body, headers := build(era, map[string]any{"name": protoEchoTool, "arguments": nil}, protoEchoTool)
				resp := postJSON(t, srv, "/mcp", body, headers)
				require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
				text := resp.result(t)["content"].([]any)[0].(map[string]any)["text"].(string)
				assert.JSONEq(t, `{"echo":{}}`, text)
			})
		})
	}
}

func TestToolCallMalformedParams(t *testing.T) {
	cases := []struct {
		name   string
		params any
	}{
		{"missing name", map[string]any{"arguments": map[string]any{}}},
		{"empty name", map[string]any{"name": ""}},
		{"name not a string", map[string]any{"name": 42}},
		{"arguments not an object", map[string]any{"name": protoEchoTool, "arguments": []any{"a"}}},
		{"arguments a string", map[string]any{"name": protoEchoTool, "arguments": "{}"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newProtocolTestServer(t)
			resp := postJSON(t, srv, "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": tc.params}, credHeaders())
			require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
			assert.Equal(t, -32602, resp.errorCode(t))
		})
	}
}

// --- legacy era -------------------------------------------------------------

func TestLegacyInitializeNegotiation(t *testing.T) {
	cases := []struct {
		requested string
		want      string
	}{
		{"2025-11-25", "2025-11-25"},
		{"2025-06-18", "2025-06-18"},
		{"2025-03-26", "2025-03-26"},
		{"2024-11-05", "2024-11-05"},
		// initialize cannot negotiate a version that removed it.
		{"2026-07-28", "2025-11-25"},
		{"1999-01-01", "2025-11-25"},
		{"", "2025-11-25"},
	}
	for _, tc := range cases {
		t.Run("requested="+tc.requested, func(t *testing.T) {
			srv := newProtocolTestServer(t)
			params := map[string]any{
				"capabilities": map[string]any{},
				"clientInfo":   map[string]any{"name": "legacy-client", "version": "1"},
			}
			if tc.requested != "" {
				params["protocolVersion"] = tc.requested
			}
			resp := postJSON(t, srv, "/mcp", map[string]any{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": params}, credHeaders())
			require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
			assert.Equal(t, float64(0), resp.Body["id"], "id 0 is a valid id")
			res := resp.result(t)
			assert.Equal(t, tc.want, res["protocolVersion"])
			assert.Equal(t, map[string]any{"tools": map[string]any{}}, res["capabilities"])
			assert.Equal(t, map[string]any{"name": "LimaCharlie MCP Server", "version": "1.0.0"}, res["serverInfo"])
			// Legacy results keep the exact legacy shape.
			assert.NotContains(t, res, "resultType")
			assert.NotContains(t, res, "_meta")
		})
	}
}

func TestLegacyInitializeToleratesMalformedOptionalFields(t *testing.T) {
	srv := newProtocolTestServer(t)
	resp := postJSON(t, srv, "/mcp", map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": 5, "clientInfo": "not-an-object"},
	}, credHeaders())
	require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
	assert.Equal(t, "2025-11-25", resp.result(t)["protocolVersion"])
}

func TestLegacyPingAndUnknownMethod(t *testing.T) {
	srv := newProtocolTestServer(t)
	resp := postJSON(t, srv, "/mcp", map[string]any{"jsonrpc": "2.0", "id": "p", "method": "ping"}, nil)
	require.Equal(t, http.StatusOK, resp.Status)
	assert.Equal(t, map[string]any{}, resp.result(t))

	resp = postJSON(t, srv, "/mcp", map[string]any{"jsonrpc": "2.0", "id": "u", "method": "resources/list"}, nil)
	// Legacy revisions define no HTTP status for unknown methods: the
	// JSON-RPC error rides on a 200 as it always has.
	require.Equal(t, http.StatusOK, resp.Status)
	assert.Equal(t, -32601, resp.errorCode(t))
	assert.Equal(t, "u", resp.Body["id"])
}

func TestLegacyProtocolVersionHeader(t *testing.T) {
	srv := newProtocolTestServer(t)
	list := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}

	for _, v := range []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"} {
		resp := postJSON(t, srv, "/mcp", list, map[string]string{"MCP-Protocol-Version": v})
		require.Equal(t, http.StatusOK, resp.Status, "version %s: %s", v, resp.Raw)
		assert.NotContains(t, resp.result(t), "resultType")
	}

	resp := postJSON(t, srv, "/mcp", list, map[string]string{"MCP-Protocol-Version": "2099-12-31"})
	require.Equal(t, http.StatusBadRequest, resp.Status)
	assert.Equal(t, -32022, resp.errorCode(t))
}

func TestLegacyVersionCarriedInMetaIsServedAsLegacy(t *testing.T) {
	srv := newProtocolTestServer(t)
	body, headers := modernRequest(1, "tools/list", nil)
	body["params"].(map[string]any)["_meta"].(map[string]any)[mcp.MetaKeyProtocolVersion] = "2025-06-18"
	headers["MCP-Protocol-Version"] = "2025-06-18"
	delete(headers, "Mcp-Method") // not required before 2026-07-28

	resp := postJSON(t, srv, "/mcp", body, headers)
	require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
	res := resp.result(t)
	assert.NotContains(t, res, "resultType")
	assert.NotContains(t, res, "ttlMs")
}

func TestLegacyToolsListIsUnchangedShape(t *testing.T) {
	srv := newProtocolTestServer(t)
	headers := map[string]string{"X-MCP-Tools": protoEchoTool}
	resp := postJSON(t, srv, "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers)
	require.Equal(t, http.StatusOK, resp.Status)
	res := resp.result(t)
	assert.Equal(t, []string{"tools"}, mapKeys(res), "legacy tools/list carries only the tool list")
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- tools/list contents ----------------------------------------------------

func TestToolsListCarriesFullDefinitions(t *testing.T) {
	srv := newProtocolTestServer(t)
	resp := postJSON(t, srv, "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, map[string]string{"X-MCP-Tools": protoEchoTool})
	require.Equal(t, http.StatusOK, resp.Status)
	listed := resp.result(t)["tools"].([]any)
	require.Len(t, listed, 1)
	echo := listed[0].(map[string]any)

	ann, ok := echo["annotations"].(map[string]any)
	require.True(t, ok, "annotations must be sent: %v", echo)
	assert.Equal(t, true, ann["readOnlyHint"])
	assert.Equal(t, "Echo", ann["title"])
	schema := echo["inputSchema"].(map[string]any)
	assert.Equal(t, "object", schema["type"])
	assert.Contains(t, schema["properties"], "message")
}

func TestToolsListMatchesRegisteredSchemasForEveryTool(t *testing.T) {
	// Every tool's listed definition must be exactly its registered schema
	// (plus the injected oid parameter), so annotations such as
	// destructiveHint reach clients for all tools, not just a sample.
	srv := newProtocolTestServer(t)
	resp := postJSON(t, srv, "/mcp/all", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, nil)
	require.Equal(t, http.StatusOK, resp.Status)
	listed := resp.result(t)["tools"].([]any)
	require.NotEmpty(t, listed)

	names := make([]string, 0, len(listed))
	for _, entry := range listed {
		got := entry.(map[string]any)
		name := got["name"].(string)
		names = append(names, name)

		reg, ok := tools.GetTool(name)
		require.True(t, ok, name)
		want := reg.ToolSchema()
		if reg.NeedsOID() {
			want = tools.AddOIDToToolSchema(want)
		}
		want.Name = reg.ToolName()
		wantJSON, err := json.Marshal(want)
		require.NoError(t, err)
		gotJSON, err := json.Marshal(got)
		require.NoError(t, err)
		assert.JSONEq(t, string(wantJSON), string(gotJSON), "tool %s", name)
	}
	assert.True(t, sort.StringsAreSorted(names), "tools/list must be sorted by name")
	// Every registered tool of the profile is listed (profile entries whose
	// package is not linked into this test binary are skipped, as in prod).
	var registered []string
	for _, name := range tools.GetToolsForProfile("all") {
		if _, ok := tools.GetTool(name); ok {
			registered = append(registered, name)
		}
	}
	assert.ElementsMatch(t, registered, names)
}

func TestToolsListIsDeterministic(t *testing.T) {
	// The "all" profile is built from a map, so its raw order varies between
	// calls; the listing must not.
	srv := newProtocolTestServer(t)
	var first []byte
	for i := 0; i < 5; i++ {
		resp := postJSON(t, srv, "/mcp/all", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, nil)
		require.Equal(t, http.StatusOK, resp.Status)
		if first == nil {
			first = resp.Raw
			continue
		}
		assert.Equal(t, string(first), string(resp.Raw), "listing changed between calls")
	}
}

func TestToolsListDeduplicatesHeaderTools(t *testing.T) {
	srv := newProtocolTestServer(t)
	resp := postJSON(t, srv, "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
		map[string]string{"X-MCP-Tools": protoFailTool + "," + protoEchoTool + "," + protoFailTool})
	require.Equal(t, http.StatusOK, resp.Status)
	listed := resp.result(t)["tools"].([]any)
	require.Len(t, listed, 2)
	assert.Equal(t, protoEchoTool, listed[0].(map[string]any)["name"])
	assert.Equal(t, protoFailTool, listed[1].(map[string]any)["name"])
}

func TestModernAndLegacyListTheSameTools(t *testing.T) {
	srv := newProtocolTestServer(t)
	legacy := postJSON(t, srv, "/mcp/all", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, nil)
	body, headers := modernRequest(1, "tools/list", nil)
	modern := postJSON(t, srv, "/mcp/all", body, headers)
	require.Equal(t, http.StatusOK, legacy.Status)
	require.Equal(t, http.StatusOK, modern.Status)
	assert.Equal(t, jsonString(legacy.result(t)["tools"]), jsonString(modern.result(t)["tools"]))
}

// --- JSON-RPC framing ---------------------------------------------------------

func TestJSONRPCFraming(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   int
		wantID     any // nil: id omitted
	}{
		{"empty body", ``, http.StatusBadRequest, -32700, nil},
		{"not json", `{"jsonrpc":`, http.StatusBadRequest, -32700, nil},
		{"batch", `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, http.StatusBadRequest, -32600, nil},
		{"invalid batch json", `[{"jsonrpc":"2.0",`, http.StatusBadRequest, -32700, nil},
		{"wrong jsonrpc version", `{"jsonrpc":"1.0","id":4,"method":"ping"}`, http.StatusBadRequest, -32600, float64(4)},
		{"missing jsonrpc", `{"id":4,"method":"ping"}`, http.StatusBadRequest, -32600, float64(4)},
		{"float id", `{"jsonrpc":"2.0","id":1.5,"method":"ping"}`, http.StatusBadRequest, -32600, nil},
		{"bool id", `{"jsonrpc":"2.0","id":true,"method":"ping"}`, http.StatusBadRequest, -32600, nil},
		{"object id", `{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}`, http.StatusBadRequest, -32600, nil},
		{"null id on a request", `{"jsonrpc":"2.0","id":null,"method":"tools/list"}`, http.StatusBadRequest, -32600, nil},
		{"method not a string", `{"jsonrpc":"2.0","id":2,"method":7}`, http.StatusBadRequest, -32600, nil},
		{"empty method", `{"jsonrpc":"2.0","id":2,"method":""}`, http.StatusBadRequest, -32600, float64(2)},
		{"client sent a response", `{"jsonrpc":"2.0","id":2,"result":{}}`, http.StatusBadRequest, -32600, float64(2)},
		{"params is an array", `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":[1]}`, http.StatusBadRequest, -32602, float64(2)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newProtocolTestServer(t)
			resp := postRaw(t, srv, "/mcp", []byte(tc.body), nil)
			require.Equal(t, tc.wantStatus, resp.Status, "%s", resp.Raw)
			assert.Equal(t, tc.wantCode, resp.errorCode(t))
			assert.Equal(t, "2.0", resp.Body["jsonrpc"])
			if tc.wantID == nil {
				assert.NotContains(t, resp.Body, "id", "an unreadable id must be omitted, not null")
			} else {
				assert.Equal(t, tc.wantID, resp.Body["id"])
			}
		})
	}
}

func TestStringAndZeroIDsEchoed(t *testing.T) {
	srv := newProtocolTestServer(t)
	for _, raw := range []string{`"abc-123"`, `0`, `-7`, `""`} {
		resp := postRaw(t, srv, "/mcp", []byte(`{"jsonrpc":"2.0","id":`+raw+`,"method":"ping"}`), nil)
		require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
		assert.Contains(t, string(resp.Raw), `"id":`+raw)
	}
}

func TestNotificationsAre202WithoutBody(t *testing.T) {
	bodies := map[string]string{
		"initialized":            `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		"cancelled":              `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}`,
		"null id notification":   `{"jsonrpc":"2.0","id":null,"method":"notifications/initialized"}`,
		"unknown notification":   `{"jsonrpc":"2.0","method":"notifications/whatever"}`,
		"modern-style with meta": `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			srv := newProtocolTestServer(t)
			resp := postRaw(t, srv, "/mcp", []byte(body), nil)
			assert.Equal(t, http.StatusAccepted, resp.Status)
			assert.Empty(t, resp.Raw, "a notification must not get a JSON-RPC response")
		})
	}
}

func TestNonPostMethodsAre405(t *testing.T) {
	srv := newProtocolTestServer(t)
	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPut, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/mcp", nil)
			// Legacy clients open the standalone SSE stream or end a session
			// with these; neither exists here.
			req.Header.Set("Accept", "text/event-stream")
			req.Header.Set("Mcp-Session-Id", "abc")
			w := httptest.NewRecorder()
			srv.mux.ServeHTTP(w, req)
			assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
			assert.Equal(t, http.MethodPost, w.Header().Get("Allow"))
		})
	}
}

func TestSessionHeadersAreIgnored(t *testing.T) {
	srv := newProtocolTestServer(t)
	resp := postJSON(t, srv, "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"},
		map[string]string{"Mcp-Session-Id": "client-made-this-up", "Last-Event-ID": "42"})
	require.Equal(t, http.StatusOK, resp.Status)
	assert.Empty(t, resp.Header.Get("Mcp-Session-Id"), "the server never mints or echoes session ids")
}

func TestRootPathServesBothEras(t *testing.T) {
	srv := newProtocolTestServer(t)
	body, headers := modernRequest(1, "server/discover", nil)
	resp := postJSON(t, srv, "/", body, headers)
	require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
	assert.Equal(t, "complete", resp.result(t)["resultType"])

	resp = postJSON(t, srv, "/", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-06-18"}}, credHeaders())
	require.Equal(t, http.StatusOK, resp.Status)
	assert.Equal(t, "2025-06-18", resp.result(t)["protocolVersion"])
}

// --- Origin validation ------------------------------------------------------

func TestOriginValidation(t *testing.T) {
	newSrv := func(t *testing.T) *Server {
		srv := newProtocolTestServer(t)
		srv.config.HTTP.ServerURL = "https://mcp.example.com"
		srv.config.HTTP.CORSAllowedOrigins = []string{"https://app.example.org"}
		return srv
	}
	ping := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)

	allowed := []string{"", "https://mcp.example.com", "https://MCP.example.com", "https://app.example.org"}
	for _, origin := range allowed {
		t.Run("allowed "+origin, func(t *testing.T) {
			resp := postRaw(t, newSrv(t), "/mcp", ping, map[string]string{"Origin": origin})
			assert.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
		})
	}

	rejected := []string{"https://evil.example", "null", "http://mcp.example.com", "https://mcp.example.com:8443", "https://mcp.example.com.evil.example"}
	for _, origin := range rejected {
		t.Run("rejected "+origin, func(t *testing.T) {
			resp := postRaw(t, newSrv(t), "/mcp", ping, map[string]string{"Origin": origin})
			assert.Equal(t, http.StatusForbidden, resp.Status)
			assert.NotContains(t, resp.Body, "id")
			assert.NotNil(t, resp.Body["error"])
		})
	}

	t.Run("wildcard CORS allows any origin", func(t *testing.T) {
		srv := newSrv(t)
		srv.config.HTTP.CORSAllowedOrigins = []string{"*"}
		resp := postRaw(t, srv, "/mcp", ping, map[string]string{"Origin": "https://anything.example"})
		assert.Equal(t, http.StatusOK, resp.Status)
	})
}

// --- result decoration ------------------------------------------------------

func TestDecorateModernResult(t *testing.T) {
	t.Run("adds resultType and serverInfo, keeps fields", func(t *testing.T) {
		out, err := decorateModernResult(map[string]any{"content": []any{}, "isError": true}, false)
		require.NoError(t, err)
		var got map[string]any
		require.NoError(t, json.Unmarshal(out, &got))
		assert.Equal(t, "complete", got["resultType"])
		assert.Equal(t, true, got["isError"])
		assert.Contains(t, got["_meta"], mcp.MetaKeyServerInfo)
		assert.NotContains(t, got, "ttlMs")
	})
	t.Run("cacheable adds hints", func(t *testing.T) {
		out, err := decorateModernResult(map[string]any{"tools": []any{}}, true)
		require.NoError(t, err)
		assert.Contains(t, string(out), `"ttlMs":300000`)
		assert.Contains(t, string(out), `"cacheScope":"private"`)
	})
	t.Run("merges an existing _meta", func(t *testing.T) {
		out, err := decorateModernResult(map[string]any{"_meta": map[string]any{"a/b": 1}}, false)
		require.NoError(t, err)
		var got map[string]any
		require.NoError(t, json.Unmarshal(out, &got))
		meta := got["_meta"].(map[string]any)
		assert.Equal(t, float64(1), meta["a/b"])
		assert.Contains(t, meta, mcp.MetaKeyServerInfo)
	})
	t.Run("null _meta is replaced", func(t *testing.T) {
		out, err := decorateModernResult(json.RawMessage(`{"_meta":null}`), false)
		require.NoError(t, err)
		assert.Contains(t, string(out), mcp.MetaKeyServerInfo)
	})
	t.Run("non-object results are rejected", func(t *testing.T) {
		_, err := decorateModernResult([]any{1}, false)
		assert.Error(t, err)
		_, err = decorateModernResult(json.RawMessage(`{"_meta":"x"}`), false)
		assert.Error(t, err)
	})
}

func TestParseMCPMessageKeepsRawID(t *testing.T) {
	msg, rpcErr := parseMCPMessage([]byte(`{"jsonrpc":"2.0","id":12345678901234567890,"method":"ping"}`))
	// Larger than int64: not a valid MCP integer id.
	require.NotNil(t, rpcErr)
	assert.Nil(t, msg.id)

	msg, rpcErr = parseMCPMessage([]byte(` {"jsonrpc":"2.0","id":9007199254740993,"method":"ping"} `))
	require.Nil(t, rpcErr)
	assert.Equal(t, "9007199254740993", string(msg.call.id))
	assert.Equal(t, "{}", string(msg.call.params), "missing params normalise to an empty object")
}

// --- OAuth discovery routes -------------------------------------------------

func TestProtectedResourceMetadataPaths(t *testing.T) {
	s, _ := createOAuthTestServer(t)
	// The OAuth handlers load their HTML templates relative to the repo root.
	t.Chdir("../..")
	handlers, err := endpoints.NewHandlers(s.stateManager, s.tokenManager, nil, s.metadataProvider, slog.Default(), []string{"http://localhost/callback"})
	require.NoError(t, err)
	s.oauthHandlers = handlers
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, req)
		return w
	}
	root := get("/.well-known/oauth-protected-resource")
	require.Equal(t, http.StatusOK, root.Code)
	var rootDoc map[string]any
	require.NoError(t, json.Unmarshal(root.Body.Bytes(), &rootDoc))
	require.Equal(t, "https://mcp.example.com/mcp", rootDoc["resource"])

	var someProfile string
	for p := range tools.ProfileDefinitions {
		someProfile = p
		break
	}
	require.NotEmpty(t, someProfile)

	for _, path := range []string{
		"/.well-known/oauth-protected-resource/mcp",
		"/.well-known/oauth-protected-resource/mcp/v1",
		"/.well-known/oauth-protected-resource/mcp/all",
		"/.well-known/oauth-protected-resource/mcp/v1/all",
		"/.well-known/oauth-protected-resource/mcp/" + someProfile,
		"/.well-known/oauth-protected-resource/mcp/v1/" + someProfile,
		"/mcp/.well-known/oauth-protected-resource",
	} {
		t.Run(path, func(t *testing.T) {
			w := get(path)
			require.Equal(t, http.StatusOK, w.Code)
			assert.JSONEq(t, root.Body.String(), w.Body.String())
		})
	}

	for _, path := range []string{
		"/.well-known/oauth-protected-resource/",
		"/.well-known/oauth-protected-resource/other",
		"/.well-known/oauth-protected-resource/mcp/no_such_profile",
		"/.well-known/oauth-protected-resource/mcp/v1/",
		"/.well-known/oauth-protected-resource/mcpx",
		"/.well-known/oauth-protected-resource/mcp/all/extra",
	} {
		t.Run("404 "+path, func(t *testing.T) {
			assert.Equal(t, http.StatusNotFound, get(path).Code)
		})
	}
}

func TestCORSAllowsMCPHeaders(t *testing.T) {
	srv := newProtocolTestServer(t)
	srv.config.HTTP.CORSAllowedOrigins = []string{"https://app.example.org"}
	handler := srv.corsMiddleware(srv.mux)
	req := httptest.NewRequest(http.MethodOptions, "/mcp", nil)
	req.Header.Set("Origin", "https://app.example.org")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	allowed := strings.ToLower(w.Header().Get("Access-Control-Allow-Headers"))
	for _, h := range []string{"mcp-protocol-version", "mcp-method", "mcp-name"} {
		assert.Contains(t, allowed, h)
	}
}
