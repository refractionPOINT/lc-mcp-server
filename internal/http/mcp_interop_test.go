package http

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Interoperability tests: two independent MCP client implementations (the
// mark3labs mcp-go client and the official Go SDK) talk to the server over
// real HTTP, in every protocol version they support. The wire log asserts
// what each era actually sent and received.

type wireExchange struct {
	httpMethod      string
	rpcMethod       string
	protocolHeader  string
	mcpMethodHeader string
	mcpNameHeader   string
	status          int
	body            []byte
}

type wireLog struct {
	mu        sync.Mutex
	exchanges []wireExchange
}

func (l *wireLog) record(e wireExchange) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.exchanges = append(l.exchanges, e)
}

func (l *wireLog) snapshot() []wireExchange {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]wireExchange(nil), l.exchanges...)
}

func (l *wireLog) rpcMethods() []string {
	var out []string
	for _, e := range l.snapshot() {
		if e.httpMethod == http.MethodPost {
			out = append(out, e.rpcMethod)
		}
	}
	return out
}

// startInteropServer serves the MCP routes over a real listener and records
// every exchange.
func startInteropServer(t *testing.T) (*httptest.Server, *wireLog) {
	t.Helper()
	srv := newProtocolTestServer(t)
	log := &wireLog{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody []byte
		if r.Body != nil {
			reqBody, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(reqBody))
		}
		var msg struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(reqBody, &msg)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, r)
		log.record(wireExchange{
			httpMethod:      r.Method,
			rpcMethod:       msg.Method,
			protocolHeader:  r.Header.Get("MCP-Protocol-Version"),
			mcpMethodHeader: r.Header.Get("Mcp-Method"),
			mcpNameHeader:   r.Header.Get("Mcp-Name"),
			status:          rec.Code,
			body:            rec.Body.Bytes(),
		})
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	}))
	t.Cleanup(ts.Close)
	return ts, log
}

func interopHeaders() map[string]string {
	h := credHeaders()
	h["X-MCP-Tools"] = protoEchoTool + "," + protoFailTool
	return h
}

// assertEraOnTheWire checks what the client and server exchanged for the
// negotiated era.
func assertEraOnTheWire(t *testing.T, log *wireLog, modern bool, version string) {
	t.Helper()
	methods := log.rpcMethods()
	for _, e := range log.snapshot() {
		if e.httpMethod == http.MethodPost && e.status != http.StatusOK && e.status != http.StatusAccepted {
			t.Errorf("unexpected HTTP %d for %s: %s", e.status, e.rpcMethod, e.body)
		}
		if e.httpMethod != http.MethodPost {
			// Only a legacy client may try the standalone SSE stream, and it
			// must be told there is none.
			assert.False(t, modern, "modern client sent %s", e.httpMethod)
			assert.Equal(t, http.StatusMethodNotAllowed, e.status)
		}
	}
	if modern {
		assert.NotContains(t, methods, "initialize")
		assert.NotContains(t, methods, "notifications/initialized")
		assert.Contains(t, methods, "server/discover")
		for _, e := range log.snapshot() {
			if e.httpMethod != http.MethodPost {
				continue
			}
			assert.Equal(t, version, e.protocolHeader, "%s", e.rpcMethod)
			assert.Equal(t, e.rpcMethod, e.mcpMethodHeader)
			var resp map[string]any
			require.NoError(t, json.Unmarshal(e.body, &resp), "%s", e.body)
			if result, ok := resp["result"].(map[string]any); ok {
				assert.Equal(t, "complete", result["resultType"], "%s", e.rpcMethod)
			}
		}
		return
	}
	assert.Contains(t, methods, "initialize")
	for _, e := range log.snapshot() {
		if e.rpcMethod == "notifications/initialized" {
			assert.Equal(t, http.StatusAccepted, e.status)
			assert.Empty(t, e.body)
		}
		if e.httpMethod == http.MethodPost && e.rpcMethod != "initialize" && version != "2024-11-05" && version != "2025-03-26" {
			// Since 2025-06-18 the negotiated version rides on every request.
			assert.Equal(t, version, e.protocolHeader, "%s", e.rpcMethod)
		}
		var resp map[string]any
		if json.Unmarshal(e.body, &resp) == nil {
			if result, ok := resp["result"].(map[string]any); ok {
				assert.NotContains(t, result, "resultType", "legacy results keep the legacy shape (%s)", e.rpcMethod)
			}
		}
	}
}

func TestInteropMark3labsClient(t *testing.T) {
	cases := []struct {
		name        string
		pinned      string // client.WithProtocolVersion; "" = client default
		wantVersion string
		wantModern  bool
	}{
		{"default", "", "2026-07-28", true},
		{"2026-07-28", "2026-07-28", "2026-07-28", true},
		{"2025-11-25", "2025-11-25", "2025-11-25", false},
		{"2025-06-18", "2025-06-18", "2025-06-18", false},
		{"2025-03-26", "2025-03-26", "2025-03-26", false},
		{"2024-11-05", "2024-11-05", "2024-11-05", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, log := startInteropServer(t)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			tr, err := transport.NewStreamableHTTP(ts.URL+"/mcp", transport.WithHTTPHeaders(interopHeaders()))
			require.NoError(t, err)
			var opts []mcpclient.ClientOption
			if tc.pinned != "" {
				opts = append(opts, mcpclient.WithProtocolVersion(tc.pinned))
			}
			c := mcpclient.NewClient(tr, opts...)
			require.NoError(t, c.Start(ctx))
			defer c.Close()

			initRes, err := c.Initialize(ctx, mcp.InitializeRequest{Params: mcp.InitializeParams{
				ProtocolVersion: tc.pinned,
				ClientInfo:      mcp.Implementation{Name: "interop-mark3labs", Version: "1.0.0"},
			}})
			require.NoError(t, err)
			assert.Equal(t, tc.wantVersion, c.ProtocolVersion())
			assert.Equal(t, tc.wantVersion, initRes.ProtocolVersion)
			assert.Equal(t, "LimaCharlie MCP Server", initRes.ServerInfo.Name)
			require.NotNil(t, initRes.Capabilities.Tools)

			if !tc.wantModern {
				require.NoError(t, c.Ping(ctx))
			}

			listed, err := c.ListTools(ctx, mcp.ListToolsRequest{})
			require.NoError(t, err)
			require.Len(t, listed.Tools, 2)
			assert.Equal(t, protoEchoTool, listed.Tools[0].Name)
			require.NotNil(t, listed.Tools[0].Annotations.ReadOnlyHint)
			assert.True(t, *listed.Tools[0].Annotations.ReadOnlyHint)
			if tc.wantModern {
				assert.Equal(t, mcp.ResultTypeComplete, listed.GetResultType())
				ttl, ok := listed.TTL()
				assert.True(t, ok)
				assert.Equal(t, int64(300000), ttl)
				assert.Equal(t, mcp.CacheScopePrivate, listed.CacheScope)
			}

			res, err := c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{
				Name:      protoEchoTool,
				Arguments: map[string]any{"message": "héllo wörld"},
			}})
			require.NoError(t, err)
			require.False(t, res.IsError)
			require.Len(t, res.Content, 1)
			assert.JSONEq(t, `{"echo":{"message":"héllo wörld"}}`, res.Content[0].(mcp.TextContent).Text)

			res, err = c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: protoFailTool}})
			require.NoError(t, err, "a tool failure is a result, not a transport error")
			assert.True(t, res.IsError)
			assert.Equal(t, "backend exploded: quota exhausted", res.Content[0].(mcp.TextContent).Text)

			_, err = c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "zz_not_a_tool"}})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "Unknown tool")

			assertEraOnTheWire(t, log, tc.wantModern, tc.wantVersion)
		})
	}
}

// headerRoundTripper adds fixed headers to every request.
type headerRoundTripper struct {
	headers map[string]string
}

func (h headerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h.headers {
		r.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func TestInteropOfficialGoSDKClient(t *testing.T) {
	cases := []struct {
		name        string
		requested   string
		wantVersion string
		wantModern  bool
	}{
		{"default", "", "2026-07-28", true},
		{"2026-07-28", "2026-07-28", "2026-07-28", true},
		{"2025-11-25", "2025-11-25", "2025-11-25", false},
		{"2025-06-18", "2025-06-18", "2025-06-18", false},
		{"2025-03-26", "2025-03-26", "2025-03-26", false},
		{"2024-11-05", "2024-11-05", "2024-11-05", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, log := startInteropServer(t)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			client := sdk.NewClient(&sdk.Implementation{Name: "interop-go-sdk", Version: "1.0.0"}, nil)
			cs, err := client.Connect(ctx, &sdk.StreamableClientTransport{
				Endpoint:   ts.URL + "/mcp",
				HTTPClient: &http.Client{Transport: headerRoundTripper{headers: interopHeaders()}},
				MaxRetries: -1,
			}, &sdk.ClientSessionOptions{ProtocolVersion: tc.requested})
			require.NoError(t, err)
			defer cs.Close()

			initRes := cs.InitializeResult()
			require.NotNil(t, initRes)
			assert.Equal(t, tc.wantVersion, initRes.ProtocolVersion)
			assert.Equal(t, "LimaCharlie MCP Server", initRes.ServerInfo.Name)

			listed, err := cs.ListTools(ctx, nil)
			require.NoError(t, err)
			require.Len(t, listed.Tools, 2)
			assert.Equal(t, protoEchoTool, listed.Tools[0].Name)
			require.NotNil(t, listed.Tools[0].Annotations)
			assert.True(t, listed.Tools[0].Annotations.ReadOnlyHint)
			assert.Equal(t, "Echo", listed.Tools[0].Annotations.Title)

			res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: protoEchoTool, Arguments: map[string]any{"message": "hi"}})
			require.NoError(t, err)
			require.False(t, res.IsError)
			assert.JSONEq(t, `{"echo":{"message":"hi"}}`, res.Content[0].(*sdk.TextContent).Text)

			res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: protoFailTool, Arguments: map[string]any{}})
			require.NoError(t, err)
			assert.True(t, res.IsError)
			assert.Equal(t, "backend exploded: quota exhausted", res.Content[0].(*sdk.TextContent).Text)

			_, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "zz_not_a_tool", Arguments: map[string]any{}})
			require.Error(t, err)

			assertEraOnTheWire(t, log, tc.wantModern, tc.wantVersion)
		})
	}
}
