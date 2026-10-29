package http

import (
	"context"
	"net/http"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/payloads"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The HTTP server is shared by many tenants. No request it serves may be marked as
// running on the caller's own machine, or tools that read and write the server's
// filesystem by caller-supplied path would work for any tenant.
func TestHTTPRequestsNeverCarryLocalFilesystemAccess(t *testing.T) {
	const probe = "zz_localfs_probe"
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        probe,
		Description: "reports whether the request may use the server filesystem",
		Profile:     "core",
		RequiresOID: true,
		Schema: mcp.NewTool(probe,
			mcp.WithDescription("reports whether the request may use the server filesystem"),
			mcp.WithReadOnlyHintAnnotation(true)),
		Handler: func(ctx context.Context, _ map[string]interface{}) (*mcp.CallToolResult, error) {
			return tools.SuccessResult(map[string]any{"local_fs": auth.HasLocalFilesystemAccess(ctx)}), nil
		},
	})
	t.Cleanup(func() { tools.UnregisterTool(probe) })

	srv := newProtocolTestServer(t)
	headers := credHeaders()
	headers["X-MCP-Tools"] = probe

	legacy := postJSON(t, srv, "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": probe, "arguments": map[string]any{}}}, headers)
	require.Equal(t, http.StatusOK, legacy.Status, "%s", legacy.Raw)
	text, isErr := toolText(t, legacy)
	require.False(t, isErr, text)
	assert.JSONEq(t, `{"local_fs":false}`, text)

	body, modernHeaders := modernRequest(2, "tools/call", map[string]any{"name": probe, "arguments": map[string]any{}})
	for k, v := range headers {
		modernHeaders[k] = v
	}
	modern := postJSON(t, srv, "/mcp", body, modernHeaders)
	require.Equal(t, http.StatusOK, modern.Status, "%s", modern.Raw)
	text, isErr = toolText(t, modern)
	require.False(t, isErr, text)
	assert.JSONEq(t, `{"local_fs":false}`, text)
}

// End to end through the HTTP transport: a server-side file_path is refused with an
// error that names the in-band alternative, and nothing is read.
func TestHTTPCreatePayloadRefusesServerFilePath(t *testing.T) {
	srv := newProtocolTestServer(t)
	headers := credHeaders()
	headers["X-MCP-Tools"] = "create_payload,get_payload"

	for _, tc := range []struct {
		tool string
		args map[string]any
		hint string
	}{
		{"create_payload", map[string]any{"name": "x.sh", "file_path": "/usr/share/zoneinfo/UTC"}, "file_content"},
		{"get_payload", map[string]any{"name": "x.sh", "file_path": "/tmp/lc-should-not-be-written"}, "content_base64"},
	} {
		resp := postJSON(t, srv, "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": tc.tool, "arguments": tc.args}}, headers)
		require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
		text, isErr := toolText(t, resp)
		assert.True(t, isErr, "%s must be a tool error: %s", tc.tool, text)
		assert.Contains(t, text, "hosting this MCP server")
		assert.Contains(t, text, tc.hint)
	}
}
