package http

import (
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/gcs"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A deployment without GCS (GCS_BUCKET_NAME unset) still hands the HTTP server a
// large-result manager. A result above the token threshold, such as an inline
// get_payload (up to 25 MiB of base64), must come back in the response: writing
// it to the shared server's temp directory would return a path the remote tenant
// cannot read and leave a file of up to ~33 MB that nothing cleans up.
func TestHTTPLargeResultWithGCSDisabledIsReturnedInline(t *testing.T) {
	// The server wires the manager exactly like this (server_http.go).
	t.Setenv("GCS_BUCKET_NAME", "")
	t.Setenv("GCS_TOKEN_THRESHOLD", "100")
	cfg := gcs.LoadConfig()
	require.False(t, cfg.Enabled)
	mgr, err := gcs.NewManager(context.Background(), cfg)
	require.NoError(t, err)

	// Anything the server writes to its temp directory lands here.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	const probe = "zz_large_result"
	content := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("payload bytes ", 4000)))
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        probe,
		Description: "returns a result far above the large-result threshold, like an inline get_payload",
		Profile:     "core",
		Schema: mcp.NewTool(probe,
			mcp.WithDescription("returns a large result"),
			mcp.WithReadOnlyHintAnnotation(true)),
		Handler: func(context.Context, map[string]interface{}) (*mcp.CallToolResult, error) {
			return tools.SuccessResult(map[string]any{
				"success":        true,
				"payload_name":   "x.bin",
				"encoding":       "base64",
				"content_base64": content,
			}), nil
		},
	})
	t.Cleanup(func() { tools.UnregisterTool(probe) })

	srv := newProtocolTestServer(t)
	srv.gcsManager = mgr
	headers := credHeaders()
	headers["X-MCP-Tools"] = probe

	call := func(body map[string]any, headers map[string]string) {
		t.Helper()
		resp := postJSON(t, srv, "/mcp", body, headers)
		require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
		text, isErr := toolText(t, resp)
		require.False(t, isErr, text)
		assert.NotContains(t, text, "resource_link", "a path on the server is useless to a remote caller")
		assert.NotContains(t, text, "is_temp_file")
		assert.Contains(t, text, content, "the full result is in the response")
	}

	call(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": probe, "arguments": map[string]any{}}}, headers)

	body, modernHeaders := modernRequest(2, "tools/call", map[string]any{"name": probe, "arguments": map[string]any{}})
	for k, v := range headers {
		modernHeaders[k] = v
	}
	call(body, modernHeaders)

	entries, err := os.ReadDir(tmp)
	require.NoError(t, err)
	assert.Empty(t, entries, "nothing may be written to the server's temp directory")
}
