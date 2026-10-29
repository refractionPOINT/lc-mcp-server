package payloads

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/api" // registers lc_call_tool
	"github.com/refractionpoint/lc-mcp-go/internal/tools/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testOID = "11111111-2222-3333-4444-555555555555"

var fakeAPI *testutil.FakeAPI

func TestMain(m *testing.M) {
	api, stop := testutil.InstallFakeAPI()
	fakeAPI = api
	code := m.Run()
	stop()
	os.Exit(code)
}

// payloadStore is the fake gateway's payload backend: the REST routes hand out
// pre-signed URLs, which point back at this same server.
type payloadStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func (p *payloadStore) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()
		switch {
		case strings.HasPrefix(path, "/v1/payload/"+testOID+"/"):
			name, _ := url.PathUnescape(strings.TrimPrefix(path, "/v1/payload/"+testOID+"/"))
			key := url.PathEscape(name)
			switch r.Method {
			case http.MethodPost:
				_ = json.NewEncoder(w).Encode(map[string]string{"put_url": fakeAPI.Server.URL + "/blob/" + key})
			case http.MethodGet:
				_ = json.NewEncoder(w).Encode(map[string]string{"get_url": fakeAPI.Server.URL + "/blob/" + key})
			}
		case strings.HasPrefix(path, "/blob/"):
			key := strings.TrimPrefix(path, "/blob/")
			p.mu.Lock()
			defer p.mu.Unlock()
			if r.Method == http.MethodPut {
				b, _ := io.ReadAll(r.Body)
				p.data[key] = b
				return
			}
			_, _ = w.Write(p.data[key])
		default:
			t.Errorf("unexpected request %s %s", r.Method, path)
			http.NotFound(w, r)
		}
	}
}

func newStore(t *testing.T) *payloadStore {
	s := &payloadStore{data: map[string][]byte{}}
	fakeAPI.Handle(t, s.handler(t))
	return s
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

func call(t *testing.T, ctx context.Context, tool string, args map[string]interface{}) *mcp.CallToolResult {
	t.Helper()
	reg, ok := tools.GetTool(tool)
	require.True(t, ok)
	res, err := reg.Invoke(ctx, args)
	require.NoError(t, err)
	return res
}

// httpCtx is a request as the HTTP transport builds it: no local-filesystem marker.
func httpCtx(t *testing.T) context.Context {
	return fakeAPI.Context(t, auth.AuthModeUIDOAuth, testOID)
}

// stdioCtx is a request as the stdio server builds it: the caller is on their own machine.
func stdioCtx(t *testing.T) context.Context {
	return auth.WithLocalFilesystemAccess(fakeAPI.Context(t, auth.AuthModeUIDOAuth, testOID))
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestCreatePayloadRefusesServerFilePathOverHTTP(t *testing.T) {
	store := newStore(t)
	// A file that exists on the server: the exfiltration target.
	secret := filepath.Join(t.TempDir(), "other-tenant-result.json")
	require.NoError(t, os.WriteFile(secret, []byte("TOP-SECRET"), 0o600))

	res := call(t, httpCtx(t), "create_payload", map[string]interface{}{"name": "x.sh", "file_path": secret})
	require.True(t, res.IsError)
	assert.Contains(t, text(res), "file_path")
	assert.Contains(t, text(res), "file_content", "the error must say what to send instead")

	// Nothing reached the gateway, so nothing was uploaded into the caller's org.
	assert.Empty(t, fakeAPI.Requests())
	assert.Empty(t, store.data)

	t.Run("also refused when file_content is sent alongside", func(t *testing.T) {
		res := call(t, httpCtx(t), "create_payload", map[string]interface{}{"name": "x.sh", "file_path": secret, "file_content": b64([]byte("x"))})
		require.True(t, res.IsError)
		assert.Empty(t, fakeAPI.Requests())
	})

	t.Run("a context that was never marked is treated as HTTP", func(t *testing.T) {
		// Fail closed: the marker is opt-in, so a request path that forgets it gets no
		// filesystem access.
		res := call(t, context.Background(), "create_payload", map[string]interface{}{"name": "x.sh", "file_path": secret})
		require.True(t, res.IsError)
		assert.Contains(t, text(res), "file_path")
	})

	t.Run("blocked prefixes are not the defence: a readable file outside them is refused too", func(t *testing.T) {
		res := call(t, httpCtx(t), "create_payload", map[string]interface{}{"name": "x.sh", "file_path": "/usr/share/zoneinfo/UTC"})
		require.True(t, res.IsError)
		assert.Contains(t, text(res), "hosting this MCP server")
	})
}

func TestGetPayloadRefusesServerFilePathOverHTTP(t *testing.T) {
	store := newStore(t)
	store.data["x.sh"] = []byte("payload-bytes")
	dest := filepath.Join(t.TempDir(), "overwrite-me")
	require.NoError(t, os.WriteFile(dest, []byte("ORIGINAL"), 0o600))

	res := call(t, httpCtx(t), "get_payload", map[string]interface{}{"name": "x.sh", "file_path": dest})
	require.True(t, res.IsError)
	assert.Contains(t, text(res), "content_base64", "the error must say how to get the content instead")

	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "ORIGINAL", string(got), "the server file must be untouched")
	assert.Empty(t, fakeAPI.Requests())

	t.Run("a path that does not exist yet is not created either", func(t *testing.T) {
		fresh := filepath.Join(t.TempDir(), "sub", "new-file")
		res := call(t, httpCtx(t), "get_payload", map[string]interface{}{"name": "x.sh", "file_path": fresh})
		require.True(t, res.IsError)
		_, err := os.Stat(filepath.Dir(fresh))
		assert.True(t, os.IsNotExist(err), "no directory may be created on the server")
	})
}

func TestCreatePayloadInlineContent(t *testing.T) {
	for name, ctx := range map[string]context.Context{"http": httpCtx(t), "stdio": stdioCtx(t)} {
		t.Run(name, func(t *testing.T) {
			store := newStore(t)
			content := []byte("#!/bin/sh\necho hello\n")
			res := call(t, ctx, "create_payload", map[string]interface{}{"name": "hello.sh", "file_content": b64(content)})
			require.False(t, res.IsError, text(res))
			assert.Equal(t, content, store.data["hello.sh"])
			assert.Contains(t, text(res), fmt.Sprintf(`"size":%d`, len(content)))
		})
	}
}

func TestCreatePayloadInlineSizeLimit(t *testing.T) {
	newStore(t)

	atLimit := make([]byte, maxInlineUploadBytes)
	res := call(t, httpCtx(t), "create_payload", map[string]interface{}{"name": "big.bin", "file_content": b64(atLimit)})
	require.False(t, res.IsError, text(res))

	t.Run("one byte over", func(t *testing.T) {
		res := call(t, httpCtx(t), "create_payload", map[string]interface{}{"name": "big.bin", "file_content": b64(make([]byte, maxInlineUploadBytes+1))})
		require.True(t, res.IsError)
		assert.Contains(t, text(res), "too large")
	})

	t.Run("far over is refused before decoding", func(t *testing.T) {
		res := call(t, httpCtx(t), "create_payload", map[string]interface{}{"name": "big.bin", "file_content": strings.Repeat("A", 40<<20)})
		require.True(t, res.IsError)
		assert.Contains(t, text(res), "too large")
	})

	t.Run("the limit fits inside the 10 MiB request body cap", func(t *testing.T) {
		assert.Less(t, base64.StdEncoding.EncodedLen(maxInlineUploadBytes), 10*1024*1024-64*1024)
	})

	t.Run("invalid base64", func(t *testing.T) {
		res := call(t, httpCtx(t), "create_payload", map[string]interface{}{"name": "x", "file_content": "!!!not-base64"})
		require.True(t, res.IsError)
		assert.Contains(t, text(res), "invalid base64")
	})

	t.Run("one of file_path or file_content is required", func(t *testing.T) {
		res := call(t, httpCtx(t), "create_payload", map[string]interface{}{"name": "x"})
		require.True(t, res.IsError)
	})
}

func TestGetPayloadInline(t *testing.T) {
	for name, ctx := range map[string]context.Context{"http": httpCtx(t), "stdio": stdioCtx(t)} {
		t.Run(name, func(t *testing.T) {
			store := newStore(t)
			content := []byte{0x00, 0x01, 0xff, 'M', 'Z'}
			store.data["tool.exe"] = content

			res := call(t, ctx, "get_payload", map[string]interface{}{"name": "tool.exe"})
			require.False(t, res.IsError, text(res))
			var out map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(text(res)), &out))
			assert.Equal(t, "base64", out["encoding"])
			assert.Equal(t, float64(len(content)), out["size"])
			decoded, err := base64.StdEncoding.DecodeString(out["content_base64"].(string))
			require.NoError(t, err)
			assert.Equal(t, content, decoded)
		})
	}
}

func TestGetPayloadInlineSizeLimit(t *testing.T) {
	store := newStore(t)
	store.data["huge.bin"] = make([]byte, maxInlineDownloadBytes+1)
	res := call(t, httpCtx(t), "get_payload", map[string]interface{}{"name": "huge.bin"})
	require.True(t, res.IsError)
	assert.Contains(t, text(res), "limit for inline retrieval")
	assert.NotContains(t, text(res), "content_base64")
}

// stdio is a single local user on their own machine: the file features keep working.
func TestStdioStillSupportsLocalFiles(t *testing.T) {
	store := newStore(t)
	dir := t.TempDir()

	src := filepath.Join(dir, "upload.ps1")
	require.NoError(t, os.WriteFile(src, []byte("Write-Host hi"), 0o600))
	res := call(t, stdioCtx(t), "create_payload", map[string]interface{}{"name": "upload.ps1", "file_path": src})
	require.False(t, res.IsError, text(res))
	assert.Equal(t, []byte("Write-Host hi"), store.data["upload.ps1"])

	store.data["dl.bin"] = []byte("downloaded")
	dest := filepath.Join(dir, "nested", "dl.bin")
	res = call(t, stdioCtx(t), "get_payload", map[string]interface{}{"name": "dl.bin", "file_path": dest})
	require.False(t, res.IsError, text(res))
	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "downloaded", string(got))

	t.Run("the system-directory guard still applies", func(t *testing.T) {
		res := call(t, stdioCtx(t), "get_payload", map[string]interface{}{"name": "dl.bin", "file_path": "/etc/lc-test-should-not-exist"})
		require.True(t, res.IsError)
		assert.Contains(t, text(res), "not allowed")
	})
}

// lc_call_tool reaches these tools indirectly; it must not be a way around the rule.
func TestCreatePayloadViaIndirectDispatchIsRefusedOverHTTP(t *testing.T) {
	newStore(t)
	secret := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(secret, []byte("S"), 0o600))
	res, err := tools.CallTool(httpCtx(t), "create_payload", map[string]interface{}{"name": "x", "file_path": secret})
	require.NoError(t, err)
	require.True(t, res.IsError)
	assert.Contains(t, text(res), "hosting this MCP server")
	assert.Empty(t, fakeAPI.Requests())
}

func TestPayloadFilePathViaLCCallToolIsRefusedOverHTTP(t *testing.T) {
	newStore(t)
	secret := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(secret, []byte("S"), 0o600))
	dest := filepath.Join(t.TempDir(), "d")

	for tool, params := range map[string]map[string]interface{}{
		"create_payload": {"name": "x", "file_path": secret},
		"get_payload":    {"name": "x", "file_path": dest},
	} {
		res := call(t, httpCtx(t), "lc_call_tool", map[string]interface{}{"tool_name": tool, "parameters": params})
		require.True(t, res.IsError, tool)
		assert.Contains(t, text(res), "hosting this MCP server", tool)
	}
	_, err := os.Stat(dest)
	assert.True(t, os.IsNotExist(err))
	assert.Empty(t, fakeAPI.Requests())
}
