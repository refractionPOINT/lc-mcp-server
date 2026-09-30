package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Drive the HTTP transport, not just the profile inventory: a narrow profile
// must constrain both discovery and calls, including read-shaped elevated tools.
func TestEmailSecurityProfileDiscovery(t *testing.T) {
	for _, path := range []string{"/mcp/email_security", "/mcp/v1/email_security", "/mcp/email_security_readonly", "/mcp/v1/email_security_readonly"} {
		t.Run(path, func(t *testing.T) {
			srv := createTestServer(t)
			t.Cleanup(srv.sdkCache.Close)
			srv.profile = ""
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.mux.ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code)
			var response struct {
				Result struct {
					Tools []struct {
						Name string `json:"name"`
					} `json:"tools"`
				} `json:"result"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			names := make([]string, 0, len(response.Result.Tools))
			for _, tool := range response.Result.Tools {
				names = append(names, tool.Name)
			}
			assert.Contains(t, names, "mailsec_get_coverage")
			assert.Contains(t, names, "mailsec_list_messages")
			assert.Contains(t, names, "mailsec_analyze")
			assert.NotContains(t, names, "cloudsec_list_findings")
			if path == "/mcp/email_security_readonly" || path == "/mcp/v1/email_security_readonly" {
				for _, name := range privilegedMailTools {
					assert.NotContains(t, names, name)
				}
			} else {
				for _, name := range privilegedMailTools {
					assert.Contains(t, names, name)
				}
			}
		})
	}
}

var privilegedMailTools = []string{
	"mailsec_get_message_eml",
	"mailsec_revise_verdict",
	"mailsec_act_on_message",
	"mailsec_preview_campaign_action",
	"mailsec_act_on_campaign",
	"mailsec_execute_bulk_action",
	"mailsec_resolve_report",
	"mailsec_reopen_report",
	"mailsec_test_connection",
	"mailsec_prepare_tenant_purge",
	"mailsec_purge_tenant",
}

func TestEmailSecurityReadonlyRejectsPrivilegedCalls(t *testing.T) {
	for _, name := range privilegedMailTools {
		t.Run(name, func(t *testing.T) {
			srv := createTestServer(t)
			t.Cleanup(srv.sdkCache.Close)
			srv.profile = ""
			body, err := json.Marshal(map[string]interface{}{
				"jsonrpc": "2.0", "id": 1, "method": "tools/call",
				"params": map[string]interface{}{"name": name, "arguments": map[string]interface{}{}},
			})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/mcp/v1/email_security_readonly", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-LC-OID", "11111111-2222-3333-4444-555555555555")
			req.Header.Set("X-LC-API-KEY", "local-test-key-for-profile-check")
			w := httptest.NewRecorder()
			srv.mux.ServeHTTP(w, req)
			var response struct {
				Error struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			assert.Equal(t, -32601, response.Error.Code)
			assert.Equal(t, "Tool not available", response.Error.Message)
		})
	}
}

func TestUnknownProductProfileDoesNotExposeTools(t *testing.T) {
	for _, path := range []string{"/mcp/email_security_readonli", "/mcp/v1/cloud_security_readonli"} {
		t.Run(path, func(t *testing.T) {
			srv := createTestServer(t)
			t.Cleanup(srv.sdkCache.Close)
			srv.profile = ""
			for _, method := range []string{"tools/list", "tools/call"} {
				body, err := json.Marshal(map[string]interface{}{
					"jsonrpc": "2.0", "id": 1, "method": method,
					"params": map[string]interface{}{"name": "mailsec_act_on_message", "arguments": map[string]interface{}{}},
				})
				require.NoError(t, err)
				req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-LC-OID", "11111111-2222-3333-4444-555555555555")
				req.Header.Set("X-LC-API-KEY", "local-test-key-for-profile-check")
				w := httptest.NewRecorder()
				srv.mux.ServeHTTP(w, req)
				require.Equal(t, http.StatusNotFound, w.Code)
				// Even if routing changes to accept unknown profile paths, the
				// handler must preserve the empty permitted set.
				w = httptest.NewRecorder()
				srv.handleMCPRequest(w, req)
				var response struct {
					Result struct {
						Tools []interface{} `json:"tools"`
					} `json:"result"`
					Error struct {
						Code int `json:"code"`
					} `json:"error"`
				}
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
				if method == "tools/list" {
					assert.Empty(t, response.Result.Tools)
				} else {
					assert.Equal(t, -32601, response.Error.Code)
				}
			}
		})
	}
}

func TestBaseMCPRoutesKeepAllProfile(t *testing.T) {
	srv := createTestServer(t)
	t.Cleanup(srv.sdkCache.Close)
	srv.profile = ""
	for _, path := range []string{"/", "/mcp", "/mcp/" + APIVersionV1} {
		assert.Equal(t, "all", srv.getActiveProfile(httptest.NewRequest(http.MethodPost, path, nil)), path)
	}
}
