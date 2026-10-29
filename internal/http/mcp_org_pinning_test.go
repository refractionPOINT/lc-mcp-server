package http

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Org pinning: under 2026-07-28 the tool list may vary by the credential on
// the request, so a caller whose credential fixes the organization is not
// asked for a per-call oid. Legacy clients keep the listing they always had.

const (
	protoOrgTool         = "zz_proto_org_scoped"
	protoDestructiveTool = "zz_proto_destructive"
	testUID              = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

func registerOrgScopedTool(t *testing.T) {
	t.Helper()
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        protoOrgTool,
		Description: "returns the organization the call ran against",
		Profile:     "core",
		RequiresOID: true,
		Schema: mcp.NewTool(protoOrgTool,
			mcp.WithDescription("returns the organization the call ran against"),
			mcp.WithString("filter", mcp.Required(), mcp.Description("a filter")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			authCtx, err := auth.FromContext(ctx)
			if err != nil {
				return nil, err
			}
			return tools.SuccessResult(map[string]any{"oid": authCtx.OID}), nil
		},
	})
	t.Cleanup(func() { tools.UnregisterTool(protoOrgTool) })

	tools.RegisterTool(&tools.ToolRegistration{
		Name:        protoDestructiveTool,
		Description: "deletes things",
		Profile:     "core",
		RequiresOID: true,
		Schema: mcp.NewTool(protoDestructiveTool,
			mcp.WithDescription("deletes things"),
			mcp.WithDestructiveHintAnnotation(true),
			mcp.WithTitleAnnotation("Delete things"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return tools.SuccessResult("deleted"), nil
		},
	})
	t.Cleanup(func() { tools.UnregisterTool(protoDestructiveTool) })
}

// listedTool returns the definition of name from a tools/list response.
func listedTool(t *testing.T, resp rpcResponse, name string) map[string]any {
	t.Helper()
	for _, entry := range resp.result(t)["tools"].([]any) {
		tool := entry.(map[string]any)
		if tool["name"] == name {
			return tool
		}
	}
	t.Fatalf("tool %s not listed: %s", name, resp.Raw)
	return nil
}

func TestToolsListFixedDefinitions(t *testing.T) {
	// Exact wire shapes, written out by hand rather than derived from the
	// code under test: the injected oid parameter and the annotations.
	srv := newProtocolTestServer(t)
	registerOrgScopedTool(t)
	resp := postJSON(t, srv, "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
		map[string]string{"X-MCP-Tools": protoOrgTool + "," + protoDestructiveTool})
	require.Equal(t, http.StatusOK, resp.Status)

	got, err := json.Marshal(resp.result(t)["tools"])
	require.NoError(t, err)
	assert.JSONEq(t, `[
	  {
	    "name": "zz_proto_destructive",
	    "description": "deletes things",
	    "inputSchema": {
	      "type": "object",
	      "properties": {"oid": {"type": "string", "description": "Organization ID"}},
	      "required": ["oid"]
	    },
	    "annotations": {"title": "Delete things", "readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true}
	  },
	  {
	    "name": "zz_proto_org_scoped",
	    "description": "returns the organization the call ran against",
	    "inputSchema": {
	      "type": "object",
	      "properties": {
	        "filter": {"type": "string", "description": "a filter"},
	        "oid": {"type": "string", "description": "Organization ID"}
	      },
	      "required": ["filter", "oid"]
	    },
	    "annotations": {"readOnlyHint": true, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true}
	  }
	]`, string(got))
}

func TestModernToolsListOmitsOIDWhenCredentialPinsOrg(t *testing.T) {
	cases := []struct {
		name       string
		headers    map[string]string
		wantPinned bool
	}{
		{"org API key", map[string]string{"X-LC-OID": testOID, "X-LC-API-KEY": testAPIKey}, true},
		{"user API key pinned to an org", map[string]string{"X-LC-UID": testUID, "X-LC-API-KEY": testAPIKey, "X-LC-OID": testOID}, true},
		{"user API key, multi-org", map[string]string{"X-LC-UID": testUID, "X-LC-API-KEY": testAPIKey}, false},
		{"no credentials", map[string]string{}, false},
		{"malformed OID header", map[string]string{"X-LC-OID": "bad oid!", "X-LC-API-KEY": testAPIKey}, false},
		{"rejected bearer token", map[string]string{"Authorization": "Bearer not-a-real-token", "X-LC-OID": testOID}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newProtocolTestServer(t)
			registerOrgScopedTool(t)
			body, headers := modernRequest(1, "tools/list", nil)
			delete(headers, "X-LC-OID")
			delete(headers, "X-LC-API-KEY")
			for k, v := range tc.headers {
				headers[k] = v
			}
			headers["X-MCP-Tools"] = protoOrgTool

			resp := postJSON(t, srv, "/mcp", body, headers)
			// tools/list never rejects a caller over its credentials.
			require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
			schema := listedTool(t, resp, protoOrgTool)["inputSchema"].(map[string]any)
			props := schema["properties"].(map[string]any)
			required := schema["required"].([]any)
			assert.Contains(t, props, "filter")
			assert.Contains(t, required, "filter")
			if tc.wantPinned {
				assert.NotContains(t, props, "oid")
				assert.NotContains(t, required, "oid")
			} else {
				assert.Contains(t, props, "oid")
				assert.Contains(t, required, "oid")
			}
		})
	}
}

func TestLegacyToolsListKeepsOIDForPinnedCredentials(t *testing.T) {
	srv := newProtocolTestServer(t)
	registerOrgScopedTool(t)
	headers := credHeaders()
	headers["X-MCP-Tools"] = protoOrgTool
	resp := postJSON(t, srv, "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers)
	require.Equal(t, http.StatusOK, resp.Status)
	schema := listedTool(t, resp, protoOrgTool)["inputSchema"].(map[string]any)
	assert.Contains(t, schema["properties"], "oid")
}

func TestModernPinnedToolCallRunsAgainstPinnedOrg(t *testing.T) {
	srv := newProtocolTestServer(t)
	registerOrgScopedTool(t)

	// The model calls the tool as listed: no oid argument.
	body, headers := modernRequest(1, "tools/call", map[string]any{"name": protoOrgTool, "arguments": map[string]any{"filter": "x"}})
	headers["X-MCP-Tools"] = protoOrgTool
	resp := postJSON(t, srv, "/mcp", body, headers)
	require.Equal(t, http.StatusOK, resp.Status, "%s", resp.Raw)
	res := resp.result(t)
	require.NotEqual(t, true, res["isError"], "%s", resp.Raw)
	assert.JSONEq(t, `{"oid":"`+testOID+`"}`, res["content"].([]any)[0].(map[string]any)["text"].(string))
}

func TestResolveRequestAuth(t *testing.T) {
	srv := newProtocolTestServer(t)
	cases := []struct {
		name        string
		headers     map[string]string
		wantMode    auth.AuthMode
		wantOID     string
		wantPinned  string
		wantFailure bool
		wantChallng bool
	}{
		{"org key", map[string]string{"X-LC-OID": testOID, "X-LC-API-KEY": testAPIKey}, auth.AuthModeNormal, testOID, testOID, false, false},
		{"user key pinned", map[string]string{"X-LC-UID": testUID, "X-LC-API-KEY": testAPIKey, "X-LC-OID": testOID}, auth.AuthModeUIDKey, testOID, testOID, false, false},
		{"user key", map[string]string{"X-LC-UID": testUID, "X-LC-API-KEY": testAPIKey}, auth.AuthModeUIDKey, "", "", false, false},
		{"bad OID", map[string]string{"X-LC-OID": "bad oid!", "X-LC-API-KEY": testAPIKey}, 0, "", "", true, false},
		{"bad UID", map[string]string{"X-LC-UID": "bad uid!", "X-LC-API-KEY": testAPIKey}, 0, "", "", true, false},
		{"not bearer", map[string]string{"Authorization": "Basic abc"}, 0, "", "", true, true},
		{"nothing", map[string]string{}, 0, "", "", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "/mcp", nil)
			require.NoError(t, err)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			resolved, failure := srv.resolveRequestAuth(req, "test")
			if tc.wantFailure {
				require.NotNil(t, failure)
				assert.Nil(t, resolved)
				assert.Equal(t, tc.wantChallng, failure.challenge)
				return
			}
			require.Nil(t, failure)
			assert.Equal(t, tc.wantMode, resolved.authCtx.Mode)
			assert.Equal(t, tc.wantOID, resolved.authCtx.OID)
			assert.Equal(t, tc.wantPinned, resolved.pinnedOID())
			assert.False(t, resolved.jwtPassthrough)
		})
	}

	t.Run("jwt passthrough is never pinned", func(t *testing.T) {
		r := &resolvedAuth{authCtx: &auth.AuthContext{Mode: auth.AuthModeUIDOAuth, OID: testOID}, jwtPassthrough: true}
		assert.Empty(t, r.pinnedOID())
	})
}
