package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/investigation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Investigation Engine is behind INVESTIGATION_ENGINE_ENABLED. These tests run with it unset (the default,
// and what a release without that variable runs with) and check that nothing of the engine is reachable.
// Gate-on behaviour is covered by the tests of internal/tools/investigation and internal/tools.

func requireGateOff(t *testing.T) {
	t.Helper()
	require.False(t, tools.InvestigationEngineEnabled(), "run these tests without %s", tools.EnvInvestigationEngine)
}

// Every tool the investigation package declares is held back: none is in the registry, none is in any profile.
func TestInvestigationEngineGateOffRegistersNoTool(t *testing.T) {
	requireGateOff(t)

	// The package is linked and did declare its tools; they were kept out, not forgotten.
	held := tools.HeldToolNames()
	assert.Contains(t, held, "investigate_get")
	assert.Contains(t, held, "investigate_save_plan")

	for _, name := range tools.GetAllRegisteredToolNames() {
		assert.False(t, strings.HasPrefix(name, "investigate_"), "%s is registered with the gate off", name)
	}
	for _, name := range held {
		_, ok := tools.GetTool(name)
		assert.False(t, ok, "%s is in the registry with the gate off", name)
	}
	assert.Error(t, tools.ValidateToolNames([]string{"investigate_get"}), "X-MCP-Tools must not be able to name a gated tool")

	for _, profile := range []string{investigation.Profile, investigation.Profile + "_readonly"} {
		_, defined := tools.ProfileDefinitions[profile]
		assert.False(t, defined, "profile %s is defined with the gate off", profile)
		assert.Empty(t, tools.GetToolsForProfile(profile), profile)
	}
	for profile, names := range tools.ProfileDefinitions {
		for _, name := range names {
			assert.False(t, strings.HasPrefix(name, "investigate_"), "profile %s lists %s with the gate off", profile, name)
		}
	}
	for _, name := range tools.GetToolsForProfile("all") {
		assert.False(t, strings.HasPrefix(name, "investigate_"), "the all profile lists %s with the gate off", name)
	}
}

func postGateJSONRPC(t *testing.T, srv *Server, path, method string, params map[string]interface{}, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	return w
}

// Over HTTP: tools/list never shows an investigate_ tool, on the all endpoint or on the engine's own profile
// paths, and the engine's profile paths do not exist.
func TestInvestigationEngineGateOffHidesTheToolsOverHTTP(t *testing.T) {
	requireGateOff(t)
	for _, path := range []string{"/mcp", "/mcp/all", "/mcp/v1/all", "/mcp/investigation_engine", "/mcp/v1/investigation_engine", "/mcp/investigation_engine_readonly", "/mcp/v1/investigation_engine_readonly"} {
		t.Run("list "+path, func(t *testing.T) {
			srv := createTestServer(t)
			t.Cleanup(srv.sdkCache.Close)
			srv.profile = ""
			w := postGateJSONRPC(t, srv, path, "tools/list", map[string]interface{}{}, nil)
			var resp struct {
				Result struct {
					Tools []struct {
						Name string `json:"name"`
					} `json:"tools"`
				} `json:"result"`
			}
			if strings.Contains(path, "investigation_engine") {
				// Not a defined profile: the route is not registered at all.
				assert.Equal(t, http.StatusNotFound, w.Code, path)
				return
			}
			require.Equal(t, http.StatusOK, w.Code)
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.NotEmpty(t, resp.Result.Tools, "the all endpoint still lists the other tools")
			for _, tool := range resp.Result.Tools {
				assert.False(t, strings.HasPrefix(tool.Name, "investigate_"), "%s is listed with the gate off", tool.Name)
			}
		})
	}
}

// A client that knows the tool's name gets "Unknown tool", whether it asks through the all endpoint or
// names the tool in X-MCP-Tools.
func TestInvestigationEngineGateOffRefusesCallsAndHeaders(t *testing.T) {
	requireGateOff(t)
	creds := map[string]string{"X-LC-OID": "11111111-2222-3333-4444-555555555555", "X-LC-API-KEY": "local-test-key-for-gate-check"}

	srv := createTestServer(t)
	t.Cleanup(srv.sdkCache.Close)
	srv.profile = ""
	for _, name := range []string{"investigate_get", "investigate_save_plan", "investigate_wave"} {
		w := postGateJSONRPC(t, srv, "/mcp", "tools/call", map[string]interface{}{"name": name, "arguments": map[string]interface{}{}}, creds)
		var resp struct {
			Error struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp), name)
		assert.Equal(t, -32602, resp.Error.Code, name)
		assert.Equal(t, "Unknown tool: "+name, resp.Error.Message, name)
	}

	headers := map[string]string{"X-MCP-Tools": "investigate_get"}
	for k, v := range creds {
		headers[k] = v
	}
	w := postGateJSONRPC(t, srv, "/mcp", "tools/list", map[string]interface{}{}, headers)
	assert.NotContains(t, w.Body.String(), `"name":"investigate_get"`)
	assert.Contains(t, w.Body.String(), "invalid tool names")
}
