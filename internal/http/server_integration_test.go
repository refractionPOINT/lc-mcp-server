package http

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/config"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/token"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Import tool packages to trigger init() registration
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/admin"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/ai"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/api" // Generic API access tools
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/artifacts"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/config"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/core"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/forensics"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/historical"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/investigation"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/response"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/rules"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/schemas"
)

// MockTokenManager implements a mock token manager for testing
type MockTokenManager struct {
	validateFunc func(ctx context.Context, token string, checkExpiry bool) (*token.ValidationResult, error)
}

func (m *MockTokenManager) ValidateAccessToken(ctx context.Context, accessToken string, checkExpiry bool) (*token.ValidationResult, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, accessToken, checkExpiry)
	}
	return &token.ValidationResult{
		Valid:           true,
		UID:             "test-uid",
		LimaCharlieJWT:  "test-jwt",
		FirebaseIDToken: "test-firebase-token",
	}, nil
}

// createTestServer creates a minimal server for testing
// Note: This is simplified for basic route testing without Redis/OAuth dependencies.
// Tests that require full integration should use actual server initialization.
func createTestServer(t *testing.T) *Server {
	t.Helper()

	logger := slog.Default()
	cfg := &config.Config{
		HTTP: config.HTTPConfig{
			Port: 8080,
		},
	}

	// Create SDK cache
	sdkCache := auth.NewSDKCache(5*time.Minute, logger)

	s := &Server{
		config:   cfg,
		logger:   logger,
		mux:      http.NewServeMux(),
		sdkCache: sdkCache,
		profile:  "core", // Default test profile
	}

	// Setup routes
	s.setupRoutes()

	return s
}

// Test MCP Tools List
func TestMCPToolsList(t *testing.T) {
	server := createTestServer(t)

	requestBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	}

	body, err := json.Marshal(requestBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "2.0", response["jsonrpc"])
	result := response["result"].(map[string]interface{})
	toolsList := result["tools"].([]interface{})

	// Should have at least some core tools
	assert.Greater(t, len(toolsList), 0)

	// Check that tools have required fields
	if len(toolsList) > 0 {
		firstTool := toolsList[0].(map[string]interface{})
		assert.NotEmpty(t, firstTool["name"])
		assert.NotEmpty(t, firstTool["description"])
		assert.NotNil(t, firstTool["inputSchema"])
	}
}

// Test Invalid JSON-RPC Request
func TestInvalidJSONRPC(t *testing.T) {
	server := createTestServer(t)

	t.Run("malformed JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code) // JSON-RPC errors still return 200

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		errorObj := response["error"].(map[string]interface{})
		assert.Equal(t, float64(-32700), errorObj["code"]) // Parse error
	})

	t.Run("invalid JSON-RPC version", func(t *testing.T) {
		requestBody := map[string]interface{}{
			"jsonrpc": "1.0", // Wrong version
			"id":      1,
			"method":  "initialize",
		}

		body, err := json.Marshal(requestBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.mux.ServeHTTP(w, req)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		errorObj := response["error"].(map[string]interface{})
		assert.Equal(t, float64(-32600), errorObj["code"]) // Invalid Request
	})

	t.Run("unknown method", func(t *testing.T) {
		requestBody := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "unknown_method",
			"params":  map[string]interface{}{},
		}

		body, err := json.Marshal(requestBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.mux.ServeHTTP(w, req)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		errorObj := response["error"].(map[string]interface{})
		assert.Equal(t, float64(-32601), errorObj["code"]) // Method not found
	})
}

// Test Missing Authorization
func TestMissingAuth(t *testing.T) {
	server := createTestServer(t)

	requestBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "test_tool",
			"arguments": map[string]interface{}{},
		},
	}

	body, err := json.Marshal(requestBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	errorObj := response["error"].(map[string]interface{})
	assert.Equal(t, float64(-32000), errorObj["code"]) // Server error
	assert.Contains(t, errorObj["message"], "Unauthorized")
}

// Test Invalid Bearer Token Format
func TestInvalidBearerToken(t *testing.T) {
	server := createTestServer(t)

	t.Run("missing Bearer prefix", func(t *testing.T) {
		requestBody := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name":      "test_tool",
				"arguments": map[string]interface{}{},
			},
		}

		body, err := json.Marshal(requestBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "invalid-token") // Missing "Bearer " prefix
		w := httptest.NewRecorder()

		server.mux.ServeHTTP(w, req)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		errorObj := response["error"].(map[string]interface{})
		assert.Equal(t, float64(-32000), errorObj["code"])
		assert.Contains(t, errorObj["message"], "Unauthorized")
	})
}

// Test Root Endpoint
func TestRootEndpoint(t *testing.T) {
	server := createTestServer(t)

	t.Run("GET returns server info", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		server.mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "lc-mcp-server", response["type"])
		assert.Equal(t, "ok", response["status"])
		assert.NotNil(t, response["endpoints"])
	})

	t.Run("POST delegates to MCP handler", func(t *testing.T) {
		requestBody := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "ping",
		}

		body, err := json.Marshal(requestBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "2.0", response["jsonrpc"])
	})

	t.Run("other methods return 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/", nil)
		w := httptest.NewRecorder()

		server.mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// Test Method Not Allowed
func TestMethodNotAllowed(t *testing.T) {
	server := createTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// Test Ping Method
func TestPingMethod(t *testing.T) {
	server := createTestServer(t)

	requestBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "ping",
	}

	body, err := json.Marshal(requestBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "2.0", response["jsonrpc"])
	assert.Equal(t, float64(1), response["id"])
	assert.NotNil(t, response["result"])
}

// Test Profile Selection
func TestProfileSelection(t *testing.T) {
	server := createTestServer(t)

	// Test with explicit profile set
	server.profile = "core"

	req := httptest.NewRequest(http.MethodGet, "/mcp/historical_data", nil)
	activeProfile := server.getActiveProfile(req)

	// Should use explicit profile, not URL
	assert.Equal(t, "core", activeProfile)

	// Test with no explicit profile (URL-based routing)
	server.profile = ""

	req = httptest.NewRequest(http.MethodGet, "/mcp/historical_data", nil)
	activeProfile = server.getActiveProfile(req)

	// Should extract from URL
	assert.Equal(t, "historical_data", activeProfile)
}

// Test Tool Registration
func TestToolRegistration(t *testing.T) {
	// Verify that core tools are registered
	coreTools := []string{
		"test_tool",
		"get_sensor_info",
		"list_sensors",
		"get_online_sensors",
		"is_online",
		"search_hosts",
	}

	for _, toolName := range coreTools {
		tool, ok := tools.GetTool(toolName)
		assert.True(t, ok, "Tool %s should be registered", toolName)
		if ok {
			assert.Equal(t, toolName, tool.Name)
			assert.NotEmpty(t, tool.Description)
			assert.NotNil(t, tool.Handler)
		}
	}
}

// Test Server Close
func TestServerClose(t *testing.T) {
	server := createTestServer(t)

	err := server.Close()

	assert.NoError(t, err)
}

// Test Versioned Routes
func TestVersionedRoutes(t *testing.T) {
	server := createTestServer(t)

	requestBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	}

	body, err := json.Marshal(requestBody)
	require.NoError(t, err)

	t.Run("unversioned /mcp route works", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "2.0", response["jsonrpc"])
	})

	t.Run("versioned /mcp/v1 route works", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp/v1", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "2.0", response["jsonrpc"])
	})

	t.Run("unversioned and versioned routes return same results", func(t *testing.T) {
		// Request to unversioned route
		req1 := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		req1.Header.Set("Content-Type", "application/json")
		w1 := httptest.NewRecorder()
		server.mux.ServeHTTP(w1, req1)

		var response1 map[string]interface{}
		err = json.Unmarshal(w1.Body.Bytes(), &response1)
		require.NoError(t, err)

		// Request to versioned route
		req2 := httptest.NewRequest(http.MethodPost, "/mcp/v1", bytes.NewReader(body))
		req2.Header.Set("Content-Type", "application/json")
		w2 := httptest.NewRecorder()
		server.mux.ServeHTTP(w2, req2)

		var response2 map[string]interface{}
		err = json.Unmarshal(w2.Body.Bytes(), &response2)
		require.NoError(t, err)

		// Compare tool counts (not exact match since tools might have internal state)
		result1 := response1["result"].(map[string]interface{})
		result2 := response2["result"].(map[string]interface{})
		tools1 := result1["tools"].([]interface{})
		tools2 := result2["tools"].([]interface{})
		assert.Equal(t, len(tools1), len(tools2), "Tool counts should match")
	})

	t.Run("invalid version returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp/v999", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// Test Versioned Profile Routes
func TestVersionedProfileRoutes(t *testing.T) {
	server := createTestServer(t)

	requestBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "ping",
	}

	body, err := json.Marshal(requestBody)
	require.NoError(t, err)

	profileTests := []struct {
		name            string
		unversionedPath string
		versionedPath   string
	}{
		{
			name:            "all profile",
			unversionedPath: "/mcp/all",
			versionedPath:   "/mcp/v1/all",
		},
		{
			name:            "core profile",
			unversionedPath: "/mcp/core",
			versionedPath:   "/mcp/v1/core",
		},
		{
			name:            "historical_data profile",
			unversionedPath: "/mcp/historical_data",
			versionedPath:   "/mcp/v1/historical_data",
		},
	}

	for _, tt := range profileTests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("unversioned route works", func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPost, tt.unversionedPath, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()

				server.mux.ServeHTTP(w, req)

				assert.Equal(t, http.StatusOK, w.Code)

				var response map[string]interface{}
				err = json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Equal(t, "2.0", response["jsonrpc"])
			})

			t.Run("versioned route works", func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPost, tt.versionedPath, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()

				server.mux.ServeHTTP(w, req)

				assert.Equal(t, http.StatusOK, w.Code)

				var response map[string]interface{}
				err = json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Equal(t, "2.0", response["jsonrpc"])
			})
		})
	}

	t.Run("invalid version on profile route returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp/v999/all", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.mux.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// Test Root Endpoint Returns Version Info
func TestRootEndpointVersionInfo(t *testing.T) {
	server := createTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	server.mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Check that version info is present
	apiVersion, ok := response["api_version"].(map[string]interface{})
	require.True(t, ok, "api_version should be present in root response")
	assert.Equal(t, APIVersionV1, apiVersion["current"])
	assert.Equal(t, APIVersionV1, apiVersion["supported"])

	// Check that versioned endpoints are advertised
	endpoints, ok := response["endpoints"].(map[string]interface{})
	require.True(t, ok, "endpoints should be present in root response")
	assert.NotEmpty(t, endpoints["mcp"])
	assert.NotEmpty(t, endpoints["mcp_v1"])
}

// Test Profile-Based Tool Filtering
func TestProfileBasedToolFiltering(t *testing.T) {
	server := createTestServer(t)
	// Clear the hardcoded profile to enable URL-based routing
	server.profile = ""

	requestBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
	}

	body, err := json.Marshal(requestBody)
	require.NoError(t, err)

	tests := []struct {
		name          string
		path          string
		expectedTools []string
		description   string
	}{
		{
			name:          "api_access profile returns only lc_call_tool",
			path:          "/mcp/api_access",
			expectedTools: []string{"lc_call_tool"},
			description:   "api_access profile should return only the lc_call_tool tool",
		},
		{
			name:          "versioned api_access profile returns only lc_call_tool",
			path:          "/mcp/v1/api_access",
			expectedTools: []string{"lc_call_tool"},
			description:   "versioned api_access profile should return only the lc_call_tool tool",
		},
		{
			name: "core profile returns only core tools",
			path: "/mcp/core",
			expectedTools: []string{
				"test_tool",
				"get_sensor_info",
				"list_sensors",
				"get_online_sensors",
				"is_online",
				"search_hosts",
			},
			description: "core profile should return only core tools",
		},
		{
			name: "versioned core profile returns only core tools",
			path: "/mcp/v1/core",
			expectedTools: []string{
				"test_tool",
				"get_sensor_info",
				"list_sensors",
				"get_online_sensors",
				"is_online",
				"search_hosts",
			},
			description: "versioned core profile should return only core tools",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			server.mux.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "Request should succeed")

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err, "Response should be valid JSON")

			// Extract tools from response
			result, ok := response["result"].(map[string]interface{})
			require.True(t, ok, "Response should have result field")

			toolsList, ok := result["tools"].([]interface{})
			require.True(t, ok, "Result should have tools array")

			// Extract tool names
			toolNames := make([]string, len(toolsList))
			for i, tool := range toolsList {
				toolMap, ok := tool.(map[string]interface{})
				require.True(t, ok, "Tool should be an object")
				toolNames[i] = toolMap["name"].(string)
			}

			// Verify exact match of tools
			assert.ElementsMatch(t, tt.expectedTools, toolNames,
				"%s: expected %v, got %v", tt.description, tt.expectedTools, toolNames)
		})
	}
}

// Test Default Profile Returns All Tools
func TestDefaultProfileReturnsAllTools(t *testing.T) {
	server := createTestServer(t)
	// Clear the hardcoded profile to enable URL-based routing
	server.profile = ""

	requestBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
	}

	body, err := json.Marshal(requestBody)
	require.NoError(t, err)

	tests := []struct {
		name        string
		path        string
		description string
	}{
		{
			name:        "root /mcp returns all tools",
			path:        "/mcp",
			description: "default /mcp endpoint should return all tools",
		},
		{
			name:        "versioned /mcp/v1 returns all tools",
			path:        "/mcp/v1",
			description: "versioned /mcp/v1 endpoint should return all tools",
		},
		{
			name:        "explicit all profile returns all tools",
			path:        "/mcp/all",
			description: "/mcp/all profile should return all tools",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			server.mux.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "Request should succeed")

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err, "Response should be valid JSON")

			// Extract tools from response
			result, ok := response["result"].(map[string]interface{})
			require.True(t, ok, "Response should have result field")

			toolsList, ok := result["tools"].([]interface{})
			require.True(t, ok, "Result should have tools array")

			// Should return many tools (at least 50 based on profile definitions)
			assert.Greater(t, len(toolsList), 50, "%s: should return many tools, got %d", tt.description, len(toolsList))

			// Verify it includes tools from multiple profiles
			toolNames := make(map[string]bool)
			for _, tool := range toolsList {
				toolMap, ok := tool.(map[string]interface{})
				require.True(t, ok, "Tool should be an object")
				toolNames[toolMap["name"].(string)] = true
			}

			// Check that it includes tools from different profiles
			assert.True(t, toolNames["lc_call_tool"], "Should include api_access profile tool")
			assert.True(t, toolNames["get_sensor_info"], "Should include core profile tool")
			assert.True(t, toolNames["run_lcql_query"], "Should include historical_data profile tool")
		})
	}
}

// Benchmark MCP Request Handling
func BenchmarkMCPInitialize(b *testing.B) {
	// Create a testing.T for the helper function
	t := &testing.T{}
	server := createTestServer(t)

	requestBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params":  map[string]interface{}{},
	}

	body, _ := json.Marshal(requestBody)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.mux.ServeHTTP(w, req)
	}
}

// Benchmark Versioned Route Performance
func BenchmarkVersionedRoute(b *testing.B) {
	t := &testing.T{}
	server := createTestServer(t)

	requestBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "ping",
	}

	body, _ := json.Marshal(requestBody)

	b.Run("unversioned", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			server.mux.ServeHTTP(w, req)
		}
	})

	b.Run("versioned", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp/v1", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			server.mux.ServeHTTP(w, req)
		}
	})
}
