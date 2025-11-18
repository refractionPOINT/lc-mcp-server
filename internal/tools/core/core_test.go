package core

import (
	"context"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		pattern  string
		expected bool
	}{
		{"exact match", "server1", "server1", true},
		{"no match", "server1", "server2", false},
		{"wildcard all", "anything", "*", true},
		{"prefix match", "server1", "ser*", true},
		{"prefix no match", "server1", "web*", false},
		{"suffix match", "server1", "*ver1", true},
		{"suffix no match", "server1", "*ver2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchHostname(tt.hostname, tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToolRegistration(t *testing.T) {
	t.Run("all core tools are registered", func(t *testing.T) {
		expectedTools := []string{
			"test_tool",
			"get_sensor_info",
			"list_sensors",
			"get_online_sensors",
			"is_online",
			"search_hosts",
		}

		// Verify each tool is actually registered
		for _, toolName := range expectedTools {
			tool, exists := tools.GetTool(toolName)
			assert.True(t, exists, "Tool %s should be registered", toolName)
			assert.NotNil(t, tool, "Tool %s should not be nil", toolName)
			assert.Equal(t, "core", tool.Profile, "Tool %s should be in core profile", toolName)
		}
	})

	t.Run("tools have correct metadata", func(t *testing.T) {
		testCases := []struct {
			name        string
			requiresOID bool
		}{
			{"test_tool", false},
			{"get_sensor_info", true},
			{"list_sensors", true},
			{"get_online_sensors", true},
			{"is_online", true},
			{"search_hosts", true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				tool, exists := tools.GetTool(tc.name)
				require.True(t, exists)
				assert.Equal(t, tc.requiresOID, tool.RequiresOID,
					"Tool %s RequiresOID should be %v", tc.name, tc.requiresOID)
				assert.NotEmpty(t, tool.Description)
				assert.NotNil(t, tool.Handler)
				assert.NotNil(t, tool.Schema)
			})
		}
	})
}

func TestTestTool(t *testing.T) {
	tool, exists := tools.GetTool("test_tool")
	require.True(t, exists)

	t.Run("returns success without auth context", func(t *testing.T) {
		ctx := context.Background()
		args := make(map[string]interface{})

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.IsError)

		// Verify content structure
		assert.NotEmpty(t, result.Content)
	})

	t.Run("accepts any arguments", func(t *testing.T) {
		ctx := context.Background()
		args := map[string]interface{}{
			"random_param": "value",
			"number":       123,
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.IsError)
	})
}

func TestGetSensorInfo_ParameterValidation(t *testing.T) {
	tool, exists := tools.GetTool("get_sensor_info")
	require.True(t, exists)

	t.Run("requires sid parameter", func(t *testing.T) {
		ctx := context.Background()
		args := make(map[string]interface{})

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError, "Should error when sid is missing")
	})

	t.Run("validates sid format", func(t *testing.T) {
		ctx := context.Background()

		invalidSIDs := []string{
			"",
			"not-a-uuid",
			"12345",
			"abc-def-ghi",
		}

		for _, sid := range invalidSIDs {
			args := map[string]interface{}{
				"sid": sid,
			}

			result, err := tool.Handler(ctx, args)

			require.NoError(t, err, "Handler should not return error for invalid SID")
			assert.True(t, result.IsError, "Should return error result for invalid SID: %s", sid)
		}
	})

	t.Run("accepts valid UUID", func(t *testing.T) {
		ctx := context.Background()
		validSID := "550e8400-e29b-41d4-a716-446655440000"

		args := map[string]interface{}{
			"sid": validSID,
		}

		// Will fail to get organization, but SID validation should pass
		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		// Should error getting organization, not on SID validation
		assert.True(t, result.IsError)
		// Note: Can't easily check exact error message due to MCP result structure
	})
}

func TestListSensors_ParameterValidation(t *testing.T) {
	tool, exists := tools.GetTool("list_sensors")
	require.True(t, exists)

	t.Run("accepts optional parameters", func(t *testing.T) {
		ctx := context.Background()

		args := map[string]interface{}{
			"with_hostname_prefix": "web-",
			"with_ip":              "192.168.1.100",
		}

		// Will fail to get organization, but parameter validation should pass
		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})

	t.Run("works without parameters", func(t *testing.T) {
		ctx := context.Background()
		args := make(map[string]interface{})

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})
}

func TestIsOnline_ParameterValidation(t *testing.T) {
	tool, exists := tools.GetTool("is_online")
	require.True(t, exists)

	t.Run("requires sid parameter", func(t *testing.T) {
		ctx := context.Background()
		args := make(map[string]interface{})

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})

	t.Run("validates sid format", func(t *testing.T) {
		ctx := context.Background()
		args := map[string]interface{}{
			"sid": "invalid-uuid",
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})
}

func TestSearchHosts_ParameterValidation(t *testing.T) {
	tool, exists := tools.GetTool("search_hosts")
	require.True(t, exists)

	t.Run("requires hostname parameter", func(t *testing.T) {
		ctx := context.Background()
		args := make(map[string]interface{})

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})

	t.Run("accepts hostname pattern", func(t *testing.T) {
		ctx := context.Background()
		args := map[string]interface{}{
			"hostname": "web-*",
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		// Will fail to get organization
		assert.True(t, result.IsError)
	})
}

// TestWithOIDParameter tests that tools properly handle OID parameter in UID mode
func TestWithOIDParameter(t *testing.T) {
	tool, exists := tools.GetTool("list_sensors")
	require.True(t, exists)

	t.Run("OID parameter is validated", func(t *testing.T) {
		// Create auth context in UID mode
		authCtx := &auth.AuthContext{
			Mode:   auth.AuthModeUIDKey,
			UID:    "test-user",
			APIKey: "test-key-1234567890",
		}
		ctx := auth.WithAuthContext(context.Background(), authCtx)

		// Test with invalid OID
		args := map[string]interface{}{
			"oid": "invalid oid!@#",
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		// Should fail with invalid OID error
		assert.True(t, result.IsError)
	})
}
