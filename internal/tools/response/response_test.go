package response

import (
	"context"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// Test helper to create auth context
func createTestContext() context.Context {
	authCtx := &auth.AuthContext{
		Mode:   auth.AuthModeNormal,
		OID:    "test-org-id",
		APIKey: "test-api-key-1234567890",
	}
	return auth.WithAuthContext(context.Background(), authCtx)
}

// TestToolRegistration verifies response tools in this file are registered correctly
// Note: tasking.go has its own init() and tools, which are tested separately
func TestToolRegistration(t *testing.T) {
	t.Run("network isolation tools are registered", func(t *testing.T) {
		expectedTools := []string{
			"isolate_network",
			"rejoin_network",
			"is_isolated",
			"add_tag",
			"remove_tag",
		}

		for _, toolName := range expectedTools {
			tool, exists := tools.GetTool(toolName)
			assert.True(t, exists, "Tool %s should be registered", toolName)
			assert.NotNil(t, tool, "Tool %s should not be nil", toolName)
			assert.Equal(t, "threat_response", tool.Profile, "Tool %s should be in threat_response profile", toolName)
			assert.True(t, tool.RequiresOID, "Tool %s should require OID", toolName)
		}
	})

	t.Run("tools have correct metadata", func(t *testing.T) {
		testCases := []struct {
			name        string
			description string
		}{
			{"isolate_network", "Isolate a sensor from the network"},
			{"rejoin_network", "Remove network isolation from a sensor"},
			{"is_isolated", "Check if a sensor is isolated from the network"},
			{"add_tag", "Add a tag to a sensor"},
			{"remove_tag", "Remove a tag from a sensor"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				tool, exists := tools.GetTool(tc.name)
				require.True(t, exists)
				assert.NotEmpty(t, tool.Description)
				assert.Contains(t, tool.Description, tc.description)
				assert.NotNil(t, tool.Handler)
				assert.NotNil(t, tool.Schema)
			})
		}
	})
}

// ===== isolate_network tests =====

func TestIsolateNetwork_ParameterValidation(t *testing.T) {
	tool, exists := tools.GetTool("isolate_network")
	require.True(t, exists)

	t.Run("requires sid parameter", func(t *testing.T) {
		ctx := createTestContext()
		args := make(map[string]interface{})

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError, "Should error when sid is missing")
	})

	t.Run("validates sid format", func(t *testing.T) {
		ctx := createTestContext()

		invalidSIDs := []struct {
			sid         string
			description string
		}{
			{"", "empty string"},
			{"not-a-uuid", "invalid format"},
			{"12345", "too short"},
			{"abc-def-ghi-jkl", "invalid UUID"},
		}

		for _, tc := range invalidSIDs {
			t.Run(tc.description, func(t *testing.T) {
				args := map[string]interface{}{
					"sid": tc.sid,
				}

				result, err := tool.Handler(ctx, args)

				require.NoError(t, err)
				assert.True(t, result.IsError, "Should error for invalid SID: %s", tc.sid)
			})
		}
	})

	t.Run("handles missing auth context", func(t *testing.T) {
		ctx := context.Background()
		args := map[string]interface{}{
			"sid": "550e8400-e29b-41d4-a716-446655440000",
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})

	t.Run("handles sensor not found", func(t *testing.T) {
		mockOrg := &testutil.MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return nil // Sensor not found
			},
		}

		ctx := createTestContext()
		ctx = tools.WithOrganizationClient(ctx, mockOrg)

		args := map[string]interface{}{
			"sid": "550e8400-e29b-41d4-a716-446655440000",
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
		// Verify error message mentions sensor not found
		assert.NotEmpty(t, result.Content)
	})
}

// ===== rejoin_network tests =====

func TestRejoinNetwork_ParameterValidation(t *testing.T) {
	tool, exists := tools.GetTool("rejoin_network")
	require.True(t, exists)

	t.Run("requires sid parameter", func(t *testing.T) {
		ctx := createTestContext()
		args := make(map[string]interface{})

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})

	t.Run("validates sid format", func(t *testing.T) {
		ctx := createTestContext()
		args := map[string]interface{}{
			"sid": "invalid-uuid",
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})

	t.Run("handles sensor not found", func(t *testing.T) {
		mockOrg := &testutil.MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return nil
			},
		}

		ctx := createTestContext()
		ctx = tools.WithOrganizationClient(ctx, mockOrg)

		args := map[string]interface{}{
			"sid": "550e8400-e29b-41d4-a716-446655440000",
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})
}

// ===== is_isolated tests =====

func TestIsIsolated_ParameterValidation(t *testing.T) {
	tool, exists := tools.GetTool("is_isolated")
	require.True(t, exists)

	t.Run("requires sid parameter", func(t *testing.T) {
		ctx := createTestContext()
		args := make(map[string]interface{})

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})

	t.Run("validates sid format", func(t *testing.T) {
		ctx := createTestContext()
		args := map[string]interface{}{
			"sid": "not-a-uuid",
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})

	t.Run("handles sensor not found", func(t *testing.T) {
		mockOrg := &testutil.MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return nil
			},
		}

		ctx := createTestContext()
		ctx = tools.WithOrganizationClient(ctx, mockOrg)

		args := map[string]interface{}{
			"sid": "550e8400-e29b-41d4-a716-446655440000",
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})
}

// ===== add_tag tests =====

func TestAddTag_ParameterValidation(t *testing.T) {
	tool, exists := tools.GetTool("add_tag")
	require.True(t, exists)

	t.Run("requires sid parameter", func(t *testing.T) {
		ctx := createTestContext()
		args := map[string]interface{}{
			"tag": "test-tag",
			"ttl": 3600,
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})

	t.Run("requires tag parameter", func(t *testing.T) {
		ctx := createTestContext()
		args := map[string]interface{}{
			"sid": "550e8400-e29b-41d4-a716-446655440000",
			"ttl": 3600,
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})

	t.Run("requires ttl parameter", func(t *testing.T) {
		ctx := createTestContext()
		args := map[string]interface{}{
			"sid": "550e8400-e29b-41d4-a716-446655440000",
			"tag": "test-tag",
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})

	t.Run("validates sid format", func(t *testing.T) {
		ctx := createTestContext()
		args := map[string]interface{}{
			"sid": "invalid-uuid",
			"tag": "test-tag",
			"ttl": 3600,
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})

	t.Run("accepts valid ttl values", func(t *testing.T) {
		mockOrg := &testutil.MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return nil // Will error on sensor not found
			},
		}

		ctx := createTestContext()
		ctx = tools.WithOrganizationClient(ctx, mockOrg)

		validTTLs := []interface{}{
			60,            // int
			3600,          // int
			float64(7200), // float64 (common from JSON)
		}

		for _, ttl := range validTTLs {
			args := map[string]interface{}{
				"sid": "550e8400-e29b-41d4-a716-446655440000",
				"tag": "test-tag",
				"ttl": ttl,
			}

			result, err := tool.Handler(ctx, args)

			require.NoError(t, err)
			// Should error on sensor not found, not TTL validation
			assert.True(t, result.IsError)
		}
	})

	t.Run("handles sensor not found", func(t *testing.T) {
		mockOrg := &testutil.MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return nil
			},
		}

		ctx := createTestContext()
		ctx = tools.WithOrganizationClient(ctx, mockOrg)

		args := map[string]interface{}{
			"sid": "550e8400-e29b-41d4-a716-446655440000",
			"tag": "compromised",
			"ttl": 86400,
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})
}

// ===== remove_tag tests =====

func TestRemoveTag_ParameterValidation(t *testing.T) {
	tool, exists := tools.GetTool("remove_tag")
	require.True(t, exists)

	t.Run("requires sid parameter", func(t *testing.T) {
		ctx := createTestContext()
		args := map[string]interface{}{
			"tag": "test-tag",
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})

	t.Run("requires tag parameter", func(t *testing.T) {
		ctx := createTestContext()
		args := map[string]interface{}{
			"sid": "550e8400-e29b-41d4-a716-446655440000",
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})

	t.Run("validates sid format", func(t *testing.T) {
		ctx := createTestContext()
		args := map[string]interface{}{
			"sid": "not-a-uuid",
			"tag": "test-tag",
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})

	t.Run("handles sensor not found", func(t *testing.T) {
		mockOrg := &testutil.MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				return nil
			},
		}

		ctx := createTestContext()
		ctx = tools.WithOrganizationClient(ctx, mockOrg)

		args := map[string]interface{}{
			"sid": "550e8400-e29b-41d4-a716-446655440000",
			"tag": "test-tag",
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})
}

// Note: Tests for tasking tools (send_reliable_task, list_reliable_tasks, delete_sensor)
// are in tasking.go and should be tested separately with their own test file.

// ===== Edge Cases and Error Scenarios =====

func TestResponse_ConcurrentAccess(t *testing.T) {
	t.Run("handles concurrent tool calls safely", func(t *testing.T) {
		// This test verifies that the tools can handle concurrent access
		// Important for multi-tenant scenarios
		tool, exists := tools.GetTool("is_isolated")
		require.True(t, exists)

		mockOrg := &testutil.MockOrganization{
			GetSensorFunc: func(sid string) *lc.Sensor {
				time.Sleep(10 * time.Millisecond) // Simulate network delay
				return nil
			},
		}

		ctx := createTestContext()
		ctx = tools.WithOrganizationClient(ctx, mockOrg)

		// Run multiple requests concurrently
		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				args := map[string]interface{}{
					"sid": "550e8400-e29b-41d4-a716-446655440000",
				}
				_, _ = tool.Handler(ctx, args)
				done <- true
			}()
		}

		// Wait for all to complete
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

func TestResponse_OIDHandling(t *testing.T) {
	t.Run("supports OID parameter in UID mode", func(t *testing.T) {
		authCtx := &auth.AuthContext{
			Mode:   auth.AuthModeUIDKey,
			UID:    "test-user",
			APIKey: "test-key-1234567890",
		}
		ctx := auth.WithAuthContext(context.Background(), authCtx)

		tool, exists := tools.GetTool("isolate_network")
		require.True(t, exists)

		// Test with valid OID parameter
		args := map[string]interface{}{
			"oid": "valid-org-id",
			"sid": "550e8400-e29b-41d4-a716-446655440000",
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		// Should fail on organization not found, not OID validation
		assert.True(t, result.IsError)
	})

	t.Run("rejects invalid OID format", func(t *testing.T) {
		authCtx := &auth.AuthContext{
			Mode:   auth.AuthModeUIDKey,
			UID:    "test-user",
			APIKey: "test-key-1234567890",
		}
		ctx := auth.WithAuthContext(context.Background(), authCtx)

		tool, exists := tools.GetTool("isolate_network")
		require.True(t, exists)

		args := map[string]interface{}{
			"oid": "invalid oid!@#",
			"sid": "550e8400-e29b-41d4-a716-446655440000",
		}

		result, err := tool.Handler(ctx, args)

		require.NoError(t, err)
		assert.True(t, result.IsError)
	})
}
