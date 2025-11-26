package replay

import (
	"context"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestContext creates a context with auth for testing
func createTestContext() context.Context {
	authCtx := &auth.AuthContext{
		Mode:   auth.AuthModeNormal,
		OID:    "test-org-id",
		APIKey: "test-api-key-1234567890",
	}
	return auth.WithAuthContext(context.Background(), authCtx)
}

// TestBuildReplayRequest_RuleSource tests rule source validation
func TestBuildReplayRequest_RuleSource(t *testing.T) {
	tests := []struct {
		name        string
		args        map[string]interface{}
		requireEvts bool
		wantErr     string
	}{
		{
			name:        "missing both rule_name and detect",
			args:        map[string]interface{}{},
			requireEvts: false,
			wantErr:     "either 'rule_name' or 'detect' must be provided",
		},
		{
			name: "both rule_name and detect provided",
			args: map[string]interface{}{
				"rule_name": "test-rule",
				"detect":    map[string]interface{}{"event": "NEW_PROCESS"},
			},
			requireEvts: false,
			wantErr:     "cannot provide both 'rule_name' and 'detect'",
		},
		{
			name: "rule_name only is valid",
			args: map[string]interface{}{
				"rule_name":    "test-rule",
				"last_seconds": float64(3600),
			},
			requireEvts: false,
			wantErr:     "",
		},
		{
			name: "detect only is valid",
			args: map[string]interface{}{
				"detect":       map[string]interface{}{"event": "NEW_PROCESS"},
				"last_seconds": float64(3600),
			},
			requireEvts: false,
			wantErr:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildReplayRequest(tt.args, tt.requireEvts)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestBuildReplayRequest_DetectComponent tests detect component validation
func TestBuildReplayRequest_DetectComponent(t *testing.T) {
	tests := []struct {
		name    string
		detect  interface{}
		wantErr string
	}{
		{
			name:    "valid map",
			detect:  map[string]interface{}{"event": "NEW_PROCESS"},
			wantErr: "",
		},
		{
			name:    "invalid string",
			detect:  "not a map",
			wantErr: "detect must be an object/map",
		},
		{
			name:    "invalid array",
			detect:  []interface{}{"a", "b"},
			wantErr: "detect must be an object/map",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := map[string]interface{}{
				"detect":       tt.detect,
				"last_seconds": float64(3600),
			}
			_, err := buildReplayRequest(args, false)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestBuildReplayRequest_RespondComponent tests respond component handling
func TestBuildReplayRequest_RespondComponent(t *testing.T) {
	tests := []struct {
		name    string
		respond interface{}
		wantErr string
		check   func(t *testing.T, req lc.ReplayDRRuleRequest)
	}{
		{
			name:    "nil respond uses default",
			respond: nil,
			wantErr: "",
			check: func(t *testing.T, req lc.ReplayDRRuleRequest) {
				respond := req.Rule["respond"].([]interface{})
				require.Len(t, respond, 1)
				action := respond[0].(map[string]interface{})
				assert.Equal(t, "report", action["action"])
				assert.Equal(t, "test-detection", action["name"])
			},
		},
		{
			name:    "array respond",
			respond: []interface{}{map[string]interface{}{"action": "task", "command": "foo"}},
			wantErr: "",
			check: func(t *testing.T, req lc.ReplayDRRuleRequest) {
				respond := req.Rule["respond"].([]interface{})
				require.Len(t, respond, 1)
				action := respond[0].(map[string]interface{})
				assert.Equal(t, "task", action["action"])
			},
		},
		{
			name:    "single object respond wrapped in array",
			respond: map[string]interface{}{"action": "report", "name": "custom"},
			wantErr: "",
			check: func(t *testing.T, req lc.ReplayDRRuleRequest) {
				respond := req.Rule["respond"].([]interface{})
				require.Len(t, respond, 1)
				action := respond[0].(map[string]interface{})
				assert.Equal(t, "report", action["action"])
				assert.Equal(t, "custom", action["name"])
			},
		},
		{
			name:    "invalid string respond",
			respond: "not valid",
			wantErr: "respond must be an array or object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := map[string]interface{}{
				"detect":       map[string]interface{}{"event": "NEW_PROCESS"},
				"last_seconds": float64(3600),
			}
			if tt.respond != nil {
				args["respond"] = tt.respond
			}

			req, err := buildReplayRequest(args, false)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				if tt.check != nil {
					tt.check(t, req)
				}
			}
		})
	}
}

// TestBuildReplayRequest_Events tests events handling for test_dr_rule_events
func TestBuildReplayRequest_Events(t *testing.T) {
	tests := []struct {
		name    string
		events  interface{}
		wantErr string
	}{
		{
			name:    "missing events when required",
			events:  nil,
			wantErr: "events parameter is required",
		},
		{
			name:    "empty events array",
			events:  []interface{}{},
			wantErr: "events array cannot be empty",
		},
		{
			name: "valid events array",
			events: []interface{}{
				map[string]interface{}{
					"routing": map[string]interface{}{"event_type": "NEW_PROCESS"},
					"event":   map[string]interface{}{"FILE_PATH": "test.exe"},
				},
			},
			wantErr: "",
		},
		{
			name:    "invalid event (not object)",
			events:  []interface{}{"not an object"},
			wantErr: "event at index 0 must be an object",
		},
		{
			name:    "events not an array",
			events:  "not an array",
			wantErr: "events must be an array",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := map[string]interface{}{
				"detect": map[string]interface{}{"event": "NEW_PROCESS"},
			}
			if tt.events != nil {
				args["events"] = tt.events
			}

			_, err := buildReplayRequest(args, true) // requireEvents = true
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestBuildReplayRequest_TimeRange tests time range validation for historical replay
func TestBuildReplayRequest_TimeRange(t *testing.T) {
	tests := []struct {
		name    string
		args    map[string]interface{}
		wantErr string
		check   func(t *testing.T, req lc.ReplayDRRuleRequest)
	}{
		{
			name: "last_seconds provided",
			args: map[string]interface{}{
				"rule_name":    "test-rule",
				"last_seconds": float64(3600),
			},
			wantErr: "",
			check: func(t *testing.T, req lc.ReplayDRRuleRequest) {
				assert.NotZero(t, req.StartTime)
				assert.NotZero(t, req.EndTime)
				assert.True(t, req.EndTime > req.StartTime)
			},
		},
		{
			name: "start_time and end_time provided",
			args: map[string]interface{}{
				"rule_name":  "test-rule",
				"start_time": float64(1000000),
				"end_time":   float64(2000000),
			},
			wantErr: "",
			check: func(t *testing.T, req lc.ReplayDRRuleRequest) {
				assert.Equal(t, int64(1000000), req.StartTime)
				assert.Equal(t, int64(2000000), req.EndTime)
			},
		},
		{
			name: "neither time range provided",
			args: map[string]interface{}{
				"rule_name": "test-rule",
			},
			wantErr: "either 'last_seconds' or both 'start_time' and 'end_time' must be provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := buildReplayRequest(tt.args, false)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				if tt.check != nil {
					tt.check(t, req)
				}
			}
		})
	}
}

// TestBuildReplayRequest_Namespace tests namespace defaulting
func TestBuildReplayRequest_Namespace(t *testing.T) {
	tests := []struct {
		name          string
		namespace     string
		wantNamespace string
	}{
		{
			name:          "no namespace defaults to general",
			namespace:     "",
			wantNamespace: "general",
		},
		{
			name:          "explicit general",
			namespace:     "general",
			wantNamespace: "general",
		},
		{
			name:          "managed namespace",
			namespace:     "managed",
			wantNamespace: "managed",
		},
		{
			name:          "service namespace",
			namespace:     "service",
			wantNamespace: "service",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := map[string]interface{}{
				"rule_name":    "test-rule",
				"last_seconds": float64(3600),
			}
			if tt.namespace != "" {
				args["namespace"] = tt.namespace
			}

			req, err := buildReplayRequest(args, false)
			require.NoError(t, err)
			assert.Equal(t, tt.wantNamespace, req.Namespace)
		})
	}
}

// TestFormatReplayResponse tests response formatting
func TestFormatReplayResponse(t *testing.T) {
	tests := []struct {
		name     string
		response *lc.ReplayDRRuleResponse
		check    func(t *testing.T, result map[string]interface{})
	}{
		{
			name: "basic response",
			response: &lc.ReplayDRRuleResponse{
				DidMatch: true,
				IsDryRun: false,
				Stats: lc.ReplayStats{
					NumEventsProcessed: 100,
					NumEventsMatched:   5,
					NumEvals:           200,
					NumScanned:         150,
					NumBytesScanned:    1024,
					NumShards:          2,
					WallTime:           1.5,
					BilledFor:          100,
					NotBilledFor:       0,
				},
				Results: []lc.ReplayResult{},
			},
			check: func(t *testing.T, result map[string]interface{}) {
				assert.Equal(t, true, result["matched"])
				assert.Equal(t, false, result["is_dry_run"])

				stats := result["stats"].(map[string]interface{})
				assert.Equal(t, uint64(100), stats["events_processed"])
				assert.Equal(t, uint64(5), stats["events_matched"])
				assert.Equal(t, uint64(200), stats["evaluations"])
			},
		},
		{
			name: "with results",
			response: &lc.ReplayDRRuleResponse{
				DidMatch: true,
				Results: []lc.ReplayResult{
					{Action: "report", Data: lc.Dict{"name": "test"}},
					{Action: "task", Data: lc.Dict{"command": "foo"}},
				},
			},
			check: func(t *testing.T, result map[string]interface{}) {
				results := result["results"].([]map[string]interface{})
				require.Len(t, results, 2)
				assert.Equal(t, "report", results[0]["action"])
				assert.Equal(t, "task", results[1]["action"])
			},
		},
		{
			name: "with traces",
			response: &lc.ReplayDRRuleResponse{
				DidMatch: false,
				Traces:   [][]string{{"step", "matched event"}},
			},
			check: func(t *testing.T, result map[string]interface{}) {
				traces := result["traces"].([][]string)
				require.Len(t, traces, 1)
			},
		},
		{
			name: "empty results",
			response: &lc.ReplayDRRuleResponse{
				DidMatch: false,
				Results:  nil,
			},
			check: func(t *testing.T, result map[string]interface{}) {
				results := result["results"].([]interface{})
				assert.Len(t, results, 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatReplayResponse(tt.response)
			require.NotNil(t, result)
			tt.check(t, result)
		})
	}
}

// TestTestDRRuleEventsTool tests the test_dr_rule_events tool handler
func TestTestDRRuleEventsTool(t *testing.T) {
	tool, exists := tools.GetTool("test_dr_rule_events")
	require.True(t, exists, "test_dr_rule_events tool should be registered")
	require.NotNil(t, tool.Handler)

	t.Run("valid request with mock", func(t *testing.T) {
		ctx := createTestContext()

		mockOrg := &testutil.MockOrganization{
			ReplayDRRuleFunc: func(req lc.ReplayDRRuleRequest) (*lc.ReplayDRRuleResponse, error) {
				// Verify the request was built correctly
				assert.NotNil(t, req.Rule)
				assert.NotEmpty(t, req.Events)
				return &lc.ReplayDRRuleResponse{
					DidMatch: true,
					Stats: lc.ReplayStats{
						NumEventsProcessed: 1,
						NumEventsMatched:   1,
					},
				}, nil
			},
		}
		ctx = tools.WithOrganizationClient(ctx, mockOrg)

		args := map[string]interface{}{
			"detect": map[string]interface{}{"event": "NEW_PROCESS"},
			"events": []interface{}{
				map[string]interface{}{
					"routing": map[string]interface{}{"event_type": "NEW_PROCESS"},
					"event":   map[string]interface{}{"FILE_PATH": "test.exe"},
				},
			},
		}

		result, err := tool.Handler(ctx, args)
		require.NoError(t, err)
		assert.False(t, result.IsError)
	})

	t.Run("missing events parameter", func(t *testing.T) {
		ctx := createTestContext()
		mockOrg := &testutil.MockOrganization{}
		ctx = tools.WithOrganizationClient(ctx, mockOrg)

		args := map[string]interface{}{
			"detect": map[string]interface{}{"event": "NEW_PROCESS"},
			// Missing events
		}

		result, err := tool.Handler(ctx, args)
		require.NoError(t, err)
		assert.True(t, result.IsError)
	})
}

// TestReplayDRRuleTool tests the replay_dr_rule tool handler
func TestReplayDRRuleTool(t *testing.T) {
	tool, exists := tools.GetTool("replay_dr_rule")
	require.True(t, exists, "replay_dr_rule tool should be registered")
	require.NotNil(t, tool.Handler)

	t.Run("valid historical replay", func(t *testing.T) {
		ctx := createTestContext()

		mockOrg := &testutil.MockOrganization{
			ReplayDRRuleFunc: func(req lc.ReplayDRRuleRequest) (*lc.ReplayDRRuleResponse, error) {
				// Verify time range was set
				assert.NotZero(t, req.StartTime)
				assert.NotZero(t, req.EndTime)
				return &lc.ReplayDRRuleResponse{
					DidMatch: false,
					Stats: lc.ReplayStats{
						NumEventsProcessed: 1000,
					},
				}, nil
			},
		}
		ctx = tools.WithOrganizationClient(ctx, mockOrg)

		args := map[string]interface{}{
			"rule_name":    "test-rule",
			"last_seconds": float64(3600),
		}

		result, err := tool.Handler(ctx, args)
		require.NoError(t, err)
		assert.False(t, result.IsError)
	})

	t.Run("mutual exclusivity check", func(t *testing.T) {
		ctx := createTestContext()
		mockOrg := &testutil.MockOrganization{}
		ctx = tools.WithOrganizationClient(ctx, mockOrg)

		args := map[string]interface{}{
			"rule_name":    "test-rule",
			"detect":       map[string]interface{}{"event": "NEW_PROCESS"},
			"last_seconds": float64(3600),
		}

		result, err := tool.Handler(ctx, args)
		require.NoError(t, err)
		assert.True(t, result.IsError)
		// Check error message mentions mutual exclusivity
		content, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		assert.Contains(t, content.Text, "cannot provide both")
	})
}
