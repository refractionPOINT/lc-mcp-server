package ai

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"strings"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Exercise real early returns without contacting an API or reading credentials.
func TestGeneratorFailureOutcomes(t *testing.T) {
	t.Setenv("ANTHROPIC_KEY", "")
	generators := []string{"generate_lcql_query", "generate_dr_rule_detection", "generate_dr_rule_respond", "generate_sensor_selector", "generate_python_playbook", "generate_detection_summary"}
	for i, name := range generators {
		t.Run(name, func(t *testing.T) {
			type failureCase struct {
				name, class, response string
				ctx                   context.Context
				args                  map[string]interface{}
			}
			cases := []failureCase{
				{"missing_query", "invalid_query", "query parameter is required", toolCallContext(), nil},
			}
			if i < 3 {
				cases = append(cases, failureCase{"missing_organization", "organization", "failed to get organization", toolCallContext(), map[string]interface{}{"query": "private-input-marker"}})
			} else {
				cases = append(cases, failureCase{"missing_prompt", "prompt_template", "failed to load prompt template", toolCallContext(), map[string]interface{}{"query": "private-input-marker"}})
			}
			if i < 3 {
				// A synthetic unexpired JWT lets organization setup remain local; the
				// missing template returns before schema or provider access.
				cache := auth.NewSDKCache(time.Minute, nil)
				t.Cleanup(cache.Close)
				claims := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Hour).Unix())))
				ctx := auth.WithAuthContext(auth.WithSDKCache(context.Background(), cache), &auth.AuthContext{
					Mode: auth.AuthModeNormal, OID: "aaaaaaaa-1111-2222-3333-444444444444", JWTToken: "eyJhbGciOiJIUzI1NiJ9." + claims + ".synthetic",
				})
				ctx = auth.WithRequestID(ctx, "req-123")
				cases = append(cases, failureCase{"missing_prompt", "prompt_template", "failed to load prompt template", ctx, map[string]interface{}{"query": "private-input-marker"}})
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					logs := captureDefaultLog(t)
					// Empty directory ensures the prompt is unavailable from the CWD.
					t.Chdir(t.TempDir())
					tool, ok := tools.GetTool(name)
					require.True(t, ok)
					result, err := tool.Handler(tc.ctx, tc.args)
					require.NoError(t, err)
					require.NotNil(t, result)
					require.True(t, result.IsError)
					response, err := json.Marshal(result)
					require.NoError(t, err)
					assert.Contains(t, string(response), tc.response)
					assertGeneratorFailure(t, logs.String(), name, tc.class)
				})
			}
			if i >= 3 {
				t.Run("provider_response", func(t *testing.T) {
					logs := captureDefaultLog(t)
					// Use committed prompt fixtures; no provider call is possible without a key.
					t.Chdir("../../..")
					tool, ok := tools.GetTool(name)
					require.True(t, ok)
					result, err := tool.Handler(toolCallContext(), map[string]interface{}{"query": "private-input-marker"})
					require.NoError(t, err)
					require.True(t, result.IsError)
					response, err := json.Marshal(result)
					require.NoError(t, err)
					assert.Contains(t, string(response), "ANTHROPIC_KEY environment variable not set")
					assertGeneratorFailure(t, logs.String(), name, "provider_response")
				})
			}
		})
	}
}

func assertGeneratorFailure(t *testing.T, logs, tool, class string) {
	t.Helper()
	assert.Equal(t, 1, strings.Count(logs, `"msg":"AI generator failed"`), "one terminal marker per failed generator call")
	entry := findLogLine(t, logs, "AI generator failed")
	assert.Equal(t, "INFO", entry["level"])
	assert.Equal(t, tool, entry["tool"])
	assert.Equal(t, "error", entry["outcome"])
	assert.Equal(t, class, entry["error_class"])
	assert.Equal(t, "req-123", entry["request_id"])
	assert.Contains(t, []string{"test-oid", "aaaaaaaa-1111-2222-3333-444444444444"}, entry["oid"])
	assert.Len(t, entry, 8, "only time, level, msg and fixed metadata")
	assert.NotContains(t, logs, "private-input-marker")
	assert.NotContains(t, logs, "test-api-key")
	assert.NotContains(t, logs, "ANTHROPIC_KEY environment variable not set")
}
