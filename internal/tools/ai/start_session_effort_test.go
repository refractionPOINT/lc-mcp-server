package ai

import (
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// start_ai_session offers the reasoning effort override with exactly the values
// the ai-sessions service accepts.
func TestStartAISessionDeclaresEffort(t *testing.T) {
	tool, ok := tools.GetTool("start_ai_session")
	require.True(t, ok)

	prop, declared := tool.Schema.InputSchema.Properties["effort"]
	require.True(t, declared, "start_ai_session must declare an effort parameter")
	schema, ok := prop.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "string", schema["type"])
	assert.ElementsMatch(t, []string{"low", "medium", "high", "xhigh", "max"}, schema["enum"])
	assert.NotContains(t, tool.Schema.InputSchema.Required, "effort")
}

// The effort argument reaches the SDK's override; absent or empty sends nothing,
// so the definition's value or the model's own default applies.
func TestStartAISessionPassesEffortToSDK(t *testing.T) {
	opts := startSessionOptions(map[string]interface{}{"definition_name": "my-agent", "effort": "xhigh"})
	require.NotNil(t, opts.Effort)
	assert.Equal(t, "xhigh", *opts.Effort)

	assert.Nil(t, startSessionOptions(map[string]interface{}{"definition_name": "my-agent"}).Effort)
	assert.Nil(t, startSessionOptions(map[string]interface{}{"definition_name": "my-agent", "effort": ""}).Effort)
}
