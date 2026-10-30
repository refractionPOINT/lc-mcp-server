package ai

import (
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// start_ai_session has the SDK read its definition from
// hive/ai_agent/<oid>/<key>/data, with the key as given or as the name in a
// hive://ai_agent/<name> reference. url.PathEscape leaves "." and ".." alone, so
// those names are refused before anything is requested.
func TestStartAISessionRefusesDefinitionNamesThatArePathSegments(t *testing.T) {
	tool, ok := tools.GetTool("start_ai_session")
	require.True(t, ok)
	text := func(r *mcp.CallToolResult) string { return r.Content[0].(mcp.TextContent).Text }

	for _, name := range []string{"..", ".", "hive://ai_agent/..", "hive://ai_agent/."} {
		result, err := tool.Handler(toolCallContext(), map[string]interface{}{"definition_name": name})
		require.NoError(t, err)
		require.True(t, result.IsError, name)
		assert.Contains(t, text(result), "definition_name", name)
		assert.Contains(t, text(result), "is not allowed", name)
	}

	// Anything else gets past the check; in this test it then fails for want of an
	// SDK cache, which is the step after it.
	for _, name := range []string{"my-agent", "hive://ai_agent/my-agent", "..a", "a.."} {
		result, err := tool.Handler(toolCallContext(), map[string]interface{}{"definition_name": name})
		require.NoError(t, err)
		require.True(t, result.IsError, name)
		assert.Contains(t, text(result), "failed to get organization", name)
	}
}
