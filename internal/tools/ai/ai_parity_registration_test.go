package ai

import (
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAIParityToolRegistration verifies that every AI session / usage / chat /
// memory parity tool is registered with the expected metadata: the ai_powered
// profile and RequiresOID true.
func TestAIParityToolRegistration(t *testing.T) {
	parityTools := []string{
		"start_ai_session",
		"list_ai_sessions",
		"get_ai_session",
		"get_ai_session_history",
		"terminate_ai_session",
		"list_ai_usage",
		"get_ai_usage",
		"list_ai_chats",
		"get_ai_chat",
		"get_ai_chat_history",
		"set_ai_memory",
		"delete_ai_memory",
	}

	t.Run("all parity tools registered with correct metadata", func(t *testing.T) {
		for _, name := range parityTools {
			t.Run(name, func(t *testing.T) {
				tool, exists := tools.GetTool(name)
				require.True(t, exists, "Tool %s should be registered", name)
				require.NotNil(t, tool, "Tool %s should not be nil", name)

				assert.Equal(t, "ai_powered", tool.Profile,
					"Tool %s should be in the ai_powered profile", name)
				assert.True(t, tool.RequiresOID,
					"Tool %s should require an OID", name)

				assert.NotEmpty(t, tool.Description, "Tool %s should have a description", name)
				assert.NotNil(t, tool.Handler, "Tool %s should have a handler", name)
				assert.NotNil(t, tool.Schema, "Tool %s should have a schema", name)
			})
		}
	})
}
