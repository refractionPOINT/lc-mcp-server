package feedback

import (
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFeedbackToolRegistration(t *testing.T) {
	expectedTools := []string{
		"request_feedback_approval",
		"request_feedback_ack",
		"request_feedback_question",
		"list_feedback_channels",
		"add_feedback_channel",
		"remove_feedback_channel",
	}

	t.Run("all feedback tools are registered", func(t *testing.T) {
		for _, toolName := range expectedTools {
			tool, exists := tools.GetTool(toolName)
			assert.True(t, exists, "Tool %s should be registered", toolName)
			require.NotNil(t, tool, "Tool %s should not be nil", toolName)
			assert.Equal(t, "platform_admin", tool.Profile,
				"Tool %s should be in platform_admin profile", toolName)
		}
	})

	t.Run("tools have correct metadata", func(t *testing.T) {
		for _, toolName := range expectedTools {
			t.Run(toolName, func(t *testing.T) {
				tool, exists := tools.GetTool(toolName)
				require.True(t, exists)
				assert.True(t, tool.RequiresOID,
					"Tool %s RequiresOID should be true", toolName)
				assert.NotEmpty(t, tool.Description)
				assert.NotNil(t, tool.Handler)
				assert.NotNil(t, tool.Schema)
			})
		}
	})
}
