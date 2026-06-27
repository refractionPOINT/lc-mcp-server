package cases

import (
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToolRegistration(t *testing.T) {
	expectedTools := []string{
		"create_case",
		"list_cases",
		"get_case",
		"update_case",
		"add_case_note",
		"list_case_entities",
		"search_case_entities",
		"add_case_entity",
		"add_case_detection",
		"add_case_telemetry",
		"add_case_artifact",
		"get_case_dashboard",
		"get_case_report",
		"bulk_update_cases",
		"merge_cases",
	}

	t.Run("all cases tools are registered", func(t *testing.T) {
		for _, toolName := range expectedTools {
			tool, exists := tools.GetTool(toolName)
			assert.True(t, exists, "Tool %s should be registered", toolName)
			require.NotNil(t, tool, "Tool %s should not be nil", toolName)
			assert.Equal(t, "investigation_management", tool.Profile,
				"Tool %s should be in investigation_management profile", toolName)
		}
	})

	t.Run("all cases tools require OID and have metadata", func(t *testing.T) {
		for _, toolName := range expectedTools {
			t.Run(toolName, func(t *testing.T) {
				tool, exists := tools.GetTool(toolName)
				require.True(t, exists)
				assert.True(t, tool.RequiresOID, "Tool %s RequiresOID should be true", toolName)
				assert.NotEmpty(t, tool.Description, "Tool %s should have a description", toolName)
				assert.NotNil(t, tool.Handler, "Tool %s should have a handler", toolName)
				assert.NotNil(t, tool.Schema, "Tool %s should have a schema", toolName)
			})
		}
	})
}
