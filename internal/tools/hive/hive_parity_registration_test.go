package hive

import (
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHiveManagementToolRegistration verifies the hive-management tools added
// to this package are registered with the expected metadata.
func TestHiveManagementToolRegistration(t *testing.T) {
	expectedTools := []string{
		"get_hive_schema",
		"validate_hive_record",
		"set_hive_record_enabled",
		"set_hive_record_tags",
		"set_hive_record_comment",
		"rename_hive_record",
		"enable_adapter",
		"disable_adapter",
		"set_adapter_tags",
		"get_adapter_schema",
		"get_adapter_sensors",
	}

	t.Run("all hive management tools are registered", func(t *testing.T) {
		for _, toolName := range expectedTools {
			tool, exists := tools.GetTool(toolName)
			assert.True(t, exists, "Tool %s should be registered", toolName)
			require.NotNil(t, tool, "Tool %s should not be nil", toolName)
			assert.Equal(t, "platform_admin", tool.Profile, "Tool %s should be in platform_admin profile", toolName)
		}
	})

	t.Run("tools have correct metadata", func(t *testing.T) {
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

// TestApplyTagAction verifies the tag set computation for set/add/remove.
func TestApplyTagAction(t *testing.T) {
	t.Run("set replaces existing", func(t *testing.T) {
		got := applyTagAction([]string{"a", "b"}, []string{"c"}, "set")
		assert.Equal(t, []string{"c"}, got)
	})
	t.Run("add merges without duplicates", func(t *testing.T) {
		got := applyTagAction([]string{"a", "b"}, []string{"b", "c"}, "add")
		assert.Equal(t, []string{"a", "b", "c"}, got)
	})
	t.Run("remove drops listed tags", func(t *testing.T) {
		got := applyTagAction([]string{"a", "b", "c"}, []string{"b"}, "remove")
		assert.Equal(t, []string{"a", "c"}, got)
	})
}
