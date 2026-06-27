package schemas

import (
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResetSchemasParityRegistration verifies the schema-management tool is
// registered with the correct profile and RequiresOID flag.
func TestResetSchemasParityRegistration(t *testing.T) {
	expected := []string{
		"reset_event_schemas",
	}

	for _, name := range expected {
		t.Run(name, func(t *testing.T) {
			tool, exists := tools.GetTool(name)
			require.True(t, exists, "Tool %s should be registered", name)
			require.NotNil(t, tool)
			assert.Equal(t, "platform_admin", tool.Profile, "Tool %s should be in platform_admin profile", name)
			assert.True(t, tool.RequiresOID, "Tool %s should require OID", name)
			assert.NotEmpty(t, tool.Description)
			assert.NotNil(t, tool.Handler)
			assert.NotNil(t, tool.Schema)
		})
	}
}
