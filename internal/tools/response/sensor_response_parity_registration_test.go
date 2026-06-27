package response

import (
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSensorResponseParityRegistration verifies the sensor-response tools are
// registered with the correct profile and RequiresOID flag.
func TestSensorResponseParityRegistration(t *testing.T) {
	expected := []string{
		"task_sensor",
		"memory_dump_sensor",
		"seal_sensor",
		"unseal_sensor",
		"mass_add_tag",
		"mass_remove_tag",
	}

	for _, name := range expected {
		t.Run(name, func(t *testing.T) {
			tool, exists := tools.GetTool(name)
			require.True(t, exists, "Tool %s should be registered", name)
			require.NotNil(t, tool)
			assert.Equal(t, "threat_response", tool.Profile, "Tool %s should be in threat_response profile", name)
			assert.True(t, tool.RequiresOID, "Tool %s should require OID", name)
			assert.NotEmpty(t, tool.Description)
			assert.NotNil(t, tool.Handler)
			assert.NotNil(t, tool.Schema)
		})
	}
}
