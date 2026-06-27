package core

import (
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFleetParityRegistration verifies the fleet-management tools are registered
// with the correct profile and RequiresOID flag.
func TestFleetParityRegistration(t *testing.T) {
	expected := []string{
		"find_sensors_by_tag",
		"wait_sensor_online",
		"export_sensors",
	}

	for _, name := range expected {
		t.Run(name, func(t *testing.T) {
			tool, exists := tools.GetTool(name)
			require.True(t, exists, "Tool %s should be registered", name)
			require.NotNil(t, tool)
			assert.Equal(t, "fleet_management", tool.Profile, "Tool %s should be in fleet_management profile", name)
			assert.True(t, tool.RequiresOID, "Tool %s should require OID", name)
			assert.NotEmpty(t, tool.Description)
			assert.NotNil(t, tool.Handler)
			assert.NotNil(t, tool.Schema)
		})
	}
}
