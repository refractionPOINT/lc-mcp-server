package rules

import (
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewRulesToolsRegistration verifies that all newly-added detection-engineering
// tools are registered with the correct profile and OID requirement.
func TestNewRulesToolsRegistration(t *testing.T) {
	newTools := []string{
		// integrity
		"list_integrity_rules",
		"set_integrity_rule",
		"delete_integrity_rule",
		// exfil
		"list_exfil_rules",
		"set_exfil_event_rule",
		"set_exfil_watch_rule",
		"delete_exfil_rule",
		// yara sources / rule-sets
		"list_yara_sources",
		"set_yara_ruleset",
		"delete_yara_ruleset",
		// dr/fp enable-disable
		"enable_dr_rule",
		"disable_dr_rule",
		"enable_fp_rule",
		"disable_fp_rule",
		// dr import
		"import_dr_rules",
		// dr-service namespace
		"list_dr_service_rules",
		"set_dr_service_rule",
		"delete_dr_service_rule",
	}

	for _, name := range newTools {
		t.Run(name, func(t *testing.T) {
			tool, exists := tools.GetTool(name)
			require.True(t, exists, "Tool %s should be registered", name)
			require.NotNil(t, tool, "Tool %s should not be nil", name)

			assert.Equal(t, "detection_engineering", tool.Profile,
				"Tool %s should be in the detection_engineering profile", name)
			assert.True(t, tool.RequiresOID,
				"Tool %s should require an OID", name)

			assert.NotEmpty(t, tool.Description, "Tool %s should have a description", name)
			assert.NotNil(t, tool.Handler, "Tool %s should have a handler", name)
			assert.NotNil(t, tool.Schema, "Tool %s should have a schema", name)
		})
	}
}
