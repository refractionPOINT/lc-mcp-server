package config

import (
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfigParityRegistration verifies that every new org-admin/config tool is
// registered with the platform_admin profile and requires an OID.
func TestConfigParityRegistration(t *testing.T) {
	newTools := []string{
		"list_audit_logs",
		"get_quota_usage",
		"set_org_quota",
		"get_billing_status",
		"list_billing_plans",
		"get_org_value",
		"set_org_value",
		"rename_org",
		"delete_org",
		"resolve_arl",
		"list_available_extensions",
		"rekey_extension",
		"get_installation_key",
		"enable_secret",
		"disable_secret",
		"get_group_logs",
		"extension_request",
	}

	for _, name := range newTools {
		t.Run(name, func(t *testing.T) {
			tool, exists := tools.GetTool(name)
			require.True(t, exists, "Tool %s should be registered", name)
			require.NotNil(t, tool, "Tool %s should not be nil", name)

			assert.Equal(t, "platform_admin", tool.Profile,
				"Tool %s should be in platform_admin profile", name)
			assert.True(t, tool.RequiresOID,
				"Tool %s should require an OID", name)

			assert.NotEmpty(t, tool.Description, "Tool %s should have a description", name)
			assert.NotNil(t, tool.Handler, "Tool %s should have a handler", name)
			assert.NotNil(t, tool.Schema, "Tool %s should have a schema", name)
		})
	}
}
