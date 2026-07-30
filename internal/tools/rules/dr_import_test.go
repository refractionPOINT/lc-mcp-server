package rules

import (
	"testing"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/hive"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestImportedRuleMetadata covers what a bulk upsert sends as usr_mtd per rule:
// nothing at all for an existing rule (which is what makes the hive keep its
// metadata), a default-enabled one for a rule being created, and a merge when
// the caller passed `enabled`.
func TestImportedRuleMetadata(t *testing.T) {
	existingResp := lc.BatchResponse{
		Data: lc.Dict{
			"usr_mtd": map[string]interface{}{
				"enabled": false,
				"tags":    []interface{}{"reviewed"},
				"comment": "muted, noisy",
				"expiry":  float64(0),
			},
			"sys_mtd": map[string]interface{}{"etag": "abc"},
		},
	}
	notFoundResp := lc.BatchResponse{Error: "RECORD_NOT_FOUND: record name 'r'"}

	t.Run("existing rule without an override sends no metadata", func(t *testing.T) {
		got, err := importedRuleMetadata(existingResp, hive.MetadataOverrides{})
		require.NoError(t, err)
		assert.Nil(t, got, "a nil usr_mtd is what preserves the record's metadata")
	})

	t.Run("existing rule with an override keeps the rest of its metadata", func(t *testing.T) {
		enabled := true
		got, err := importedRuleMetadata(existingResp, hive.MetadataOverrides{Enabled: &enabled})
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.True(t, got.Enabled)
		assert.Equal(t, []string{"reviewed"}, got.Tags)
		assert.Equal(t, "muted, noisy", got.Comment)
	})

	t.Run("missing rule is created enabled", func(t *testing.T) {
		got, err := importedRuleMetadata(notFoundResp, hive.MetadataOverrides{})
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.True(t, got.Enabled)
	})

	t.Run("missing rule honours an explicit disable", func(t *testing.T) {
		disabled := false
		got, err := importedRuleMetadata(notFoundResp, hive.MetadataOverrides{Enabled: &disabled})
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.False(t, got.Enabled)
	})

	t.Run("any other per-operation error is surfaced", func(t *testing.T) {
		_, err := importedRuleMetadata(lc.BatchResponse{Error: "UNAUTHORIZED"}, hive.MetadataOverrides{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "UNAUTHORIZED")
	})
}

// TestRuleSetToolsExposeMetadataOverrides mirrors the hive-side check: the rule
// writers must advertise the metadata overrides they honour, and keep them
// optional so an update does not silently re-enable a disabled rule.
func TestRuleSetToolsExposeMetadataOverrides(t *testing.T) {
	for _, name := range []string{"set_dr_general_rule", "set_dr_managed_rule", "set_fp_rule"} {
		t.Run(name, func(t *testing.T) {
			tool, exists := tools.GetTool(name)
			require.True(t, exists, "tool %s should be registered", name)
			for _, param := range []string{"enabled", "tags", "comment"} {
				assert.Contains(t, tool.Schema.InputSchema.Properties, param)
				assert.NotContains(t, tool.Schema.InputSchema.Required, param)
			}
		})
	}
}
