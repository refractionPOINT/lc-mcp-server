package config

import (
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLookupValue covers the shape a stored lookup record actually has: the
// hive's PreIngest hook rewrites every lookup into lookup_data /
// optimized_lookup_data, so an indicator is never at the record root.
func TestLookupValue(t *testing.T) {
	t.Run("plain lookup_data table", func(t *testing.T) {
		data := map[string]interface{}{
			"lookup_data": map[string]interface{}{
				"evil.com": map[string]interface{}{"source": "feed-a"},
			},
		}
		value, found := lookupValue(data, "evil.com")
		assert.True(t, found)
		assert.Equal(t, map[string]interface{}{"source": "feed-a"}, value)

		_, found = lookupValue(data, "good.com")
		assert.False(t, found)
	})

	t.Run("indicator at the record root is not a hit", func(t *testing.T) {
		_, found := lookupValue(map[string]interface{}{"evil.com": map[string]interface{}{}}, "evil.com")
		assert.False(t, found)
	})

	t.Run("optimized form resolves the metadata index", func(t *testing.T) {
		data := map[string]interface{}{
			"optimized_lookup_data": map[string]interface{}{
				"_LC_INDICATORS": map[string]interface{}{
					"evil.com":  float64(0),
					"worse.com": float64(1),
				},
				"_LC_METADATA": []interface{}{
					map[string]interface{}{"pulse": "first"},
					map[string]interface{}{"pulse": "second"},
				},
			},
		}
		value, found := lookupValue(data, "worse.com")
		assert.True(t, found)
		assert.Equal(t, map[string]interface{}{"pulse": "second"}, value)

		_, found = lookupValue(data, "good.com")
		assert.False(t, found)
	})

	t.Run("optimized form with an out-of-range index still reports the hit", func(t *testing.T) {
		data := map[string]interface{}{
			"optimized_lookup_data": map[string]interface{}{
				"_LC_INDICATORS": map[string]interface{}{"evil.com": float64(4)},
				"_LC_METADATA":   []interface{}{map[string]interface{}{"pulse": "first"}},
			},
		}
		value, found := lookupValue(data, "evil.com")
		assert.True(t, found)
		assert.Nil(t, value)
	})

	t.Run("plain table wins over the optimized one", func(t *testing.T) {
		data := map[string]interface{}{
			"lookup_data": map[string]interface{}{
				"evil.com": map[string]interface{}{"source": "plain"},
			},
			"optimized_lookup_data": map[string]interface{}{
				"_LC_INDICATORS": map[string]interface{}{"evil.com": float64(0)},
				"_LC_METADATA":   []interface{}{map[string]interface{}{"source": "optimized"}},
			},
		}
		value, found := lookupValue(data, "evil.com")
		assert.True(t, found)
		assert.Equal(t, map[string]interface{}{"source": "plain"}, value)
	})
}

// TestConfigSetToolsExposeMetadataOverrides mirrors the hive-side check for the
// config-owned hive writers.
func TestConfigSetToolsExposeMetadataOverrides(t *testing.T) {
	for _, name := range []string{"set_lookup", "set_secret"} {
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

// TestOrgDescriptionTools covers the org-description surface: a new tool plus
// the optional description on rename_org.
func TestOrgDescriptionTools(t *testing.T) {
	setDesc, exists := tools.GetTool("set_org_description")
	require.True(t, exists, "set_org_description should be registered")
	assert.Equal(t, "platform_admin", setDesc.Profile)
	assert.True(t, setDesc.RequiresOID)
	assert.Contains(t, setDesc.Schema.InputSchema.Properties, "description")
	assert.Contains(t, setDesc.Schema.InputSchema.Required, "description")

	rename, exists := tools.GetTool("rename_org")
	require.True(t, exists)
	assert.Contains(t, rename.Schema.InputSchema.Properties, "description")
	assert.NotContains(t, rename.Schema.InputSchema.Required, "description")
	assert.Contains(t, rename.Schema.InputSchema.Required, "name")
}
