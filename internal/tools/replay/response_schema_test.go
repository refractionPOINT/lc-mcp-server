package replay

import (
	"encoding/json"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Check the wire schema, not just the handlers: clients validate inputs against
// tools/list before calling a tool, so an object-only schema blocks valid rules.
func TestResponseComponentWireSchemas(t *testing.T) {
	for _, name := range []string{"validate_dr_rule_components", "test_dr_rule_events", "replay_dr_rule"} {
		t.Run(name, func(t *testing.T) {
			reg, ok := tools.GetTool(name)
			require.True(t, ok)
			wire, err := json.Marshal(reg.Schema)
			require.NoError(t, err)
			var tool map[string]any
			require.NoError(t, json.Unmarshal(wire, &tool))
			input := tool["inputSchema"].(map[string]any)
			property := input["properties"].(map[string]any)["respond"].(map[string]any)
			assert.NotContains(t, property, "type", "a top-level object type would still reject arrays")
			alternatives, ok := property["oneOf"].([]any)
			require.True(t, ok)
			require.Len(t, alternatives, 2)
			accepted := map[string]bool{}
			for _, alternative := range alternatives {
				branch := alternative.(map[string]any)
				kind := branch["type"].(string)
				accepted[kind] = true
				if kind == "array" {
					assert.Equal(t, "object", branch["items"].(map[string]any)["type"])
				}
			}
			assert.Equal(t, map[string]bool{"array": true, "object": true}, accepted)
			if required, ok := input["required"]; ok {
				assert.NotContains(t, required, "respond")
			}

			// The canonical multi-response rule remains whole after normalization.
			actions := []any{
				map[string]any{"action": "report", "name": "first"},
				map[string]any{"action": "report", "name": "second"},
			}
			rule, err := rules.BuildRuleFromComponents(map[string]any{"event": "NEW_PROCESS"}, actions, "unused")
			require.NoError(t, err)
			assert.Equal(t, actions, rule["respond"])
		})
	}
}
