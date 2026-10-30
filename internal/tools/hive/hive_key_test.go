package hive

import (
	"sort"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stringParams lists a tool's string parameters.
func stringParams(reg *tools.ToolRegistration) []string {
	var props []string
	for prop, def := range reg.ToolSchema().InputSchema.Properties {
		if def.(map[string]interface{})["type"] == "string" {
			props = append(props, prop)
		}
	}
	sort.Strings(props)
	return props
}

// url.PathEscape leaves "." and ".." alone, so a record named ".." would turn
// hive/<hive>/<partition>/<key>/data into hive/<hive>/<partition>/../data, a
// different route wherever dot segments get resolved between this server and the
// API. No tool may send that, whichever of its parameters carries the name. Like
// TestNoToolIsSteeredByAStrayPartitionKey it covers every registered tool, so a
// new one is included without anyone remembering to add it.
func TestNoToolSendsADotSegmentInAHivePath(t *testing.T) {
	ctx := fakeAPI.Context(t, auth.AuthModeUIDOAuth, orgA)
	checked := 0
	for _, name := range tools.GetAllRegisteredToolNames() {
		reg, _ := tools.GetTool(name)
		if !reg.NeedsOID() {
			continue
		}
		for _, param := range stringParams(reg) {
			for _, value := range []string{"..", "."} {
				t.Run(name+"/"+param+"="+value, func(t *testing.T) {
					fakeAPI.Handle(t, nil)
					args := argsFor(reg)
					// set_playbook and set_ai_skill insist on these fields.
					for _, required := range reg.ToolSchema().InputSchema.Required {
						if _, isObject := args[required].(map[string]interface{}); isObject {
							args[required] = map[string]interface{}{"a": "b", "python": "x", "content": "x"}
						}
					}
					args[param] = value
					_, err := tools.CallTool(ctx, name, args)
					require.NoError(t, err)
					assert.Empty(t, fakeAPI.DotSegmentRequests(), "%s sent a dot segment in a request path", name)
				})
				checked++
			}
		}
	}
	require.Greater(t, checked, 100, "the hive tools must have been registered and exercised")
}

// The refusal itself: the record name is rejected with an error that says so,
// before any request is made. A name that merely contains dots is a name.
func TestHiveRecordNamesThatArePathSegmentsAreRefused(t *testing.T) {
	ctx := fakeAPI.Context(t, auth.AuthModeUIDOAuth, orgA)
	for _, tc := range []struct {
		tool string
		args map[string]interface{}
	}{
		{"get_playbook", map[string]interface{}{"playbook_name": ".."}},
		{"delete_sop", map[string]interface{}{"sop_name": "."}},
		{"set_hive_record_enabled", map[string]interface{}{"hive_name": "playbook", "key": "..", "enabled": true}},
		{"rename_hive_record", map[string]interface{}{"hive_name": "playbook", "key": "ok", "new_name": ".."}},
		{"validate_hive_record", map[string]interface{}{"hive_name": "playbook", "key": "..", "data": map[string]interface{}{"a": "b"}}},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			fakeAPI.Handle(t, nil)
			res, err := tools.CallTool(ctx, tc.tool, tc.args)
			require.NoError(t, err)
			require.True(t, res.IsError, resultText(res))
			assert.Contains(t, resultText(res), "is not allowed")
			assert.Empty(t, fakeAPI.Requests(), "refused before anything is sent")
		})
	}

	t.Run("a name with dots in it is a name", func(t *testing.T) {
		fakeAPI.Handle(t, nil)
		res, err := tools.CallTool(ctx, "get_playbook", map[string]interface{}{"playbook_name": "..a.."})
		require.NoError(t, err)
		require.False(t, res.IsError, resultText(res))
		require.NotEmpty(t, fakeAPI.Requests())
		assert.Empty(t, fakeAPI.DotSegmentRequests())
	})
}
