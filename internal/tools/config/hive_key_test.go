package config

import (
	"sort"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lookupAndSecretTools are the tools of this package that put a record name into a
// hive request path.
var lookupAndSecretTools = []string{
	"get_lookup", "set_lookup", "delete_lookup", "query_lookup",
	"get_secret", "set_secret", "delete_secret", "enable_secret", "disable_secret",
}

// benignArgs is the smallest argument set that satisfies a tool's schema.
func benignArgs(reg *tools.ToolRegistration) map[string]interface{} {
	schema := reg.ToolSchema()
	args := map[string]interface{}{}
	for _, name := range schema.InputSchema.Required {
		switch schema.InputSchema.Properties[name].(map[string]interface{})["type"] {
		case "number":
			args[name] = float64(1)
		case "boolean":
			args[name] = true
		case "object":
			args[name] = map[string]interface{}{"a": "b"}
		case "array":
			args[name] = []interface{}{"x"}
		default:
			args[name] = "x"
		}
	}
	return args
}

// url.PathEscape leaves "." and ".." alone, so a record named ".." would turn
// hive/<hive>/<partition>/<key>/data into hive/<hive>/<partition>/../data. No tool
// may send that, whichever of its parameters carries the name.
func TestLookupAndSecretToolsNeverSendADotSegment(t *testing.T) {
	const oid = "11111111-2222-3333-4444-555555555555"
	ctx := fakeAPI.Context(t, auth.AuthModeUIDOAuth, oid)
	for _, name := range lookupAndSecretTools {
		reg, ok := tools.GetTool(name)
		require.True(t, ok, "%s is not a registered tool: update lookupAndSecretTools", name)

		var params []string
		for prop, def := range reg.ToolSchema().InputSchema.Properties {
			if def.(map[string]interface{})["type"] == "string" {
				params = append(params, prop)
			}
		}
		sort.Strings(params)

		for _, param := range params {
			for _, value := range []string{"..", "."} {
				t.Run(name+"/"+param+"="+value, func(t *testing.T) {
					fakeAPI.Handle(t, nil)
					args := benignArgs(reg)
					args[param] = value
					_, err := tools.CallTool(ctx, name, args)
					require.NoError(t, err)
					assert.Empty(t, fakeAPI.DotSegmentRequests(), "%s sent a dot segment in a request path", name)
				})
			}
		}
	}
}

func TestLookupAndSecretNamesThatArePathSegmentsAreRefused(t *testing.T) {
	const oid = "11111111-2222-3333-4444-555555555555"
	ctx := fakeAPI.Context(t, auth.AuthModeUIDOAuth, oid)
	for tool, args := range map[string]map[string]interface{}{
		"get_lookup":    {"lookup_name": ".."},
		"delete_secret": {"secret_name": "."},
		"enable_secret": {"secret_name": ".."},
	} {
		t.Run(tool, func(t *testing.T) {
			fakeAPI.Handle(t, nil)
			res, err := tools.CallTool(ctx, tool, args)
			require.NoError(t, err)
			require.True(t, res.IsError)
			assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "is not allowed")
			assert.Empty(t, fakeAPI.Requests(), "refused before anything is sent")
		})
	}
}
