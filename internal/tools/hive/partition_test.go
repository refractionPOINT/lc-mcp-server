package hive

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// orgA is the caller's effective organization: the one the transport authorized
	// (org pinning, ai_agent.operate). orgB is an organization the same multi-org
	// credential is NOT allowed to operate on.
	orgA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	orgB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

var fakeAPI *testutil.FakeAPI

func TestMain(m *testing.M) {
	api, stop := testutil.InstallFakeAPI()
	fakeAPI = api
	code := m.Run()
	stop()
	os.Exit(code)
}

func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func requestsMentioning(oid string) []string {
	var out []string
	for _, r := range fakeAPI.Requests() {
		if strings.Contains(r.Path, oid) || strings.Contains(string(r.Body), oid) {
			out = append(out, r.Method+" "+r.Path)
		}
	}
	return out
}

// toolsWithPartitionKey lists every registered tool that takes a partition_key
// argument. The table tests below derive from this, so a new tool that grows the
// argument is covered without anyone remembering to add it.
func toolsWithPartitionKey() []string {
	var names []string
	for _, name := range tools.GetAllRegisteredToolNames() {
		reg, _ := tools.GetTool(name)
		if _, ok := reg.ToolSchema().InputSchema.Properties["partition_key"]; ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// argsFor builds the smallest argument set that satisfies a tool's schema.
func argsFor(reg *tools.ToolRegistration) map[string]interface{} {
	schema := reg.ToolSchema()
	args := map[string]interface{}{}
	known := map[string]interface{}{
		"hive_name": "playbook", "key": "k", "rule_name": "k", "new_name": "k2",
		"enabled": true, "tags": []interface{}{"t"}, "action": "add", "comment": "c",
	}
	for _, name := range schema.InputSchema.Required {
		if v, ok := known[name]; ok {
			args[name] = v
			continue
		}
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

// The reproduced vulnerability: a multi-org credential is allowed to operate on org A
// but not org B. The transport checks the EFFECTIVE oid (A) only, so a partition_key
// naming B must not be able to carry the write across.
func TestPartitionKeyCannotRedirectAWriteToAnotherOrganization(t *testing.T) {
	fakeAPI.Handle(t, nil)
	ctx := fakeAPI.Context(t, auth.AuthModeUIDOAuth, orgA)

	res, err := tools.CallTool(ctx, "set_hive_record_enabled", map[string]interface{}{
		"oid": orgA, "hive_name": "ai_agent", "key": "agent1", "enabled": true, "partition_key": orgB,
	})
	require.NoError(t, err)
	require.True(t, res.IsError, "a foreign partition_key must be refused: %s", resultText(res))
	assert.Contains(t, resultText(res), "partition_key")
	assert.Empty(t, fakeAPI.Requests(), "nothing may reach the gateway, for either organization")
	assert.Empty(t, requestsMentioning(orgB))
}

func TestPartitionDefaultsToTheEffectiveOID(t *testing.T) {
	fakeAPI.Handle(t, nil)
	ctx := fakeAPI.Context(t, auth.AuthModeUIDOAuth, orgA)

	res, err := tools.CallTool(ctx, "set_hive_record_enabled", map[string]interface{}{
		"oid": orgA, "hive_name": "ai_agent", "key": "agent1", "enabled": true,
	})
	require.NoError(t, err)
	require.False(t, res.IsError, resultText(res))

	reqs := fakeAPI.Requests()
	require.NotEmpty(t, reqs)
	var wrote bool
	for _, r := range reqs {
		assert.NotContains(t, r.Path, orgB)
		if r.Method == "POST" {
			assert.Equal(t, "/v1/hive/ai_agent/"+orgA+"/agent1/mtd", r.Path)
			wrote = true
		}
	}
	assert.True(t, wrote, "the metadata write must have been sent to the effective organization's partition")
}

// The effective OID follows the oid argument: operating on a second organization the
// caller is allowed to reach uses THAT organization's partition, never the first.
func TestPartitionFollowsTheOIDArgument(t *testing.T) {
	fakeAPI.Handle(t, nil)
	ctx := fakeAPI.Context(t, auth.AuthModeUIDOAuth, orgA)

	res, err := tools.CallTool(ctx, "set_hive_record_enabled", map[string]interface{}{
		"oid": orgB, "hive_name": "ai_agent", "key": "agent1", "enabled": true,
	})
	require.NoError(t, err)
	require.False(t, res.IsError, resultText(res))
	for _, r := range fakeAPI.Requests() {
		assert.NotContains(t, r.Path, orgA)
		assert.Contains(t, r.Path, orgB)
	}

	// And the partition_key must now match B, not the credential's original A.
	fakeAPI.Handle(t, nil)
	res, err = tools.CallTool(ctx, "set_hive_record_enabled", map[string]interface{}{
		"oid": orgB, "hive_name": "ai_agent", "key": "agent1", "enabled": true, "partition_key": orgA,
	})
	require.NoError(t, err)
	require.True(t, res.IsError)
	assert.Empty(t, fakeAPI.Requests())
}

func TestMatchingPartitionKeyIsAccepted(t *testing.T) {
	ctx := fakeAPI.Context(t, auth.AuthModeUIDOAuth, orgA)
	// The OID itself, an empty string and an explicit null all mean "my own partition".
	for label, pk := range map[string]interface{}{"the effective OID": orgA, "empty": "", "null": nil} {
		t.Run(label, func(t *testing.T) {
			fakeAPI.Handle(t, nil)
			res, err := tools.CallTool(ctx, "set_hive_record_enabled", map[string]interface{}{
				"oid": orgA, "hive_name": "ai_agent", "key": "agent1", "enabled": true, "partition_key": pk,
			})
			require.NoError(t, err)
			assert.False(t, res.IsError, resultText(res))
			for _, r := range fakeAPI.Requests() {
				assert.Contains(t, r.Path, orgA)
			}
		})
	}
}

func TestEveryToolWithPartitionKeyRefusesAForeignPartition(t *testing.T) {
	names := toolsWithPartitionKey()
	// The five tools known to take it today; others are picked up automatically.
	for _, want := range []string{"set_hive_record_enabled", "set_hive_record_tags", "set_hive_record_comment", "rename_hive_record", "validate_hive_record"} {
		require.Contains(t, names, want)
	}

	foreign := map[string]interface{}{
		"another org":             orgB,
		"another org, upper case": strings.ToUpper(orgB),
		"path traversal":          "../" + orgB,
		"path with separator":     orgA + "/" + orgB,
		"the org plus a suffix":   orgA + "x",
		"a wildcard":              "*",
	}
	for _, name := range names {
		for label, pk := range foreign {
			t.Run(name+"/"+label, func(t *testing.T) {
				fakeAPI.Handle(t, nil)
				ctx := fakeAPI.Context(t, auth.AuthModeUIDOAuth, orgA)
				reg, _ := tools.GetTool(name)
				args := argsFor(reg)
				args["oid"] = orgA
				args["partition_key"] = pk

				res, err := tools.CallTool(ctx, name, args)
				require.NoError(t, err)
				require.True(t, res.IsError, "%s must refuse partition_key %q: %s", name, pk, resultText(res))
				assert.Empty(t, fakeAPI.Requests())
			})
		}
		t.Run(name+"/non-string", func(t *testing.T) {
			fakeAPI.Handle(t, nil)
			ctx := fakeAPI.Context(t, auth.AuthModeUIDOAuth, orgA)
			reg, _ := tools.GetTool(name)
			args := argsFor(reg)
			args["partition_key"] = float64(7)
			res, err := reg.Invoke(ctx, args)
			require.NoError(t, err)
			require.True(t, res.IsError)
			assert.Empty(t, fakeAPI.Requests())
		})
	}
}

// Tools that do not take partition_key must not be steerable by it either: sent anyway
// (a direct tools/call does not reject unknown arguments), no request may name another
// organization. Covers every registered tool, including ones that only exist to wrap
// the generic hive client.
func TestNoToolIsSteeredByAStrayPartitionKey(t *testing.T) {
	ctx := fakeAPI.Context(t, auth.AuthModeUIDOAuth, orgA)
	checked := 0
	for _, name := range tools.GetAllRegisteredToolNames() {
		reg, _ := tools.GetTool(name)
		if !reg.NeedsOID() {
			continue
		}
		t.Run(name, func(t *testing.T) {
			fakeAPI.Handle(t, nil)
			args := argsFor(reg)
			args["partition_key"] = orgB
			args["partition"] = orgB
			_, err := reg.Invoke(ctx, args)
			require.NoError(t, err)
			assert.Empty(t, requestsMentioning(orgB), "%s sent a request naming a foreign partition", name)
		})
		checked++
	}
	require.Greater(t, checked, 10, "the hive tools must have been registered and exercised")
}

func TestHiveNameCannotRewriteTheRequestPath(t *testing.T) {
	ctx := fakeAPI.Context(t, auth.AuthModeUIDOAuth, orgA)
	for _, tool := range []string{"get_rule", "list_rules", "set_hive_record_enabled", "validate_hive_record", "get_hive_schema", "rename_hive_record"} {
		for _, bad := range []string{"../" + orgB + "/x", "a/b", "..", "x?y=1", "x#f", "a b", "x%2fy", strings.Repeat("a", 65)} {
			fakeAPI.Handle(t, nil)
			reg, _ := tools.GetTool(tool)
			args := argsFor(reg)
			args["hive_name"] = bad
			res, err := reg.Invoke(ctx, args)
			require.NoError(t, err)
			assert.True(t, res.IsError, "%s accepted hive_name %q", tool, bad)
			assert.Empty(t, fakeAPI.Requests(), "%s sent a request for hive_name %q", tool, bad)
		}
	}
}

func TestValidateHiveRecordEscapesTheKey(t *testing.T) {
	fakeAPI.Handle(t, nil)
	ctx := fakeAPI.Context(t, auth.AuthModeUIDOAuth, orgA)
	reg, _ := tools.GetTool("validate_hive_record")
	res, err := reg.Invoke(ctx, map[string]interface{}{
		"hive_name": "playbook", "key": "../../" + orgB + "/k", "data": map[string]interface{}{"a": "b"},
	})
	require.NoError(t, err)
	require.False(t, res.IsError, resultText(res))
	reqs := fakeAPI.Requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "/v1/hive/playbook/"+orgA+"/..%2F..%2F"+orgB+"%2Fk/validate", reqs[0].Path)
}

// The exported helpers other code may call enforce the rule too, so a future caller
// cannot reintroduce the bypass by building the partition itself.
func TestRecordWriteHelpersRefuseAForeignPartition(t *testing.T) {
	fakeAPI.Handle(t, nil)
	ctx := fakeAPI.Context(t, auth.AuthModeUIDOAuth, orgA)
	org, err := tools.GetOrganization(ctx)
	require.NoError(t, err)

	_, err = SetRecord(org, RecordWrite{HiveName: "playbook", PartitionKey: orgB, Key: "k", Data: map[string]interface{}{"a": 1}})
	require.Error(t, err)
	err = SetRecordMetadata(org, "playbook", orgB, "k", nil)
	require.Error(t, err)
	_, err = SetRecord(org, RecordWrite{HiveName: "../x", Key: "k"})
	require.Error(t, err)
	assert.Empty(t, fakeAPI.Requests())

	// The control: the organization's own partition, explicit or implied, goes through.
	_, err = SetRecord(org, RecordWrite{HiveName: "playbook", PartitionKey: orgA, Key: "k", Data: map[string]interface{}{"a": 1}})
	require.NoError(t, err)
	_, err = SetRecord(org, RecordWrite{HiveName: "playbook", Key: "k", Data: map[string]interface{}{"a": 1}})
	require.NoError(t, err)
	for _, r := range fakeAPI.Requests() {
		assert.Contains(t, r.Path, orgA)
		assert.NotContains(t, r.Path, orgB)
	}
}
