package tools_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	// Every tool package registers itself in init(); import them all so the
	// registry holds the full catalog the server ships.
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/admin"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/ai"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/api"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/artifacts"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/cases"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/cloudsec"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/config"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/core"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/feedback"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/forensics"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/historical"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/hive"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/investigation"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/mailsec"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/payloads"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/replay"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/response"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/rules"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/schemas"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/vulnerability"
)

func sortedToolNames() []string {
	names := tools.GetAllRegisteredToolNames()
	sort.Strings(names)
	return names
}

// A tool without a classification would ship with mcp-go's defaults (notably
// openWorldHint=true), which is exactly what this table exists to prevent. A
// stale entry for a tool that no longer exists is just as wrong: it hides that a
// rename silently dropped the classification of the new name.
func TestEveryRegisteredToolIsClassified(t *testing.T) {
	registered := map[string]bool{}
	for _, name := range sortedToolNames() {
		registered[name] = true
		_, ok := tools.AnnotationFor(name)
		assert.True(t, ok, "tool %q has no entry in toolAnnotations (internal/tools/annotations_table.go): add its readOnly/destructive/idempotent/openWorld classification", name)
	}
	for _, name := range tools.ClassifiedToolNames() {
		assert.True(t, registered[name], "toolAnnotations has an entry for %q but no such tool is registered", name)
	}
}

// What clients see (tools/list, stdio, the scope policy) is ToolSchema; all four
// hints must be present in its JSON so no client falls back to a spec default,
// and they must obey the invariants the OpenAI and Muse rules rely on.
func TestEveryToolListsExplicitHints(t *testing.T) {
	for _, name := range sortedToolNames() {
		reg, _ := tools.GetTool(name)
		raw, err := json.Marshal(reg.ToolSchema())
		require.NoError(t, err, name)
		var wire struct {
			Annotations map[string]any `json:"annotations"`
		}
		require.NoError(t, json.Unmarshal(raw, &wire), name)
		for _, hint := range []string{"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"} {
			v, ok := wire.Annotations[hint]
			require.True(t, ok, "%s: %s missing from tools/list output", name, hint)
			_, isBool := v.(bool)
			require.True(t, isBool, "%s: %s must be a boolean", name, hint)
		}

		a, _ := tools.AnnotationFor(name)
		assert.Equal(t, a.ReadOnly, wire.Annotations["readOnlyHint"], name)
		assert.Equal(t, a.Destructive, wire.Annotations["destructiveHint"], name)
		assert.Equal(t, a.Idempotent, wire.Annotations["idempotentHint"], name)
		assert.Equal(t, a.OpenWorld, wire.Annotations["openWorldHint"], name)

		if a.ReadOnly {
			assert.False(t, a.Destructive, "%s: a read-only tool cannot be destructive", name)
			assert.False(t, a.Idempotent, "%s: idempotentHint is only meaningful for non-read-only tools", name)
		}
	}
}

// The OAuth scope policy reads the schema's readOnlyHint, and the table
// overrides whatever a tool declares. A tool whose own declaration disagrees
// would read as one thing in its source and behave as another, so the
// security-relevant hint must agree in both places.
func TestDeclaredReadOnlyMatchesTable(t *testing.T) {
	for _, name := range sortedToolNames() {
		reg, _ := tools.GetTool(name)
		a, _ := tools.AnnotationFor(name)
		declared := reg.DeclaredSchemaForTest().Annotations.ReadOnlyHint
		require.NotNil(t, declared, name)
		assert.Equal(t, a.ReadOnly, *declared,
			"%s: the tool declares readOnlyHint=%v in its source but annotations_table.go says %v; make them agree", name, *declared, a.ReadOnly)
	}
}

// A profile named *_readonly promises no write is reachable through it.
func TestReadOnlyProfilesContainOnlyReadOnlyTools(t *testing.T) {
	for profile, names := range tools.ProfileDefinitions {
		if !strings.HasSuffix(profile, "_readonly") {
			continue
		}
		for _, name := range names {
			a, ok := tools.AnnotationFor(name)
			if !ok {
				continue // not implemented in this build
			}
			assert.True(t, a.ReadOnly, "profile %s exposes %s, which is not read-only", profile, name)
		}
	}
}

// Pin the classification of the high-risk tools. These are the labels a
// reviewer or a platform submission cares about most; a change to any of them
// must be a conscious edit of this test.
func TestHighRiskToolClassification(t *testing.T) {
	type want struct {
		ro, destructive, idempotent, openWorld bool
		muse                                   string
	}
	cases := map[string]want{
		// Sensor tasking that changes state or runs arbitrary commands.
		"task_sensor":                   {false, true, false, true, "Sensitive write"},
		"reliable_tasking":              {false, true, false, true, "Sensitive write"},
		"isolate_network":               {false, true, true, true, "Sensitive write"},
		"rejoin_network":                {false, false, true, true, "Write"},
		"unseal_sensor":                 {false, true, true, true, "Sensitive write"},
		"collect_velociraptor_artifact": {false, true, false, true, "Sensitive write"},
		"memory_dump_sensor":            {false, false, false, true, "Write"},
		// Sensor introspection: reads on a real endpoint, so read-only but open world.
		"get_processes":           {true, false, false, true, "Read"},
		"yara_scan_file":          {true, false, false, true, "Read"},
		"dir_list":                {true, false, false, true, "Read"},
		"get_network_connections": {true, false, false, true, "Read"},
		// Deletes.
		"delete_sensor":           {false, true, true, false, "Sensitive write"},
		"delete_org":              {false, true, true, false, "Sensitive write"},
		"delete_rule":             {false, true, true, false, "Sensitive write"},
		"delete_secret":           {false, true, true, false, "Sensitive write"},
		"delete_output":           {false, true, true, false, "Sensitive write"},
		"mailsec_purge_tenant":    {false, true, true, true, "Sensitive write"},
		"mailsec_test_connection": {false, true, true, true, "Sensitive write"},
		// invite_missing emails an invite to an external address on every call.
		"add_org_user":     {false, false, false, true, "Write"},
		"add_group_member": {false, false, false, true, "Write"},
		"set_user_role":    {false, true, true, false, "Sensitive write"},
		// Third-party model API / internet fetches: read-only but open world.
		"generate_lcql_query":         {true, false, false, true, "Read"},
		"list_velociraptor_artifacts": {true, false, false, true, "Read"},
		"resolve_arl":                 {true, false, false, true, "Read"},
		// Outputs send org data to third-party destinations.
		"add_output": {false, true, true, true, "Sensitive write"},
		// Overwrites.
		"set_rule":   {false, true, true, false, "Sensitive write"},
		"set_secret": {false, true, true, false, "Sensitive write"},
		// Additive writes.
		"add_tag":       {false, false, true, false, "Write"},
		"create_case":   {false, false, false, false, "Write"},
		"add_case_note": {false, false, false, false, "Write"},
		// Reads inside the org.
		"list_sensors":   {true, false, false, false, "Read"},
		"get_org_info":   {true, false, false, false, "Read"},
		"list_outputs":   {true, false, false, false, "Read"},
		"run_lcql_query": {true, false, false, false, "Read"},
		// Meta tool: worst case of anything it can dispatch.
		"lc_call_tool": {false, true, false, true, "Sensitive write"},
	}
	for name, w := range cases {
		a, ok := tools.AnnotationFor(name)
		require.True(t, ok, name)
		assert.Equal(t, w.ro, a.ReadOnly, "%s readOnly", name)
		assert.Equal(t, w.destructive, a.Destructive, "%s destructive", name)
		assert.Equal(t, w.idempotent, a.Idempotent, "%s idempotent", name)
		assert.Equal(t, w.openWorld, a.OpenWorld, "%s openWorld", name)
		assert.Equal(t, w.muse, a.MuseClass(), "%s Muse class", name)
	}
}

// TestEveryRegisteredToolIsClassified only sees tools whose package this file
// imports. Fail when a tool package exists that either this test or the server
// binary does not import, so a new package cannot dodge the classification check.
func TestAllToolPackagesAreImported(t *testing.T) {
	self, err := os.ReadFile("annotations_test.go")
	require.NoError(t, err)
	server, err := os.ReadFile(filepath.Join("..", "..", "cmd", "server", "main.go"))
	require.NoError(t, err)

	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "testutil" {
			continue
		}
		goFiles, _ := filepath.Glob(filepath.Join(e.Name(), "*.go"))
		hasCode := false
		for _, f := range goFiles {
			if !strings.HasSuffix(f, "_test.go") {
				hasCode = true
			}
		}
		if !hasCode {
			continue
		}
		pkg := "internal/tools/" + e.Name() + `"`
		assert.Contains(t, string(self), pkg, "annotations_test.go must blank-import tool package %s", e.Name())
		assert.Contains(t, string(server), pkg, "cmd/server/main.go does not import tool package %s", e.Name())
	}
}
