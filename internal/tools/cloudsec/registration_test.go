package cloudsec

import (
	"sort"
	"strings"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readOnlyTools are the cloudsec.get tools — the exact membership of the
// cloud_security_readonly profile. Four of them are POSTs (the graph query, the
// policy-value suggester and the two simulate previews) which the gateway serves as
// read-only previews, so they belong here despite the verb.
var readOnlyTools = []string{
	// posture
	"cloudsec_get_overview",
	"cloudsec_get_risk_trend",
	"cloudsec_list_changes",
	"cloudsec_get_scan_status",
	"cloudsec_get_topology",
	"cloudsec_list_chokepoints",
	// findings
	"cloudsec_list_findings",
	"cloudsec_get_finding_facets",
	"cloudsec_get_finding",
	"cloudsec_list_finding_classes",
	"cloudsec_list_attack_paths",
	"cloudsec_list_finding_causes",
	// identity / CIEM
	"cloudsec_get_public_access",
	"cloudsec_get_identity",
	"cloudsec_get_identity_facets",
	"cloudsec_list_identities",
	// inventory / data security / graph
	"cloudsec_list_inventory",
	"cloudsec_get_inventory_facets",
	"cloudsec_get_data_security_facets",
	"cloudsec_list_data_stores",
	"cloudsec_get_resource",
	"cloudsec_get_graph_neighbors",
	"cloudsec_list_queries",
	// compliance
	"cloudsec_get_compliance_report",
	"cloudsec_list_compliance_frameworks",
	"cloudsec_list_compliance_assignments",
	// CAASM
	"cloudsec_list_caasm_assets",
	"cloudsec_list_caasm_coverage",
	"cloudsec_get_caasm_policy",
	"cloudsec_get_provider_manifests",
	// policy authoring aids
	"cloudsec_get_policy_vocabulary",
	"cloudsec_suggest_policy_values",
	"cloudsec_simulate_resource_match",
	"cloudsec_simulate_finding_match",
	"cloudsec_run_query",
	// resolution
	"cloudsec_resolve_sensors",
	"cloudsec_resolve_assets",
	// export
	"cloudsec_export_csv",
	// free tier / fleet
	"cloudsec_get_free_tier_status",
	"cloudsec_get_fleet_overview",
}

// writeTools are the cloudsec.set tools, with the destructive classification each
// one carries.
var writeTools = map[string]bool{
	"cloudsec_set_finding_status":      true,  // changes a finding's disposition
	"cloudsec_bulk_set_finding_status": true,  // same, over a batch
	"cloudsec_set_finding_owner":       false, // assignment metadata
	"cloudsec_set_finding_ticket":      false, // linkage metadata
	"cloudsec_dismiss_chokepoint":      true,  // hides an estate-wide risk
	"cloudsec_restore_chokepoint":      false, // undoes a dismissal
	"cloudsec_set_caasm_policy":        true,  // upsert replaces the whole policy
	"cloudsec_ingest_caasm_records":    false, // idempotent merge
	"cloudsec_test_provider":           false, // probe only, nothing persisted
}

// noOIDTools do not take an organization: the fleet board's route carries no {oid}
// and the gateway resolves the org set from the caller's own token.
var noOIDTools = map[string]bool{
	"cloudsec_get_fleet_overview": true,
}

func allToolNames() []string {
	names := append([]string{}, readOnlyTools...)
	for name := range writeTools {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func TestCloudSecToolRegistration(t *testing.T) {
	for _, name := range allToolNames() {
		t.Run(name, func(t *testing.T) {
			reg, exists := tools.GetTool(name)
			require.True(t, exists, "tool %s should be registered", name)
			require.NotNil(t, reg)

			assert.Equal(t, profileName, reg.Profile)
			assert.NotNil(t, reg.Handler)
			assert.NotEmpty(t, reg.Description)
			assert.Equal(t, name, reg.Schema.Name)
			assert.Equal(t, !noOIDTools[name], reg.RequiresOID,
				"RequiresOID must be false only for the routes with no {oid}")

			// Every description must carry the extension-gate remedy: a 403 from the
			// enable gate is the single most likely failure and it has a one-step fix.
			assert.Contains(t, reg.Description, "subscribe_to_extension",
				"description should name the ext-cloud-security remedy")
		})
	}
}

func TestCloudSecAnnotations(t *testing.T) {
	t.Run("reads are read-only and not destructive", func(t *testing.T) {
		for _, name := range readOnlyTools {
			reg, exists := tools.GetTool(name)
			require.True(t, exists, name)
			require.NotNil(t, reg.Schema.Annotations.ReadOnlyHint, "%s: missing read-only hint", name)
			assert.True(t, *reg.Schema.Annotations.ReadOnlyHint, name)
			// NewTool defaults DestructiveHint to true, so leaving it alone would
			// ship "read-only AND destructive" on every read.
			require.NotNil(t, reg.Schema.Annotations.DestructiveHint, name)
			assert.False(t, *reg.Schema.Annotations.DestructiveHint,
				"%s: a read-only tool must not be advertised as destructive", name)
		}
	})

	t.Run("writes carry the destructive classification and are not read-only", func(t *testing.T) {
		for name, destructive := range writeTools {
			reg, exists := tools.GetTool(name)
			require.True(t, exists, name)
			require.NotNil(t, reg.Schema.Annotations.ReadOnlyHint, name)
			assert.False(t, *reg.Schema.Annotations.ReadOnlyHint,
				"%s: a write must not claim to be read-only", name)
			require.NotNil(t, reg.Schema.Annotations.DestructiveHint, "%s: missing destructive hint", name)
			assert.Equal(t, destructive, *reg.Schema.Annotations.DestructiveHint, name)
		}
	})
}

// Every cloudsec tool is registered from this package's init(), so a name that shows
// up in the registry without being in the inventory above would also be missing from
// the profile lists and silently unreachable.
func TestNoUnlistedCloudSecTools(t *testing.T) {
	known := map[string]bool{}
	for _, name := range allToolNames() {
		known[name] = true
	}

	var unlisted []string
	for _, name := range tools.GetAllRegisteredToolNames() {
		if strings.HasPrefix(name, "cloudsec_") && !known[name] {
			unlisted = append(unlisted, name)
		}
	}
	assert.Empty(t, unlisted, "cloudsec tools missing from the inventory (and therefore from the profiles)")
}

// The configuration-adjacent tools are the only path an agent has to discover that
// providers, policies and saved queries are hive records rather than API routes.
func TestConfigurationToolsPointAtTheHives(t *testing.T) {
	for _, name := range []string{
		"cloudsec_get_scan_status",
		"cloudsec_get_provider_manifests",
		"cloudsec_get_policy_vocabulary",
		"cloudsec_suggest_policy_values",
		"cloudsec_simulate_resource_match",
		"cloudsec_simulate_finding_match",
		"cloudsec_run_query",
		"cloudsec_list_queries",
		"cloudsec_test_provider",
		"cloudsec_get_free_tier_status",
	} {
		reg, exists := tools.GetTool(name)
		require.True(t, exists, name)
		assert.True(t,
			strings.Contains(reg.Description, "cloudsec_provider") ||
				strings.Contains(reg.Description, "cloudsec_policy") ||
				strings.Contains(reg.Description, "cloudsec_query"),
			"%s should name the hive its configuration lives in", name)
	}
}
