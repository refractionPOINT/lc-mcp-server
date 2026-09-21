package cloudsec

import (
	"context"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestIaCSelectorsPreserveFalseAndVerdicts(t *testing.T) {
	for _, finding := range []bool{false, true} {
		dst := lc.Dict{}
		args := map[string]interface{}{"has_iac_origin": false}
		if finding {
			args["iac_attribution"] = []interface{}{"unknown", "ambiguous"}
		}
		require.Nil(t, addIaCSelectors(dst, args, finding))
		require.Equal(t, false, dst["has_iac_origin"])
		if finding {
			require.Equal(t, []string{"unknown", "ambiguous"}, dst["iac_attribution"])
		}
	}
	dst := lc.Dict{}
	require.Nil(t, addIaCSelectors(dst, map[string]interface{}{}, true))
	require.Empty(t, dst)
}

func TestIaCSelectorsRejectMalformedValues(t *testing.T) {
	for _, value := range []interface{}{nil, "false", 0, 1, []interface{}{}, map[string]interface{}{}} {
		result := addIaCSelectors(lc.Dict{}, map[string]interface{}{"has_iac_origin": value}, true)
		require.NotNil(t, result)
		require.True(t, result.IsError)
	}
	for _, value := range []interface{}{nil, "unknown", []string{}, []string{"safe"}, []string{"UNKNOWN"}, []string{"unknown", "unknown", "unknown", "unknown", "unknown"}, []interface{}{false}, []interface{}{map[string]interface{}{}}} {
		result := addIaCSelectors(lc.Dict{}, map[string]interface{}{"iac_attribution": value}, true)
		require.NotNil(t, result)
		require.True(t, result.IsError)
	}
	require.NotNil(t, addInventorySelector(lc.Dict{}, map[string]interface{}{"iac_attribution": []string{"unknown"}}))
}

func TestIaCToolsAdvertiseSelectors(t *testing.T) {
	for _, name := range append(append([]string{}, findingsRepoTools...), "cloudsec_list_inventory", "cloudsec_get_inventory_facets") {
		reg, ok := tools.GetTool(name)
		require.True(t, ok)
		require.Contains(t, reg.Schema.InputSchema.Properties, "has_iac_origin")
	}
	for _, name := range findingsRepoTools {
		reg, _ := tools.GetTool(name)
		require.Contains(t, reg.Schema.InputSchema.Properties, "iac_attribution")
	}
}

func TestIaCExportRejectsWrongDatasetWithoutCredentials(t *testing.T) {
	for _, dataset := range []string{"inventory", "compliance", "query"} {
		result, err := handleExportCSV(context.Background(), map[string]interface{}{"dataset": dataset, "iac_attribution": []string{"unknown"}})
		require.NoError(t, err)
		require.True(t, result.IsError)
		require.Contains(t, resultText(result), "only to dataset=findings")
	}
	for _, dataset := range []string{"compliance", "query"} {
		result, err := handleExportCSV(context.Background(), map[string]interface{}{"dataset": dataset, "has_iac_origin": false})
		require.NoError(t, err)
		require.True(t, result.IsError)
		require.Contains(t, resultText(result), "findings or inventory")
	}
}

func FuzzIaCAttributionRejectsUnknown(f *testing.F) {
	for _, value := range []string{"unknown", "safe", "attributed", "ambiguous", "none", "", "UNKNOWN"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		result := addIaCSelectors(lc.Dict{}, map[string]interface{}{"iac_attribution": []string{value}}, true)
		valid := value == "unknown" || value == "attributed" || value == "ambiguous" || value == "none"
		if valid {
			require.Nil(t, result)
		} else {
			require.NotNil(t, result)
			require.True(t, result.IsError)
		}
	})
}

func TestIaCHandlersCannotTakeTenantFromArguments(t *testing.T) {
	for _, name := range append(append([]string{}, findingsRepoTools...), "cloudsec_list_inventory", "cloudsec_get_inventory_facets") {
		reg, ok := tools.GetTool(name)
		require.True(t, ok)
		args := map[string]interface{}{"oid": "foreign-tenant", "has_iac_origin": false}
		if name == "cloudsec_export_csv" {
			args["dataset"] = "findings"
		}
		result, err := reg.Handler(context.Background(), args)
		require.NoError(t, err)
		require.True(t, result.IsError)
		require.Contains(t, resultText(result), "organization")
		args["has_iac_origin"] = "false"
		result, err = reg.Handler(context.Background(), args)
		require.NoError(t, err)
		require.True(t, result.IsError)
		require.Contains(t, resultText(result), "must be a boolean")
		require.NotContains(t, resultText(result), "foreign-tenant")
	}
}
