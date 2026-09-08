package cloudsec

import (
	"context"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findingsRepoTools are the tools whose gateway route accepts the `repo` selector
// (addCloudSecFindingParams, lc_api-go/service/endpoint_cloudsec.go — the list, the
// facets, the cause rollup and the CSV export all share that one forwarder). The
// parity gap this file pins is that the schema advertised none of them.
var findingsRepoTools = []string{
	"cloudsec_list_findings",
	"cloudsec_get_finding_facets",
	"cloudsec_list_finding_causes",
	"cloudsec_export_csv",
}

// resultText flattens a tool result's text content so a test can assert on what the
// caller is actually told.
func resultText(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if t, ok := c.(mcp.TextContent); ok {
			b.WriteString(t.Text)
		}
	}
	return b.String()
}

// The selector has to be VISIBLE to be usable: a model can only pass a parameter the
// advertised schema declares, so forwarding logic alone would leave the gap open.
func TestFindingToolsAdvertiseTheRepoSelector(t *testing.T) {
	for _, name := range findingsRepoTools {
		t.Run(name, func(t *testing.T) {
			reg, exists := tools.GetTool(name)
			require.True(t, exists, name)

			prop, declared := reg.Schema.InputSchema.Properties["repo"]
			require.True(t, declared, "%s must declare the 'repo' filter its gateway route accepts", name)

			spec, ok := prop.(map[string]any)
			require.True(t, ok, "%s: 'repo' should be a JSON-schema object", name)
			assert.Equal(t, "array", spec["type"], "%s: 'repo' is repeatable on the wire", name)
			items, ok := spec["items"].(map[string]any)
			require.True(t, ok, "%s: 'repo' should declare its item type", name)
			assert.Equal(t, "string", items["type"], name)

			// The fold is a client-side behavior the caller cannot see in the response,
			// so it has to be stated where the caller reads the parameter. Without it a
			// display-cased key looks like a filter that simply found nothing.
			desc, _ := spec["description"].(string)
			assert.Contains(t, desc, "LOWER-CASED",
				"%s: the description must say the value is folded before it is sent", name)
		})
	}
}

// The facets response has carried a `repo` dimension since the code lane landed
// (legion_graph findingstore.FacetResult.Repo / RepoTruncated). It is the only way to
// discover the keys the filter takes without paging the worklist, so a description
// that does not mention it hides the discovery step behind a tool the caller has no
// reason to reach for.
func TestFacetsToolDocumentsTheRepoDimension(t *testing.T) {
	reg, exists := tools.GetTool("cloudsec_get_finding_facets")
	require.True(t, exists)

	assert.Contains(t, reg.Description, "'repo' facet")
	assert.Contains(t, reg.Description, "repo_truncated",
		"the cap has to be reported or a missing repository reads as a zero count")
}

// The fold is what makes the filter work at all: the backend matches the stored key
// exactly, and that key is the repository urn's ASCII-lower-cased owner/name
// (go-cloudsec model.BuildRepoURN / FoldRepoSegment). A key taken from a finding's
// display fields, an SCM page or a hive record routinely carries other casing.
func TestFindingRepoValuesFoldsToTheStoredKey(t *testing.T) {
	got, errResult := findingRepoValues(map[string]interface{}{
		"repo": []interface{}{"Acme/API", "acme/web"},
	})
	require.Nil(t, errResult)
	assert.Equal(t, []string{"acme/api", "acme/web"}, got)

	t.Run("surrounding whitespace is trimmed, not folded into the key", func(t *testing.T) {
		got, errResult := findingRepoValues(map[string]interface{}{"repo": "  Acme/API  "})
		require.Nil(t, errResult)
		assert.Equal(t, []string{"acme/api"}, got)
	})

	t.Run("the fold is ASCII-only, like the backend's", func(t *testing.T) {
		// strings.ToLower would rewrite these bytes; the urn builder does not, so
		// folding them here would produce a key no repository ever had.
		got, errResult := findingRepoValues(map[string]interface{}{"repo": "ÉQUIPE/Ünicode-REPO"})
		require.Nil(t, errResult)
		assert.Equal(t, []string{"Équipe/Ünicode-repo"}, got)
	})

	t.Run("each segment is trimmed, not just the whole key", func(t *testing.T) {
		// "acme / api" survives a whole-key trim with both halves non-empty and no inner
		// slash, so it would pass every shape check and then match zero rows silently.
		got, errResult := findingRepoValues(map[string]interface{}{"repo": "Acme / API"})
		require.Nil(t, errResult)
		assert.Equal(t, []string{"acme/api"}, got)
	})

	t.Run("absent leaves the dimension unconstrained", func(t *testing.T) {
		got, errResult := findingRepoValues(map[string]interface{}{"severity": []interface{}{"HIGH"}})
		require.Nil(t, errResult)
		assert.Nil(t, got)
	})
}

// Every rejection below would otherwise be a SILENT WIDENING. `repo` has no "any
// repository" value — a finding with no repository is every cloud finding in the
// estate — so a value that cannot be used has to end the call rather than be dropped,
// or the caller gets the whole worklist back under a filter it believes it applied.
func TestFindingRepoValuesRejectsRatherThanWidens(t *testing.T) {
	cases := map[string]interface{}{
		"blank":                  []interface{}{""},
		"whitespace only":        "   ",
		"blank among real keys":  []interface{}{"acme/api", ""},
		"no owner segment":       "api",
		"empty owner segment":    "/api",
		"empty name segment":     "acme/",
		"three segments":         "acme/team/api",
		"empty list":             []interface{}{},
		"not a string or a list": float64(7),
		"an object":              map[string]interface{}{"owner": "acme"},
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			got, errResult := findingRepoValues(map[string]interface{}{"repo": value})
			require.NotNil(t, errResult, "%s must be refused, not dropped", name)
			assert.Nil(t, got)
			assert.True(t, errResult.IsError)
			assert.Contains(t, resultText(errResult), "repo")
		})
	}

	// argStrings drops an element it cannot turn into a scalar, which for this selector
	// is a PARTIAL application: the read runs scoped to fewer repositories than were
	// asked for and nothing in the response says so.
	t.Run("an unusable element is not silently skipped", func(t *testing.T) {
		got, errResult := findingRepoValues(map[string]interface{}{
			"repo": []interface{}{"acme/api", map[string]interface{}{"owner": "acme", "name": "web"}},
		})
		require.NotNil(t, errResult)
		assert.Nil(t, got)
		assert.Contains(t, resultText(errResult), "not repository keys")
	})

	// The control: the same shapes minus the defect are accepted, so the assertions
	// above are testing the validation and not something that refuses everything.
	got, errResult := findingRepoValues(map[string]interface{}{"repo": []interface{}{"acme/api"}})
	require.Nil(t, errResult)
	assert.Equal(t, []string{"acme/api"}, got)
}

// `repo` is declarable on every export dataset because it arrives through the shared
// findings selector, but only the findings walk has the column. Ignoring it there would
// export the whole estate under a filter the caller believes it applied — the same
// silent widening the findings path refuses.
func TestExportRefusesARepoOnADatasetThatHasNone(t *testing.T) {
	reg, exists := tools.GetTool("cloudsec_export_csv")
	require.True(t, exists)

	for _, dataset := range []string{"inventory", "compliance", "query"} {
		t.Run(dataset, func(t *testing.T) {
			res, err := reg.Handler(context.Background(), map[string]interface{}{
				"dataset": dataset,
				"repo":    []interface{}{"acme/api"},
			})
			require.NoError(t, err)
			text := resultText(res)
			assert.Contains(t, text, "'repo' filter applies only to dataset=findings")
			assert.NotContains(t, text, "failed to get organization",
				"the refusal must precede the credential lookup")
		})
	}

	// The control: the same repo on the dataset that HAS the column is accepted and the
	// call proceeds into the request path.
	res, err := reg.Handler(context.Background(), map[string]interface{}{
		"dataset": "findings",
		"repo":    []interface{}{"acme/api"},
	})
	require.NoError(t, err)
	assert.Contains(t, resultText(res), "organization")
}

// The selector must reach the WIRE in the repeated-key form the gateway's filters read,
// on the paged route and the export alike — those two are meant to describe the same
// filtered set.
func TestAddFindingSelectorCarriesTheFoldedRepo(t *testing.T) {
	for _, paging := range []bool{true, false} {
		dst := lc.Dict{}
		errResult := addFindingSelector(dst, map[string]interface{}{
			"repo":     []interface{}{"Acme/API", "Acme/Web"},
			"severity": []interface{}{"HIGH"},
		}, paging)
		require.Nil(t, errResult)
		assert.Equal(t, []string{"acme/api", "acme/web"}, dst["repo"])
		assert.Equal(t, []string{"HIGH"}, dst["severity"])

		values := queryValues(dst)
		assert.Equal(t, []string{"acme/api", "acme/web"}, values["repo"])
		assert.Contains(t, values.Encode(), "repo=acme%2Fapi&repo=acme%2Fweb")
	}

	t.Run("a bad repo stops the whole selector", func(t *testing.T) {
		dst := lc.Dict{}
		errResult := addFindingSelector(dst, map[string]interface{}{"repo": []interface{}{"acme"}}, true)
		require.NotNil(t, errResult)
		assert.NotContains(t, dst, "repo")
	})
}

// End to end through the registered handlers: a bad `repo` is refused BEFORE anything
// is sent. The control is what makes that provable here — the same call with a valid
// repository gets past validation and fails on the missing organization instead, which
// is the first thing the request path does.
func TestFindingHandlersRejectABadRepoBeforeAnyRequest(t *testing.T) {
	for _, name := range findingsRepoTools {
		t.Run(name, func(t *testing.T) {
			reg, exists := tools.GetTool(name)
			require.True(t, exists, name)

			args := map[string]interface{}{"repo": []interface{}{"acme"}}
			if name == "cloudsec_export_csv" {
				args["dataset"] = "findings"
			}

			res, err := reg.Handler(context.Background(), args)
			require.NoError(t, err)
			require.NotNil(t, res)
			text := resultText(res)
			assert.Contains(t, text, "acme", "the refusal must name the value it refused")
			assert.NotContains(t, text, "failed to get organization",
				"%s: validation must run before the organization is resolved, i.e. before any request", name)

			args["repo"] = []interface{}{"acme/api"}
			res, err = reg.Handler(context.Background(), args)
			require.NoError(t, err)
			assert.Contains(t, resultText(res), "organization",
				"%s: a valid repo must get past validation into the request path", name)
		})
	}
}
