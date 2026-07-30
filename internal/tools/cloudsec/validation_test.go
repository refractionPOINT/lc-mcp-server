package cloudsec

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The gateway forwards whichever of named/text/query the body carries and lets the
// backend decide, so ambiguity has to be caught here or a caller spends a round-trip
// (and an empty text spends one to learn nothing).
func TestQueryBodyRequiresExactlyOneSelector(t *testing.T) {
	t.Run("named alone", func(t *testing.T) {
		body, errResult := queryBody(map[string]interface{}{"named": "public_data_stores"})
		require.Nil(t, errResult)
		assert.Equal(t, map[string]interface{}{"named": "public_data_stores"}, body)
	})

	t.Run("none supplied", func(t *testing.T) {
		_, errResult := queryBody(map[string]interface{}{})
		require.NotNil(t, errResult)
	})

	t.Run("two supplied", func(t *testing.T) {
		_, errResult := queryBody(map[string]interface{}{"named": "a", "text": "MATCH (n) RETURN n"})
		require.NotNil(t, errResult)
	})

	t.Run("explicitly empty text is rejected, not treated as absent", func(t *testing.T) {
		_, errResult := queryBody(map[string]interface{}{"text": ""})
		require.NotNil(t, errResult)
	})

	t.Run("query object passes through", func(t *testing.T) {
		body, errResult := queryBody(map[string]interface{}{
			"query": map[string]interface{}{"match": "DataStore"},
		})
		require.Nil(t, errResult)
		assert.Equal(t, map[string]interface{}{"match": "DataStore"}, body["query"])
	})

	t.Run("query supplied as a JSON string decodes", func(t *testing.T) {
		body, errResult := queryBody(map[string]interface{}{"query": `{"match":"DataStore"}`})
		require.Nil(t, errResult)
		assert.Equal(t, map[string]interface{}{"match": "DataStore"}, body["query"])
	})

	t.Run("a JSON array is not an object", func(t *testing.T) {
		_, errResult := queryBody(map[string]interface{}{"query": `["DataStore"]`})
		require.NotNil(t, errResult)
	})

	t.Run("project accepts only graph", func(t *testing.T) {
		body, errResult := queryBody(map[string]interface{}{"named": "a", "project": "graph"})
		require.Nil(t, errResult)
		assert.Equal(t, "graph", body["project"])

		_, errResult = queryBody(map[string]interface{}{"named": "a", "project": "table"})
		require.NotNil(t, errResult)
	})

	t.Run("an empty project is treated as unset", func(t *testing.T) {
		body, errResult := queryBody(map[string]interface{}{"named": "a", "project": ""})
		require.Nil(t, errResult)
		assert.NotContains(t, body, "project")
	})
}

func TestResolutionBody(t *testing.T) {
	t.Run("kind plus an optional reason", func(t *testing.T) {
		res, errResult := resolutionBody(map[string]interface{}{
			"kind":   "mitigated",
			"reason": "firewall rule removed",
		}, true)
		require.Nil(t, errResult)
		assert.Equal(t, "mitigated", res["kind"])
		assert.Equal(t, "firewall rule removed", res["reason"])
		assert.NotContains(t, res, "expires_at")
	})

	t.Run("expires_at is forwarded as supplied seconds", func(t *testing.T) {
		res, errResult := resolutionBody(map[string]interface{}{
			"kind":       "accepted",
			"expires_at": float64(1785000000),
		}, true)
		require.Nil(t, errResult)
		assert.Equal(t, 1785000000, res["expires_at"])
	})

	t.Run("open reopens on the single-finding route", func(t *testing.T) {
		res, errResult := resolutionBody(map[string]interface{}{"kind": "open"}, true)
		require.Nil(t, errResult)
		assert.Equal(t, "open", res["kind"])
	})

	t.Run("open is refused for a bulk disposition", func(t *testing.T) {
		_, errResult := resolutionBody(map[string]interface{}{"kind": "open"}, false)
		require.NotNil(t, errResult)
	})

	t.Run("an unknown kind is refused", func(t *testing.T) {
		_, errResult := resolutionBody(map[string]interface{}{"kind": "wontfix"}, true)
		require.NotNil(t, errResult)
	})

	t.Run("a missing kind is refused", func(t *testing.T) {
		_, errResult := resolutionBody(map[string]interface{}{}, true)
		require.NotNil(t, errResult)
	})
}

func TestTruncateCSV(t *testing.T) {
	const doc = "a,b\n1,2\n3,4\n"

	t.Run("a document within budget is untouched", func(t *testing.T) {
		assert.Equal(t, doc, truncateCSV(doc, 1024))
		assert.Equal(t, doc, truncateCSV(doc, 0))
	})

	t.Run("a cut lands on a row boundary and is announced", func(t *testing.T) {
		got := truncateCSV(doc, 9)
		assert.True(t, strings.HasPrefix(got, "a,b\n1,2\n"), "got %q", got)
		assert.NotContains(t, got, "3,4")
		assert.Contains(t, got, "# truncated by lc-mcp-server")
		assert.True(t, strings.HasSuffix(got, "\n"))
	})

	t.Run("a single row longer than the budget keeps the budget's worth", func(t *testing.T) {
		got := truncateCSV("aaaaaaaaaaaaaaaaaaaa", 5)
		assert.True(t, strings.HasPrefix(got, "aaaaa"))
		assert.Contains(t, got, "# truncated by lc-mcp-server")
	})
}

func TestDescribeErrAddsSubscribeRemedy(t *testing.T) {
	err := &apiError{
		Status: 403,
		Body:   `{"error":"cloud security is not enabled for this organization; subscribe to the \"ext-cloud-security\" extension to enable it"}`,
	}
	got := describeErr(err)
	assert.Contains(t, got, "subscribe_to_extension")

	assert.NotContains(t, describeErr(&apiError{Status: 500, Body: "backend unavailable"}), "subscribe_to_extension")
}
