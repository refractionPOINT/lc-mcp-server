package cloudsec

import (
	"testing"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The empty string is a real selection for several gateway dimensions (owner="" is
// the unassigned findings bucket, an empty posture_* value selects assets no source
// reported that fact for), so it must survive extraction and encoding.
func TestArgStringsPreservesEmptyElements(t *testing.T) {
	t.Run("lone empty element survives", func(t *testing.T) {
		got, ok := argStrings(map[string]interface{}{"owner": []interface{}{""}}, "owner")
		require.True(t, ok)
		assert.Equal(t, []string{""}, got)
	})

	t.Run("empty element among named owners survives", func(t *testing.T) {
		got, ok := argStrings(map[string]interface{}{"owner": []interface{}{"a@b.c", ""}}, "owner")
		require.True(t, ok)
		assert.Equal(t, []string{"a@b.c", ""}, got)
	})

	t.Run("absent key is reported as absent", func(t *testing.T) {
		got, ok := argStrings(map[string]interface{}{}, "owner")
		assert.False(t, ok)
		assert.Nil(t, got)
	})

	t.Run("bare string is accepted as one element", func(t *testing.T) {
		got, ok := argStrings(map[string]interface{}{"severity": "HIGH"}, "severity")
		require.True(t, ok)
		assert.Equal(t, []string{"HIGH"}, got)
	})

	t.Run("non-string scalars are stringified, containers skipped", func(t *testing.T) {
		got, ok := argStrings(map[string]interface{}{
			"kind": []interface{}{"user", 7, true, map[string]interface{}{"a": 1}, []interface{}{"b"}, nil},
		}, "kind")
		require.True(t, ok)
		assert.Equal(t, []string{"user", "7", "true"}, got)
	})
}

// The nested-document params (a provider record, a coverage policy, a suppression
// matcher) frequently arrive already serialized, and an empty object is a real value
// for the finding simulator.
func TestArgMapAcceptsObjectsAndJSONStrings(t *testing.T) {
	t.Run("a decoded object passes through", func(t *testing.T) {
		got, ok := argMap(map[string]interface{}{"policy": map[string]interface{}{"expect": []interface{}{}}}, "policy")
		require.True(t, ok)
		assert.Contains(t, got, "expect")
	})

	t.Run("a JSON string decodes", func(t *testing.T) {
		got, ok := argMap(map[string]interface{}{"match": `{"max_severity":"LOW"}`}, "match")
		require.True(t, ok)
		assert.Equal(t, "LOW", got["max_severity"])
	})

	t.Run("an empty object is supplied, not absent", func(t *testing.T) {
		got, ok := argMap(map[string]interface{}{"match": map[string]interface{}{}}, "match")
		require.True(t, ok)
		assert.Empty(t, got)
	})

	t.Run("an absent key and a non-object are both refused", func(t *testing.T) {
		_, ok := argMap(map[string]interface{}{}, "match")
		assert.False(t, ok)

		_, ok = argMap(map[string]interface{}{"match": "not json"}, "match")
		assert.False(t, ok)

		_, ok = argMap(map[string]interface{}{"match": `["an","array"]`}, "match")
		assert.False(t, ok)
	})
}

// The export tool has to declare 'account' as an array for the findings dataset, so
// the inventory branch — where the gateway reads it single-valued — must still cope.
func TestArgScalarAcceptsEitherForm(t *testing.T) {
	assert.Equal(t, "prod", argScalar(map[string]interface{}{"account": "prod"}, "account"))
	assert.Equal(t, "prod", argScalar(map[string]interface{}{"account": []interface{}{"prod", "staging"}}, "account"))
	assert.Equal(t, "", argScalar(map[string]interface{}{}, "account"))
}

func TestAddStringsForwardsPresenceNotEmptiness(t *testing.T) {
	dst := lc.Dict{}
	addStrings(dst, map[string]interface{}{
		"owner":  []interface{}{""},
		"status": []interface{}{},
	}, "owner", "status", "account")

	assert.Equal(t, []string{""}, dst["owner"], "the unassigned bucket must be forwarded")
	assert.NotContains(t, dst, "status", "an empty array selects nothing and must not be forwarded")
	assert.NotContains(t, dst, "account")
}

// A tri-state boolean must only travel when supplied: the gateway reads an absent key
// as "unconstrained" and a forwarded false as "pin this dimension to false".
func TestAddTriStateOnlyForwardsSuppliedValues(t *testing.T) {
	dst := lc.Dict{}
	addTriState(dst, map[string]interface{}{
		"reachable": false,
		"admin":     true,
		"kev":       "yes", // not a bool: not a value the gateway would parse
	}, "reachable", "admin", "kev", "external")

	require.Contains(t, dst, "reachable")
	assert.Equal(t, false, dst["reachable"], "an explicit false must be forwarded, not dropped")
	assert.Equal(t, true, dst["admin"])
	assert.NotContains(t, dst, "kev", "a non-boolean must not be guessed at")
	assert.NotContains(t, dst, "external", "an absent tri-state leaves the dimension unconstrained")
}

func TestAddScalarsSkipsEmptyValues(t *testing.T) {
	dst := lc.Dict{}
	addScalars(dst, map[string]interface{}{"q": "", "sort": "severity"}, "q", "sort", "order")

	assert.NotContains(t, dst, "q", "the gateway reads a scalar q with q.Get and treats \"\" as unset")
	assert.Equal(t, "severity", dst["sort"])
	assert.NotContains(t, dst, "order")
}

func TestAddIntClampsAndSkips(t *testing.T) {
	args := map[string]interface{}{
		"limit":        float64(5000),
		"trend_days":   float64(30),
		"sample_limit": float64(0),
		"other":        float64(-3),
	}

	dst := lc.Dict{}
	addInt(dst, args, "limit", maxPageLimit)
	addInt(dst, args, "trend_days", 0)
	addInt(dst, args, "sample_limit", maxSampleLimit)
	addInt(dst, args, "other", 0)

	assert.Equal(t, maxPageLimit, dst["limit"], "a limit above the gateway cap is clamped, not rejected")
	assert.Equal(t, 30, dst["trend_days"])
	assert.NotContains(t, dst, "sample_limit", "a non-positive limit is omitted so the backend default applies")
	assert.NotContains(t, dst, "other")
}

// queryValues is the CSV export's encoder; it must produce the same wire form the
// SDK's getStringKV produces for the JSON reads, or an export would describe a
// different population than the list it mirrors.
func TestQueryValuesEncoding(t *testing.T) {
	t.Run("arrays become repeated keys and keep empty elements", func(t *testing.T) {
		values := queryValues(lc.Dict{"owner": []string{"a@b.c", ""}})
		assert.Equal(t, []string{"a@b.c", ""}, values["owner"])
		assert.Equal(t, "owner=a%40b.c&owner=", values.Encode())
	})

	t.Run("booleans travel as true/false", func(t *testing.T) {
		values := queryValues(lc.Dict{"reachable": false, "kev": true})
		assert.Equal(t, "false", values.Get("reachable"))
		assert.Equal(t, "true", values.Get("kev"))
	})

	t.Run("ints are not rendered in exponent form", func(t *testing.T) {
		values := queryValues(lc.Dict{"limit": 1000})
		assert.Equal(t, "1000", values.Get("limit"))
	})

	t.Run("interface arrays are expanded too", func(t *testing.T) {
		values := queryValues(lc.Dict{"severity": []interface{}{"HIGH", "LOW"}})
		assert.Equal(t, []string{"HIGH", "LOW"}, values["severity"])
	})
}

func TestAddFindingSelectorPagingSplit(t *testing.T) {
	args := map[string]interface{}{
		"severity": []interface{}{"HIGH"},
		"owner":    []interface{}{""},
		"kev":      true,
		"q":        "bucket",
		"cursor":   "tok",
		"limit":    float64(200),
	}

	withPaging := lc.Dict{}
	addFindingSelector(withPaging, args, true)
	assert.Equal(t, "tok", withPaging["cursor"])
	assert.Equal(t, 200, withPaging["limit"])

	// The CSV export walks the whole filtered set server-side and ignores paging, so
	// forwarding a cursor there would only mislead the caller.
	noPaging := lc.Dict{}
	addFindingSelector(noPaging, args, false)
	assert.NotContains(t, noPaging, "cursor")
	assert.NotContains(t, noPaging, "limit")
	assert.Equal(t, []string{"HIGH"}, noPaging["severity"])
	assert.Equal(t, []string{""}, noPaging["owner"])
	assert.Equal(t, true, noPaging["kev"])
	assert.Equal(t, "bucket", noPaging["q"])
}

// The AppSec code lane's producer selector reaches BOTH findings routes and stays a
// SCALAR. The scalar half is what a reviewer would get wrong: the sibling `source` on
// the identity tools is a repeatable array, so forwarding this one as a list would put
// a []string where the gateway reads a scalar and the filter would vanish — a silently
// unfiltered read under an active-looking selection.
func TestAddFindingSelectorForwardsTheProducerScalar(t *testing.T) {
	for _, paging := range []bool{true, false} {
		dst := lc.Dict{}
		addFindingSelector(dst, map[string]interface{}{"source": "hosted"}, paging)
		assert.Equal(t, "hosted", dst["source"])
	}

	// Absent means unconstrained, and must not reach the wire at all: an empty value
	// is an unrecognised producer at the backend, which matches nothing.
	dst := lc.Dict{}
	addFindingSelector(dst, map[string]interface{}{"severity": []interface{}{"HIGH"}}, false)
	assert.NotContains(t, dst, "source")

	// 'both' travels rather than being resolved locally — the server is what treats it
	// as no constraint, and only one place should know that.
	both := lc.Dict{}
	addFindingSelector(both, map[string]interface{}{"source": "both"}, false)
	assert.Equal(t, "both", both["source"])

	// The identity selector's `source` is the repeatable producing-SWEEP filter. Same
	// word, different shape, different routes — pinned so a future tidy-up cannot
	// merge them.
	ident := lc.Dict{}
	addIdentitySelector(ident, map[string]interface{}{"source": []interface{}{"okta", "gcp"}})
	assert.Equal(t, []string{"okta", "gcp"}, ident["source"])
}

func TestAddInventorySelectorKeepsPlacementScalar(t *testing.T) {
	dst := lc.Dict{}
	addInventorySelector(dst, map[string]interface{}{
		"type":             "compute_instance",
		"provider":         "gcp",
		"account_unscoped": false,
	})

	assert.Equal(t, "compute_instance", dst["type"])
	assert.Equal(t, "gcp", dst["provider"], "the generic inventory walk reads provider single-valued")
	assert.Equal(t, false, dst["account_unscoped"])
}

// The gateway upgrades the placement dimensions to their repeatable form only under
// type=Identity; forwarding an array to the generic walk would read as unset there
// and silently widen the answer.
func TestAddInventorySelectorUpgradesPlacementOnlyForIdentity(t *testing.T) {
	t.Run("generic walk keeps the first value", func(t *testing.T) {
		dst := lc.Dict{}
		addInventorySelector(dst, map[string]interface{}{
			"type":    "compute_instance",
			"account": []interface{}{"prod", "staging"},
		})
		assert.Equal(t, "prod", dst["account"])
	})

	t.Run("identity lane forwards every value", func(t *testing.T) {
		dst := lc.Dict{}
		addInventorySelector(dst, map[string]interface{}{
			"type":    "Identity",
			"account": []interface{}{"prod", "staging"},
		})
		assert.Equal(t, []string{"prod", "staging"}, dst["account"])
	})

	t.Run("a single value stays scalar even on the identity lane", func(t *testing.T) {
		dst := lc.Dict{}
		addInventorySelector(dst, map[string]interface{}{
			"type":    "Identity",
			"account": []interface{}{"prod"},
		})
		assert.Equal(t, "prod", dst["account"])
	})
}
