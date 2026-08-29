package cloudsec

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// Gateway caps worth mirroring client-side so a request is not silently reshaped
// server-side. Every value below is the gateway's own constant.
const (
	maxPageLimit     = 1000 // maxCloudSecPageLimit, endpoint_cloudsec.go:231
	maxNeighborLimit = 500  // maxCloudSecNeighborLimit, endpoint_cloudsec.go:1466
	maxSampleLimit   = 100  // maxCloudSecSampleLimit, endpoint_cloudsec.go:1048
	maxSuggestLimit  = 50   // maxCloudSecSuggestLimit, endpoint_cloudsec.go:1096
	maxSuggestQueryB = 256  // maxCloudSecSuggestQueryLen, endpoint_cloudsec.go:1102 (BYTES)
	maxCauseLimit    = 200  // the causes rollup's own cap, endpoint_cloudsec.go:1217
	maxCauseKeyLen   = 512  // maxCloudSecCauseKeyLen, endpoint_cloudsec.go:1252
	maxBulkFindings  = 500  // maxCloudSecBulkFindingIDs, endpoint_cloudsec.go:249 — REJECTED above, not clamped
	maxFleetLimit    = 100  // maxCloudSecFleetPageLimit, endpoint_cloudsec_fleet.go:56
	maxFleetOids     = 500  // maxCloudSecFleetOids, endpoint_cloudsec_fleet.go:50
	maxFilterValues  = 100  // maxCloudSecFilterValues, endpoint_cloudsec.go:242

	// resolveChunkSize matches the python SDK's _RESOLVE_CHUNK_SIZE
	// (limacharlie/sdk/cloudsec.py): the ids ride as repeated query params and the
	// load balancer caps URLs near 8 KB (~190 UUIDs), well below the gateway's own
	// 500-per-request clamp.
	resolveChunkSize = 100
)

// argString returns a non-empty string arg, or "".
func argString(args map[string]interface{}, key string) string {
	s, _ := argStringOK(args, key)
	return s
}

// argStringOK reports whether the string arg was supplied separately from whether
// it is empty. Needed wherever the empty string is a real value: clearing a
// finding's owner/ticket, or rejecting an explicitly-empty query text instead of
// treating it as absent.
func argStringOK(args map[string]interface{}, key string) (string, bool) {
	v, ok := args[key]
	if !ok {
		return "", false
	}
	s, isStr := v.(string)
	if !isStr {
		return "", false
	}
	return s, true
}

// argInt returns an int arg. MCP numeric args arrive as float64.
func argInt(args map[string]interface{}, key string) (int, bool) {
	switch v := args[key].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	}
	return 0, false
}

// argBool returns a bool arg and whether it was supplied. The distinction is
// load-bearing for every tri-state filter: absent leaves the dimension
// unconstrained, false pins it (addCloudSecTriStateBools, endpoint_cloudsec.go:396-406).
func argBool(args map[string]interface{}, key string) (bool, bool) {
	v, ok := args[key].(bool)
	return v, ok
}

// argStrings extracts a repeatable filter's values.
//
// Empty elements are PRESERVED: for several gateway dimensions the empty value is
// a real selection — owner="" is the unassigned findings bucket
// (endpoint_cloudsec.go:296-314) and an empty posture_* value selects assets no
// source reported that fact for (endpoint_cloudsec_caasm.go:78-89). Dropping it
// would silently widen the read to the whole estate.
//
// A bare string is accepted as a one-element list, and non-string scalars are
// stringified, because models routinely send either form for an array parameter.
func argStrings(args map[string]interface{}, key string) ([]string, bool) {
	v, present := args[key]
	if !present {
		return nil, false
	}
	switch typed := v.(type) {
	case string:
		return []string{typed}, true
	case []string:
		return typed, true
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			switch e := item.(type) {
			case string:
				out = append(out, e)
			case nil, map[string]interface{}, []interface{}:
				// Not a scalar filter value; skip rather than send "map[...]".
			default:
				out = append(out, fmt.Sprintf("%v", e))
			}
		}
		return out, true
	}
	return nil, false
}

// argScalar returns the single-valued form of an arg that the gateway reads with
// q.Get. It accepts a one-element array as well as a bare string, because the same
// dimension is repeatable on the sibling routes (and on the shared export tool
// 'account' has to be declared as an array for the findings dataset) — so a caller
// legitimately arrives here holding ["prod"]. Extra elements are dropped: the generic
// inventory walk takes one value per dimension.
func argScalar(args map[string]interface{}, key string) string {
	if s, ok := argStringOK(args, key); ok {
		return s
	}
	if v, ok := argStrings(args, key); ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

// argMap returns an object arg and whether it was supplied. An empty object is a
// valid value (simulate/findings reads {} as "everything up to the default
// severity ceiling"), so presence is reported separately from emptiness.
//
// A JSON string that decodes to an object is accepted too: these are nested
// documents (a provider record, a coverage policy, a suppression matcher) and a
// model routinely hands them over already serialized.
func argMap(args map[string]interface{}, key string) (map[string]interface{}, bool) {
	v, present := args[key]
	if !present {
		return nil, false
	}
	m, err := asObject(v)
	if err != nil {
		return nil, false
	}
	return m, true
}

// asObject accepts an object either as a decoded map or as a JSON string.
func asObject(raw interface{}) (map[string]interface{}, error) {
	switch v := raw.(type) {
	case map[string]interface{}:
		return v, nil
	case string:
		if strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("value is empty")
		}
		out := map[string]interface{}{}
		if err := json.Unmarshal([]byte(v), &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported type %T", raw)
}

// argList returns an array arg verbatim (used for JSON bodies, where the elements
// are objects rather than filter strings).
func argList(args map[string]interface{}, key string) ([]interface{}, bool) {
	v, present := args[key]
	if !present {
		return nil, false
	}
	l, isList := v.([]interface{})
	if !isList {
		return nil, false
	}
	return l, true
}

// ------------------------------------------------------------------
// query-dict builders
// ------------------------------------------------------------------

// addStrings forwards repeatable filter params. The SDK expands a []string into
// repeated query keys (getStringKV, client.go), which is the wire form the
// gateway's OR-within-a-key filters read.
//
// Values are NOT truncated client-side. Most routes clamp a repeatable key at
// maxFilterValues server-side, but the Data Security dimensions are forwarded
// unclamped (addCloudSecMultiValue with limit 0, endpoint_cloudsec.go:360) — so
// trimming here would drop values the gateway would have honored. The clamp is
// documented in the affected tool descriptions instead.
func addStrings(dst lc.Dict, args map[string]interface{}, keys ...string) {
	for _, k := range keys {
		v, ok := argStrings(args, k)
		if !ok || len(v) == 0 {
			continue
		}
		dst[k] = v
	}
}

// addScalars forwards single-valued string params. The gateway reads these with
// q.Get and treats "" as unset, so an empty value is skipped.
func addScalars(dst lc.Dict, args map[string]interface{}, keys ...string) {
	for _, k := range keys {
		if v := argString(args, k); v != "" {
			dst[k] = v
		}
	}
}

// addTriState forwards tri-state boolean filters ONLY when supplied. Absent is not
// false: the gateway omits an absent key so the dimension stays unconstrained.
func addTriState(dst lc.Dict, args map[string]interface{}, keys ...string) {
	for _, k := range keys {
		if v, ok := argBool(args, k); ok {
			dst[k] = v
		}
	}
}

// addInt forwards a positive integer param, clamped to max (max <= 0 = no clamp).
func addInt(dst lc.Dict, args map[string]interface{}, key string, max int) {
	n, ok := argInt(args, key)
	if !ok || n <= 0 {
		return
	}
	if max > 0 && n > max {
		n = max
	}
	dst[key] = n
}

// ------------------------------------------------------------------
// shared selector sets
// ------------------------------------------------------------------

// addFindingSelector layers the findings worklist selectors, matching
// addCloudSecFindingParams (endpoint_cloudsec.go:296-328). paging=false is for the
// CSV export, which walks the full filtered set server-side and ignores cursor/limit
// (endpoint_cloudsec_export.go:80-86).
func addFindingSelector(dst lc.Dict, args map[string]interface{}, paging bool) *mcp.CallToolResult {
	addStrings(dst, args, "severity", "finding_class", "status", "account", "owner")
	// `repo` is validated and case-folded rather than forwarded raw, so it is the one
	// selector here that can refuse the call. The error travels up through every caller
	// — the list, the facets, the causes rollup and the CSV export — because they are
	// meant to describe the same filtered set, and a selector that only some of them
	// applied would make the counts disagree with the rows.
	repos, errResult := findingRepoValues(args)
	if errResult != nil {
		return errResult
	}
	if len(repos) > 0 {
		dst["repo"] = repos
	}
	addTriState(dst, args, "reachable", "kev")
	addScalars(dst, args, "q", "sort", "order")
	if paging {
		addScalars(dst, args, "cursor")
		addInt(dst, args, "limit", maxPageLimit)
	}
	return nil
}

// findingRepoValues extracts the AppSec code lane's `repo` selector for the findings
// routes: `<owner>/<name>`, case-folded, or an error result the caller must return.
//
// It FOLDS because the backend matches the key exactly (`repo IN UNNEST(@f_repo)`,
// legion_graph findingstore/store.go) against a column projected off the finding's
// subject urn — and that urn's owner and name segments are ASCII-lower-cased when it is
// built (go-cloudsec model.BuildRepoURN / FoldRepoSegment, v1.46.0), so ONE repository is
// one node however its three producers spelled it. The DISPLAY name is untouched by that
// fold, so the spelling a caller reads off a finding, an SCM page, or a hive record is
// routinely not the spelling stored in the column. Folding here is what stops
// `Acme/API` from being a syntactically perfect filter that silently matches nothing.
//
// The fold is ASCII-only, deliberately, because that is the rule the backend applied:
// strings.ToLower would also fold non-ASCII (`İ` becomes two runes), producing a key no
// urn ever carried — a different wrong answer, not a safer one.
//
// It REJECTS rather than drops, because dropping is the dangerous half. `repo` has no
// "any repository" value: a finding with no repository is every cloud finding in the
// estate, so a value silently discarded here does not narrow the read differently, it
// removes the code-lane scoping entirely and hands back the whole worklist under an
// active-looking filter. A supplied-but-unusable `repo` therefore ends the call locally,
// naming the value, with no request sent.
func findingRepoValues(args map[string]interface{}) ([]string, *mcp.CallToolResult) {
	raw, present := args["repo"]
	if !present {
		return nil, nil
	}
	values, ok := argStrings(args, "repo")
	if !ok {
		// Present but not a string or a list of them (a number, a bool, an object). The
		// same shape the sibling `source` selector was caught fail-open on: absent means
		// unconstrained, so a value that decodes to nothing has to be an error here.
		return nil, tools.ErrorResultf(
			"the 'repo' filter must be a repository key '<owner>/<name>' or a list of them, not %T. "+
				"Call cloudsec_get_finding_facets (or cloudsec_code_repos) for the keys this organization has.", raw)
	}
	if len(values) == 0 {
		return nil, tools.ErrorResult(
			"the 'repo' filter was supplied with no repository. Omit it to read every finding, " +
				"or pass repository keys '<owner>/<name>' — there is no 'any repository' value, " +
				"since a finding with no repository is a cloud finding.")
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		key := strings.TrimSpace(v)
		owner, name, hasSlash := strings.Cut(key, "/")
		if owner == "" || name == "" || !hasSlash || strings.Contains(name, "/") {
			return nil, tools.ErrorResultf(
				"%q is not a repository key: 'repo' takes '<owner>/<name>' exactly as cloudsec_code_repos "+
					"and the 'repo' facet return it. An empty or malformed value selects no rows, and dropping it "+
					"would widen the read to the whole estate, so the call stops here.", v)
		}
		out = append(out, foldRepoKey(key))
	}
	return out, nil
}

// foldRepoKey is the client-side copy of go-cloudsec model.FoldRepoSegment applied to a
// whole `<owner>/<name>` key: ASCII upper-case letters lower-cased, every other byte left
// alone. Copied rather than imported because this server depends on the LimaCharlie SDK,
// not on the Cloud Security model package; it is eleven bytes of rule, and the comment on
// findingRepoValues names the original so the two can be compared.
func foldRepoKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

// addIdentitySelector layers the merged-identity cross-filter shared by
// /ciem/facets, /ciem/identities and the type=Identity inventory lane
// (addCloudSecIdentitySelectors, endpoint_cloudsec.go:435-441).
func addIdentitySelector(dst lc.Dict, args map[string]interface{}) {
	addStrings(dst, args, "source", "kind", "criticality", "risk_band")
	addTriState(dst, args,
		"admin", "external", "public", "disabled",
		"crown_jewel", "can_escalate", "dormant_90d", "with_sensitive")
	addScalars(dst, args, "mfa")
}

// addIdentityPlacement layers the placement dimensions in their REPEATABLE form,
// which the identity-only routes accept (addCloudSecIdentityFilterArgs,
// endpoint_cloudsec.go:451-458).
func addIdentityPlacement(dst lc.Dict, args map[string]interface{}) {
	addStrings(dst, args, "provider", "account", "region")
	addScalars(dst, args, "q")
}

// addInventorySelector layers the generic inventory selectors
// (addCloudSecInventoryArgs, endpoint_cloudsec.go:336-349). provider/account/region
// are single-valued here: the gateway only upgrades them to the repeatable form
// when type=Identity, and an array sent to the generic walk would read as unset.
func addInventorySelector(dst lc.Dict, args map[string]interface{}) {
	for _, k := range []string{"type", "provider", "account", "region", "q"} {
		if v := argScalar(args, k); v != "" {
			dst[k] = v
		}
	}
	if v, ok := argBool(args, "account_unscoped"); ok {
		dst["account_unscoped"] = v
	}
	// Under type=Identity the merged lane DOES read the placement dimensions
	// multi-valued, and the gateway upgrades them for exactly that type
	// (endpoint_cloudsec.go:480-482). Mirror the same condition so a caller who
	// supplied several values does not silently lose all but the first — and so the
	// array never reaches the generic walk, where it would read as unset.
	if argScalar(args, "type") == identityResourceType {
		for _, k := range []string{"provider", "account", "region"} {
			if v, ok := argStrings(args, k); ok && len(v) > 1 {
				dst[k] = v
			}
		}
	}
}

// identityResourceType is the inventory discriminator the merged identity lane
// answers for (cloudSecIdentityResourceType, endpoint_cloudsec.go:413).
const identityResourceType = "Identity"

// addDataStoreSelector layers the Data Security (DSPM) selectors
// (addCloudSecDataStoreArgs, endpoint_cloudsec.go:356-366).
func addDataStoreSelector(dst lc.Dict, args map[string]interface{}, paging bool) {
	addStrings(dst, args, "provider", "account", "region", "store_kind", "tier", "data_class")
	addScalars(dst, args, "q")
	addTriState(dst, args, "sensitivity", "exposure")
	if paging {
		addScalars(dst, args, "cursor")
		addInt(dst, args, "limit", maxPageLimit)
	}
}
