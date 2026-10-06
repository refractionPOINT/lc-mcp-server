package cloudsec

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

var entityIDPattern = regexp.MustCompile(`^e[uh]_[a-z2-7]{1,37}$`)

func entityMember(values []string, value string) bool {
	for _, v := range values {
		if value == v {
			return true
		}
	}
	return false
}

const entityObservationNote = "observations is an object {status, reason?, queries, rows, truncated?}: status is ok, incomplete, unavailable or forbidden, and reason (schema_missing, deadline, query_budget, error or bounds) says why a bound or failure applied. incomplete, unavailable and forbidden (no insight.evt.get, so no observation query ran) mean UNKNOWN, never none: an empty observed_matches, also_seen_as or cloud_sign_ins list only means nothing was found when status is ok."

const entityChromeNote = "Chrome profile identity: a signed-in Chrome sensor is a User (eu_) entity, so an old Host eh_ id for it may carry redirect_to pointing at an eu_ id, and telemetry_sources[].identity_source (parser or mapping) with platform chrome tells where the identity came from."

const entityAtDescription = "Optional Unix-second timestamp: historical IP resolution, and it pins the UTC day that observation_selectors are answered for (without it the most recent days are returned, newest first)"

const entitySelectorsDescription = "Optional, at most 4 observation selectors {type, value, platform?, origin_sid?} that ask which existing Hosts a vendor device may be (needs insight.evt.get, otherwise observations.status is forbidden). type vendor_device_id: value is the vendor's device id (at most 128 bytes), platform is required and one of sophos, crowdstrike, office365, entraid, okta, duo, origin_sid is an optional lowercase UUID naming one collector. type foreign_hostname: value is the hostname as the vendor spelled it (at most 512 bytes), with no platform or origin_sid. Values must be non-blank UTF-8. Results come back in observed_matches and are evidence only, never a merge."

const entityMaxObservationSelectors = 4

var entityObservationPlatforms = []string{"sophos", "crowdstrike", "office365", "entraid", "okta", "duo"}
var entityOriginSIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func entitySelectorsOption() mcp.ToolOption {
	return mcp.WithArray("observation_selectors", mcp.Items(map[string]any{"type": "object", "properties": map[string]any{
		"type":       map[string]any{"type": "string", "enum": []string{"vendor_device_id", "foreign_hostname"}, "description": "Selector type"},
		"value":      map[string]any{"type": "string", "description": "Vendor device id (at most 128 bytes) or foreign hostname (at most 512 bytes); non-blank UTF-8"},
		"platform":   map[string]any{"type": "string", "enum": entityObservationPlatforms, "description": "Required for vendor_device_id, not allowed for foreign_hostname"},
		"origin_sid": map[string]any{"type": "string", "description": "Optional lowercase UUID of one collector; vendor_device_id only"},
	}, "required": []string{"type", "value"}}), mcp.Description(entitySelectorsDescription))
}

// entitySelectors validates the optional observation_selectors argument the way
// the API does and returns clean selector objects containing only known fields.
// ok is false when nothing should be sent (absent or empty).
func entitySelectors(args map[string]interface{}) (selectors []interface{}, ok bool, err error) {
	value, present := args["observation_selectors"]
	if !present {
		return nil, false, nil
	}
	var items []interface{}
	switch v := value.(type) {
	case []interface{}:
		items = v
	case []map[string]interface{}:
		for _, item := range v {
			items = append(items, item)
		}
	default:
		return nil, false, fmt.Errorf("observation_selectors must be an array of {type, value, platform?, origin_sid?} objects")
	}
	if len(items) > entityMaxObservationSelectors {
		return nil, false, fmt.Errorf("observation_selectors must contain at most %d entries", entityMaxObservationSelectors)
	}
	if len(items) == 0 {
		return nil, false, nil
	}
	for _, item := range items {
		m, isMap := item.(map[string]interface{})
		if !isMap {
			return nil, false, fmt.Errorf("each observation selector must be an object")
		}
		str := func(key string) (string, bool, bool) {
			raw, has := m[key]
			if !has {
				return "", false, true
			}
			s, isString := raw.(string)
			return s, true, isString
		}
		typ, _, typOK := str("type")
		val, _, valOK := str("value")
		platform, hasPlatform, platformOK := str("platform")
		origin, hasOrigin, originOK := str("origin_sid")
		if !typOK || !valOK || !platformOK || !originOK {
			return nil, false, fmt.Errorf("observation selector fields must be strings")
		}
		if !utf8.ValidString(val) || strings.TrimSpace(val) == "" {
			return nil, false, fmt.Errorf("observation selector value must be non-blank UTF-8")
		}
		out := map[string]interface{}{"type": typ, "value": val}
		switch typ {
		case "vendor_device_id":
			if len(val) > 128 {
				return nil, false, fmt.Errorf("vendor_device_id value must be at most 128 bytes")
			}
			if !entityMember(entityObservationPlatforms, platform) {
				return nil, false, fmt.Errorf("vendor_device_id requires platform, one of %s", strings.Join(entityObservationPlatforms, ", "))
			}
			out["platform"] = platform
			if hasOrigin {
				if !entityOriginSIDPattern.MatchString(origin) {
					return nil, false, fmt.Errorf("origin_sid must be a lowercase canonical UUID")
				}
				out["origin_sid"] = origin
			}
		case "foreign_hostname":
			if len(val) > 512 {
				return nil, false, fmt.Errorf("foreign_hostname value must be at most 512 bytes")
			}
			if hasPlatform || hasOrigin {
				return nil, false, fmt.Errorf("foreign_hostname takes no platform or origin_sid")
			}
		default:
			return nil, false, fmt.Errorf("observation selector type must be vendor_device_id or foreign_hostname")
		}
		selectors = append(selectors, out)
	}
	return selectors, true, nil
}
func registerEntity() {
	register(toolDef{name: "cloudsec_entity_search", description: "Find User (eu_) and Host (eh_) entities whose known identifiers start with a prefix. Use it to discover entities when you only have a partial name; use cloudsec_entity_pivot or cloudsec_entity_resolve when you have a full identifier. Requires at least two characters (at most 512 UTF-8 bytes). Returns one bounded page: keep requesting with next_cursor (same q, kind and limit) while it is present, and do not treat index_ready:false or an incomplete page as absence.", readOnly: true,
		params: []mcp.ToolOption{mcp.WithString("q", mcp.Required(), mcp.Description("Identifier prefix: at least two characters and at most 512 UTF-8 bytes")), mcp.WithString("kind", mcp.Description("Optional user or host")), mcp.WithNumber("limit", mcp.Description("Page size from 1 to 100")), mcp.WithString("cursor", mcp.Description("Opaque next_cursor from the previous page, at most 8192 bytes"))}, handler: searchEntities})

	register(toolDef{name: "cloudsec_entity_pivot", description: "Default tool for 'what is this identifier?': resolve one identifier (email, hostname, DOMAIN\\user, IP, sensor id, GitHub id or login, cloud instance id, ...) to User/Host entity cards across EDR, Email Security and Cloud Security in one call. Returns candidates (the raw resolve results: detected type, evidence, ambiguity, possible matches), cards (fetched only for unambiguous authoritative or corroborated matches, at most 10) and the other top-level resolve fields such as index_ready, sources and sightings. possible and ambiguous candidates are unconfirmed: never pick one or pivot on it automatically; ask the user or gather more evidence. If a card carries redirect_to, the id was merged (for example an old Host eh_ id that now points at a User eu_ id) and the card is the surviving entity's. card_errors/truncated:true means some cards were not fetched; use cloudsec_entity_get on those ids. Observed pivots (needs insight.evt.get): pass observation_selectors to find the Hosts a vendor device or a foreign-vendor hostname may be; the response then carries observed_matches and observations, and fetched cards may carry also_seen_as and cloud_sign_ins. " + entityObservationNote + " Pivot never reads the cards of observed candidates: use cloudsec_entity_get on a candidate's entity id. A resolve input explicitly typed hostname that the inventory does not know also triggers a foreign_hostname lookup; untyped words never do. " + entityChromeNote + " Next: cloudsec_entity_activity or cloudsec_entity_sightings with a card's entity id.", readOnly: true,
		params: []mcp.ToolOption{mcp.WithString("identifier", mcp.Required(), mcp.Description("One identifier, at most 1024 bytes")), mcp.WithString("type", mcp.Description("Optional identifier type, at most 64 bytes (for example email, hostname, ip, sensor_id, github_login, github_user_id, windows_sid, aws_arn); omit for shape detection. The backend validates the value and may support more types than listed")), mcp.WithNumber("at", mcp.Description(entityAtDescription)), entitySelectorsOption()}, handler: pivotEntity})
	register(toolDef{name: "cloudsec_entity_resolve", description: "Batch-resolve 1 to 100 identifiers to entity candidates without fetching cards. Use it instead of cloudsec_entity_pivot when you have many identifiers or only need the entity ids; follow up with cloudsec_entity_get per id. Returns the backend response unchanged: results[] (one per input, in order, each with matches, possible, ambiguous), index_ready, sources and sightings. Matches with confidence authoritative or corroborated are confirmed; possible matches and any ambiguous result are unconfirmed and must not be auto-selected. sightings:\"forbidden\" means the caller lacks insight.evt.get, so sighting-derived matches are omitted. Observed pivots: observation_selectors (up to 4) ask which existing Hosts a vendor device (vendor_device_id) or a foreign-vendor hostname (foreign_hostname) may be; the answer is observed_matches[] (each with the selector, devices[] and candidates[].entity Host ids, plus truncated) and observations. Observed candidates are evidence only: never merge them into an identity or treat them as confirmed matches, and use cloudsec_entity_get to read a candidate. " + entityObservationNote + " A resolve input explicitly typed hostname that the inventory does not know also triggers a foreign_hostname lookup (it counts toward the 4-selector bound); untyped words never do. " + entityChromeNote + "", readOnly: true,
		params: []mcp.ToolOption{mcp.WithArray("identifiers", mcp.Required(), mcp.Items(map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "string", "description": "Identifier, at most 1024 bytes"}, "type": map[string]any{"type": "string", "description": "Optional identifier type, at most 64 bytes; omit for shape detection"}}, "required": []string{"value"}}), mcp.Description("1 to 100 objects of the form {value, type?}")), mcp.WithNumber("at", mcp.Description(entityAtDescription)), entitySelectorsOption()}, handler: resolveEntities})
	register(toolDef{name: "cloudsec_entity_get", description: "Fetch the full card for one entity id (from resolve, pivot or search): attributes, identifiers, telemetry sources, owned hosts or users and pivot hints, plus index_ready and optionally recent sightings (sightings_days). If redirect_to is present the id was merged: the returned card is the surviving entity's, so use that id from now on. card:null with index_ready:true means the id is unknown (or its surviving entity was retired, in which case redirect_to is still set), not an error. sightings:\"forbidden\" means the caller lacks insight.evt.get. With insight.evt.get the card may also carry also_seen_as[] (vendor devices that may be this Host) and cloud_sign_ins[] (sampled cloud sign-ins that may involve this entity) and observations. " + entityObservationNote + " " + entityChromeNote + " Next: cloudsec_entity_activity for a cross-product preview or cloudsec_entity_sightings for raw observations.", readOnly: true,
		params: []mcp.ToolOption{mcp.WithString("entity_id", mcp.Required(), mcp.Description("Entity id such as eu_... or eh_..., from resolve, pivot or search")), mcp.WithNumber("sightings_days", mcp.Description("Optional recent-sightings window in days, 1 to 365"))}, handler: getEntity})
	register(toolDef{name: "cloudsec_entity_sightings", description: "Page through the raw sightings (observed users, logons, internal/external IPs, hostnames) behind an entity, optionally filtered by kind and a since (inclusive) / until (exclusive) Unix-second window. Use it when the card's summary is not enough, for example to see which IPs or logons an entity used. Requires insight.evt.get; without it the call fails with a permission error. Continue calling with the returned next_cursor (same filters) for as long as next_cursor is present; a page without it is the last one.", readOnly: true,
		params: []mcp.ToolOption{mcp.WithString("entity_id", mcp.Required(), mcp.Description("Entity id such as eu_... or eh_...")), mcp.WithString("kind", mcp.Description("Optional filter: user, logon, int_ip, ext_ip or hostname")), mcp.WithNumber("since", mcp.Description("Inclusive Unix seconds")), mcp.WithNumber("until", mcp.Description("Exclusive Unix seconds; must not be before since")), mcp.WithNumber("limit", mcp.Description("Page size from 1 to 500")), mcp.WithString("cursor", mcp.Description("Opaque next_cursor from the previous page, at most 8192 bytes"))}, handler: listEntitySightings})
	register(toolDef{name: "cloudsec_entity_activity", description: "Read a bounded cross-product activity preview for one entity: email, detections, live sensor state and open cloud findings, each as a source with status ok, forbidden, not_subscribed, unavailable or timeout, a truncated flag and a full-view link. Requires the caller's own permission for each product. An unavailable, timed-out or truncated source is unknown, never evidence of absence. Use cloudsec_entity_sightings for the entity's raw observations.", readOnly: true,
		params: []mcp.ToolOption{mcp.WithString("entity_id", mcp.Required()), mcp.WithNumber("since", mcp.Description("Unix seconds; defaults to the last 30 days")), mcp.WithNumber("until", mcp.Description("Unix seconds; defaults to now; maximum window 30 days")), mcp.WithArray("sources", mcp.WithStringItems(), mcp.Description("Subset of email,detections,sensor,cloud; default all"))}, handler: readEntityActivity})
}

// entityIdentifier validates one {value, type?} identifier the way the API does,
// except that the type is deliberately not checked against a list: the backend
// owns the set of supported types and rejects the ones it does not know.
func entityIdentifier(value interface{}, typ interface{}, hasType bool) (map[string]interface{}, error) {
	s, ok := value.(string)
	if !ok || strings.TrimSpace(s) == "" || len(s) > 1024 {
		return nil, fmt.Errorf("identifier must contain 1 to 1024 bytes")
	}
	out := map[string]interface{}{"value": s}
	if hasType {
		t, ok := typ.(string)
		if !ok || strings.TrimSpace(t) == "" || len(t) > 64 {
			return nil, fmt.Errorf("identifier type must be a non-empty string of at most 64 bytes")
		}
		out["type"] = t
	}
	return out, nil
}
func entityTimestamp(args map[string]interface{}, key string) (int64, bool, error) {
	value, present := args[key]
	if !present {
		return 0, false, nil
	}
	var n int64
	switch v := value.(type) {
	case int:
		n = int64(v)
	case int64:
		n = v
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v != math.Trunc(v) || v < 0 || v > 253402300799 {
			return 0, true, fmt.Errorf("invalid %s", key)
		}
		n = int64(v)
	default:
		return 0, true, fmt.Errorf("%s must be integer Unix seconds", key)
	}
	if n < 0 || n > 253402300799 {
		return 0, true, fmt.Errorf("invalid %s", key)
	}
	return n, true, nil
}
func entityGET(ctx context.Context, org *lc.Organization, suffix string, query url.Values) (map[string]interface{}, error) {
	raw, err := rawRequest(ctx, org, http.MethodGet, orgPath(org, suffix), query, nil, 20*time.Second, maxJSONResponseBytes)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxJSONResponseBytes {
		return nil, fmt.Errorf("entity response exceeds byte limit")
	}
	var response map[string]interface{}
	if json.Unmarshal(raw, &response) != nil || response == nil {
		return nil, fmt.Errorf("invalid entity response")
	}
	return response, nil
}
func pivotEntity(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	typ, hasType := args["type"]
	input, err := entityIdentifier(args["identifier"], typ, hasType)
	if err != nil {
		return tools.ErrorResult(err.Error()), nil
	}
	body := map[string]interface{}{"identifiers": []interface{}{input}}
	if at, present, err := entityTimestamp(args, "at"); err != nil {
		return tools.ErrorResult(err.Error()), nil
	} else if present {
		body["at"] = at
	}
	if selectors, ok, err := entitySelectors(args); err != nil {
		return tools.ErrorResult(err.Error()), nil
	} else if ok {
		body["observation_selectors"] = selectors
	}
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResult("organization authentication required"), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, err := postJSON(ctx, org, orgPath(org, "entities/resolve"), body, 20*time.Second)
	if err != nil {
		return tools.ErrorResultf("entity resolution failed: %s", describeErr(err)), nil
	}
	cards := []interface{}{}
	failures := []interface{}{}
	results, _ := response["results"].([]interface{})
	// Pass every top-level resolve key through except results, which is exposed as
	// candidates, so fields the backend adds later are not silently dropped.
	out := map[string]interface{}{}
	for key, value := range response {
		if key != "results" {
			out[key] = value
		}
	}
	out["cards"] = cards
	out["candidates"] = response["results"]
	if ready, _ := response["index_ready"].(bool); !ready {
		return tools.SuccessResult(out), nil
	}
	if disabled, _ := response["feature_disabled"].(bool); disabled {
		return tools.SuccessResult(out), nil
	}
	seen := map[string]bool{}
	for _, value := range results {
		result, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		ambiguous, known := result["ambiguous"].(bool)
		if !known || ambiguous {
			continue
		}
		matches, _ := result["matches"].([]interface{})
		for _, value := range matches {
			match, ok := value.(map[string]interface{})
			if !ok {
				continue
			}
			id, _ := match["entity_id"].(string)
			confidence, _ := match["confidence"].(string)
			if !entityIDPattern.MatchString(id) || (confidence != "authoritative" && confidence != "corroborated") || seen[id] {
				continue
			}
			if len(seen) >= 10 {
				out["truncated"] = true
				break
			}
			seen[id] = true
			card, err := entityGET(ctx, org, "entities/"+id, nil)
			if err != nil {
				failures = append(failures, map[string]interface{}{"entity_id": id, "status": "unavailable"})
				out["truncated"] = true
				continue
			}
			cards = append(cards, card)
		}
	}
	out["cards"] = cards
	if len(failures) > 0 {
		out["card_errors"] = failures
	}
	return tools.SuccessResult(out), nil
}
func readEntityActivity(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	id, ok := args["entity_id"].(string)
	if !ok || !entityIDPattern.MatchString(id) {
		return tools.ErrorResult("invalid entity_id"), nil
	}
	query := url.Values{}
	var since, until int64
	var hasSince, hasUntil bool
	for _, key := range []string{"since", "until"} {
		n, present, err := entityTimestamp(args, key)
		if err != nil {
			return tools.ErrorResult(err.Error()), nil
		}
		if present {
			query.Set(key, strconv.FormatInt(n, 10))
		}
		if key == "since" {
			since, hasSince = n, present
		} else {
			until, hasUntil = n, present
		}
	}
	if hasSince && hasUntil && (since > until || until-since > 30*86400) {
		return tools.ErrorResult("activity window must be ordered and at most 30 days"), nil
	}
	if value, present := args["sources"]; present {
		var values []string
		switch v := value.(type) {
		case []string:
			values = v
		case []interface{}:
			for _, value := range v {
				s, ok := value.(string)
				if !ok {
					return tools.ErrorResult("invalid sources"), nil
				}
				values = append(values, s)
			}
		default:
			return tools.ErrorResult("sources must be an array"), nil
		}
		if len(values) < 1 || len(values) > 4 {
			return tools.ErrorResult("invalid sources"), nil
		}
		seen := map[string]bool{}
		for _, v := range values {
			if !entityMember([]string{"email", "detections", "sensor", "cloud"}, v) || seen[v] {
				return tools.ErrorResult("invalid sources"), nil
			}
			seen[v] = true
		}
		query.Set("sources", strings.Join(values, ","))
	}
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResult("organization authentication required"), nil
	}
	response, err := entityGET(ctx, org, "entities/"+id+"/activity", query)
	if err != nil {
		return tools.ErrorResultf("entity activity failed: %s", describeErr(err)), nil
	}
	return tools.SuccessResult(response), nil
}

func searchEntities(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	prefix, ok := args["q"].(string)
	if !ok || utf8.RuneCountInString(strings.TrimSpace(prefix)) < 2 || len(prefix) > 512 {
		return tools.ErrorResult("q must contain at least two characters and at most 512 UTF-8 bytes"), nil
	}
	query := url.Values{"q": []string{prefix}}
	if value, present := args["kind"]; present {
		kind, ok := value.(string)
		if !ok || !entityMember([]string{"user", "host"}, kind) {
			return tools.ErrorResult("invalid kind"), nil
		}
		query.Set("kind", kind)
	}
	if n, present, err := entityTimestamp(args, "limit"); err != nil || (present && (n < 1 || n > 100)) {
		return tools.ErrorResult("limit must be an integer from 1 to 100"), nil
	} else if present {
		query.Set("limit", strconv.FormatInt(n, 10))
	}
	if value, present := args["cursor"]; present {
		cursor, ok := value.(string)
		if !ok || len(cursor) > 8192 {
			return tools.ErrorResult("invalid cursor"), nil
		}
		query.Set("cursor", cursor)
	}
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResult("organization authentication required"), nil
	}
	response, err := entityGET(ctx, org, "entities/search", query)
	if err != nil {
		return tools.ErrorResultf("entity search failed: %s", describeErr(err)), nil
	}
	return tools.SuccessResult(response), nil
}

func resolveEntities(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	var items []interface{}
	switch v := args["identifiers"].(type) {
	case []interface{}:
		items = v
	case []map[string]interface{}:
		for _, item := range v {
			items = append(items, item)
		}
	default:
		return tools.ErrorResult("identifiers must be an array of {value, type?} objects"), nil
	}
	if len(items) < 1 || len(items) > 100 {
		return tools.ErrorResult("identifiers must contain 1 to 100 entries"), nil
	}
	identifiers := make([]interface{}, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			return tools.ErrorResult("each identifier must be an object with a value"), nil
		}
		typ, hasType := m["type"]
		input, err := entityIdentifier(m["value"], typ, hasType)
		if err != nil {
			return tools.ErrorResult(err.Error()), nil
		}
		identifiers = append(identifiers, input)
	}
	body := map[string]interface{}{"identifiers": identifiers}
	if at, present, err := entityTimestamp(args, "at"); err != nil {
		return tools.ErrorResult(err.Error()), nil
	} else if present {
		body["at"] = at
	}
	if selectors, ok, err := entitySelectors(args); err != nil {
		return tools.ErrorResult(err.Error()), nil
	} else if ok {
		body["observation_selectors"] = selectors
	}
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResult("organization authentication required"), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, err := postJSON(ctx, org, orgPath(org, "entities/resolve"), body, 20*time.Second)
	if err != nil {
		return tools.ErrorResultf("entity resolution failed: %s", describeErr(err)), nil
	}
	return tools.SuccessResult(response), nil
}

func getEntity(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	id, ok := args["entity_id"].(string)
	if !ok || !entityIDPattern.MatchString(id) {
		return tools.ErrorResult("invalid entity_id"), nil
	}
	var query url.Values
	if n, present, err := entityTimestamp(args, "sightings_days"); err != nil || (present && (n < 1 || n > 365)) {
		return tools.ErrorResult("sightings_days must be an integer from 1 to 365"), nil
	} else if present {
		query = url.Values{"sightings_days": []string{strconv.FormatInt(n, 10)}}
	}
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResult("organization authentication required"), nil
	}
	response, err := entityGET(ctx, org, "entities/"+id, query)
	if err != nil {
		return tools.ErrorResultf("entity get failed: %s", describeErr(err)), nil
	}
	return tools.SuccessResult(response), nil
}

func listEntitySightings(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	id, ok := args["entity_id"].(string)
	if !ok || !entityIDPattern.MatchString(id) {
		return tools.ErrorResult("invalid entity_id"), nil
	}
	query := url.Values{}
	if value, present := args["kind"]; present {
		kind, ok := value.(string)
		if !ok || !entityMember([]string{"user", "logon", "int_ip", "ext_ip", "hostname"}, kind) {
			return tools.ErrorResult("kind must be one of user, logon, int_ip, ext_ip, hostname"), nil
		}
		query.Set("kind", kind)
	}
	var since, until int64
	var hasSince, hasUntil bool
	for _, key := range []string{"since", "until"} {
		n, present, err := entityTimestamp(args, key)
		if err != nil {
			return tools.ErrorResult(err.Error()), nil
		}
		if present {
			query.Set(key, strconv.FormatInt(n, 10))
		}
		if key == "since" {
			since, hasSince = n, present
		} else {
			until, hasUntil = n, present
		}
	}
	if hasSince && hasUntil && since > until {
		return tools.ErrorResult("since must not be after until"), nil
	}
	if n, present, err := entityTimestamp(args, "limit"); err != nil || (present && (n < 1 || n > 500)) {
		return tools.ErrorResult("limit must be an integer from 1 to 500"), nil
	} else if present {
		query.Set("limit", strconv.FormatInt(n, 10))
	}
	if value, present := args["cursor"]; present {
		cursor, ok := value.(string)
		if !ok || cursor == "" || len(cursor) > 8192 {
			return tools.ErrorResult("invalid cursor"), nil
		}
		query.Set("cursor", cursor)
	}
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResult("organization authentication required"), nil
	}
	response, err := entityGET(ctx, org, "entities/"+id+"/sightings", query)
	if err != nil {
		return tools.ErrorResultf("entity sightings failed: %s", describeErr(err)), nil
	}
	return tools.SuccessResult(response), nil
}
