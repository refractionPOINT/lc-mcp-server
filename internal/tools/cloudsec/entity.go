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
func registerEntity() {
	register(toolDef{name: "cloudsec_entity_search", description: "Find User (eu_) and Host (eh_) entities whose known identifiers start with a prefix. Use it to discover entities when you only have a partial name; use cloudsec_entity_pivot or cloudsec_entity_resolve when you have a full identifier. Requires at least two characters (at most 512 UTF-8 bytes). Returns one bounded page: keep requesting with next_cursor (same q, kind and limit) while it is present, and do not treat index_ready:false or an incomplete page as absence.", readOnly: true,
		params: []mcp.ToolOption{mcp.WithString("q", mcp.Required(), mcp.Description("Identifier prefix: at least two characters and at most 512 UTF-8 bytes")), mcp.WithString("kind", mcp.Description("Optional user or host")), mcp.WithNumber("limit", mcp.Description("Page size from 1 to 100")), mcp.WithString("cursor", mcp.Description("Opaque next_cursor from the previous page, at most 8192 bytes"))}, handler: searchEntities})

	register(toolDef{name: "cloudsec_entity_pivot", description: "Default tool for 'what is this identifier?': resolve one identifier (email, hostname, DOMAIN\\user, IP, sensor id, GitHub id or login, cloud instance id, ...) to User/Host entity cards across EDR, Email Security and Cloud Security in one call. Returns candidates (the raw resolve results: detected type, evidence, ambiguity, possible matches), cards (fetched only for unambiguous authoritative or corroborated matches, at most 10) and the other top-level resolve fields such as index_ready, sources, sightings, observed_matches and observations. possible and ambiguous candidates are unconfirmed: never pick one or pivot on it automatically; ask the user or gather more evidence. If a card carries redirect_to, the id was merged and the card is the surviving entity's; the kind can change (an old eh_ Host id of a Chrome browser profile now redirects to an eu_ User), so use the redirected id and its kind. card_errors/truncated:true means some cards were not fetched; use cloudsec_entity_get on those ids. observed_matches are leads, never confirmed matches or merged entities: they appear only when you pass observation_selectors (a vendor device id or foreign hostname seen in Sophos, CrowdStrike, Office 365, Entra ID, Okta or Duo events) or when an input explicitly typed hostname is unknown to the inventory (only with no inventory match or possible match, and only in the room explicit selectors leave under the 4-selector bound; untyped inputs never trigger it). They need insight.evt.get. Read observations.status: ok, or incomplete/unavailable/forbidden (forbidden = lacks insight.evt.get); incomplete, unavailable and forbidden never mean there is nothing. Each device lead carries a confidence (corroborated, possible; in resolve also unlinked or unknown) and a reason such as hostname_internal_ip_same_day; describe it by that reason (for example 'same hostname and internal IP observed that day'), never as the same machine or verified. Next: cloudsec_entity_activity or cloudsec_entity_sightings with a card's entity id.", readOnly: true,
		params: []mcp.ToolOption{mcp.WithString("identifier", mcp.Required(), mcp.Description("One identifier, at most 1024 bytes")), mcp.WithString("type", mcp.Description("Optional identifier type, at most 64 bytes (for example email, hostname, ip, sensor_id, github_login, github_user_id, windows_sid, aws_arn); omit for shape detection. The backend validates the value and may support more types than listed")), mcp.WithNumber("at", mcp.Description("Optional Unix-second timestamp for historical IP resolution; it also pins the day examined for observation_selectors")), observationSelectorsOption()}, handler: pivotEntity})
	register(toolDef{name: "cloudsec_entity_resolve", description: "Batch-resolve 1 to 100 identifiers to entity candidates without fetching cards. Use it instead of cloudsec_entity_pivot when you have many identifiers or only need the entity ids; follow up with cloudsec_entity_get per id. Returns the backend response unchanged: results[] (one per input, in order, each with matches, possible, ambiguous), index_ready, sources, sightings and, when relevant, observed_matches and observations. Matches with confidence authoritative or corroborated are confirmed; possible matches and any ambiguous result are unconfirmed and must not be auto-selected. sightings:\"forbidden\" means the caller lacks insight.evt.get, so sighting-derived matches are omitted. Optional observation_selectors (at most 4) look up a vendor device id or foreign hostname in adapter events (currently sophos, crowdstrike, office365, entraid, okta, duo); answers come back only as observed_matches[{selector, devices[], truncated?}], never in matches, and they are leads, not confirmed matches: each device carries a confidence (corroborated, possible, unlinked or unknown) and a reason such as hostname_internal_ip_same_day; describe it by that reason (for example 'same hostname and internal IP observed that day'), never as the same machine or verified. A hostname-typed input the inventory does not know is also looked up that way automatically, only in the room explicit selectors leave under the 4-selector bound; untyped inputs never are. Observations need insight.evt.get; read observations.status: ok, or incomplete/unavailable/forbidden (forbidden = lacks insight.evt.get), none of which mean there is nothing. A card's redirect_to can change kind (an old eh_ Host id of a Chrome browser profile redirects to an eu_ User).", readOnly: true,
		params: []mcp.ToolOption{mcp.WithArray("identifiers", mcp.Required(), mcp.Items(map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "string", "description": "Identifier, at most 1024 bytes"}, "type": map[string]any{"type": "string", "description": "Optional identifier type, at most 64 bytes; omit for shape detection"}}, "required": []string{"value"}}), mcp.Description("1 to 100 objects of the form {value, type?}")), mcp.WithNumber("at", mcp.Description("Optional Unix-second timestamp for historical IP resolution; it also pins the day examined for observation_selectors")), observationSelectorsOption()}, handler: resolveEntities})
	register(toolDef{name: "cloudsec_entity_get", description: "Fetch the full card for one entity id (from resolve, pivot or search): attributes, identifiers, telemetry sources (attached adapter, Chrome browser profile and mailbox sensors; identity_source parser or mapping, where mapping means a customer-declared, unconfirmed identity), owned hosts or users and pivot hints, plus index_ready and optionally recent sightings (sightings_days). Host cards may carry also_seen_as[] (devices from other security products whose observed hostname and internal IP matched one of this Host's sensors on a day) and Host and User cards may carry cloud_sign_ins[] (sign-ins whose source address one of the Host's sensors reported, or by this person); both are approximate leads from adapter events (Sophos, CrowdStrike, Office 365, Entra ID, Okta, Duo) with a confidence and reason, never confirmed identity: describe them by their reason (for example 'same hostname and internal IP observed that day'), never as the same machine or verified, and sign-in host candidates are always possible. The response's observations.status is ok, incomplete, unavailable or forbidden (forbidden = the caller lacks insight.evt.get); incomplete, unavailable and forbidden never mean none. If redirect_to is present the id was merged: the returned card is the surviving entity's and its kind can differ (an old eh_ Host id of a Chrome browser profile redirects to an eu_ User), so use that id from now on. card:null with index_ready:true means the id is unknown (or its surviving entity was retired, in which case redirect_to is still set), not an error. sightings:\"forbidden\" means the caller lacks insight.evt.get. Next: cloudsec_entity_activity for a cross-product preview or cloudsec_entity_sightings for raw observations.", readOnly: true,
		params: []mcp.ToolOption{mcp.WithString("entity_id", mcp.Required(), mcp.Description("Entity id such as eu_... or eh_..., from resolve, pivot or search")), mcp.WithNumber("sightings_days", mcp.Description("Optional recent-sightings window in days, 1 to 365"))}, handler: getEntity})
	register(toolDef{name: "cloudsec_entity_sightings", description: "Page through the raw sightings (observed users, logons, internal/external IPs, hostnames) behind an entity, optionally filtered by kind and a since (inclusive) / until (exclusive) Unix-second window. Use it when the card's summary is not enough, for example to see which IPs or logons an entity used. Requires insight.evt.get; without it the call fails with a permission error. Continue calling with the returned next_cursor (same filters) for as long as next_cursor is present; a page without it is the last one.", readOnly: true,
		params: []mcp.ToolOption{mcp.WithString("entity_id", mcp.Required(), mcp.Description("Entity id such as eu_... or eh_...")), mcp.WithString("kind", mcp.Description("Optional filter: user, logon, int_ip, ext_ip or hostname")), mcp.WithNumber("since", mcp.Description("Inclusive Unix seconds")), mcp.WithNumber("until", mcp.Description("Exclusive Unix seconds; must not be before since")), mcp.WithNumber("limit", mcp.Description("Page size from 1 to 500")), mcp.WithString("cursor", mcp.Description("Opaque next_cursor from the previous page, at most 8192 bytes"))}, handler: listEntitySightings})
	register(toolDef{name: "cloudsec_entity_activity", description: "Read a bounded cross-product activity preview for one entity: email, detections, live sensor state and open cloud findings, each as a source with status ok, forbidden, not_subscribed, unavailable or timeout, a truncated flag and a full-view link. Requires the caller's own permission for each product. An unavailable, timed-out or truncated source is unknown, never evidence of absence. Use cloudsec_entity_sightings for the entity's raw observations.", readOnly: true,
		params: []mcp.ToolOption{mcp.WithString("entity_id", mcp.Required()), mcp.WithNumber("since", mcp.Description("Unix seconds; defaults to the last 30 days")), mcp.WithNumber("until", mcp.Description("Unix seconds; defaults to now; maximum window 30 days")), mcp.WithArray("sources", mcp.WithStringItems(), mcp.Description("Subset of email,detections,sensor,cloud; default all"))}, handler: readEntityActivity})
}

const (
	entityMaxObservationSelectors = 4
	entityMaxSelectorValueBytes   = 512
	entityMaxSelectorTagBytes     = 64
)

// observationSelectorsOption declares the optional observation_selectors array shared
// by resolve and pivot. The selector vocabulary (types, platforms) belongs to the
// backend, so the schema documents it as guidance without restricting it.
func observationSelectorsOption() mcp.ToolOption {
	return mcp.WithArray("observation_selectors", mcp.Items(map[string]any{
		"type": "object",
		"properties": map[string]any{
			"type":       map[string]any{"type": "string", "description": "Selector type: vendor_device_id (needs platform) or foreign_hostname"},
			"value":      map[string]any{"type": "string", "description": "Device id or hostname, at most 512 bytes"},
			"platform":   map[string]any{"type": "string", "description": "Source platform for vendor_device_id, currently sophos, crowdstrike, office365, entraid, okta or duo"},
			"origin_sid": map[string]any{"type": "string", "description": "Optional sensor id the event came from"},
		},
		"required":             []string{"type", "value"},
		"additionalProperties": false,
	}), mcp.Description("Optional, at most 4 leads to look up in adapter events: {type:\"vendor_device_id\", platform, value, origin_sid?} or {type:\"foreign_hostname\", value}. Answered only in observed_matches (leads, never confirmed matches). Needs insight.evt.get. The backend validates types and platforms and rejects unsupported ones"))
}

// entityObservationSelectors shapes and bounds observation_selectors without
// allowlisting selector types or platforms: the backend owns those vocabularies.
// It returns nil when the argument is absent or empty.
func entityObservationSelectors(args map[string]interface{}) ([]interface{}, error) {
	raw, present := args["observation_selectors"]
	if !present || raw == nil {
		return nil, nil
	}
	var items []interface{}
	switch v := raw.(type) {
	case []interface{}:
		items = v
	case []map[string]interface{}:
		for _, item := range v {
			items = append(items, item)
		}
	default:
		return nil, fmt.Errorf("observation_selectors must be an array of selector objects")
	}
	if len(items) > entityMaxObservationSelectors {
		return nil, fmt.Errorf("observation_selectors accepts at most %d selectors", entityMaxObservationSelectors)
	}
	out := make([]interface{}, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("each observation selector must be an object")
		}
		sel := map[string]interface{}{}
		for key, value := range m {
			limit := entityMaxSelectorTagBytes
			switch key {
			case "type", "platform", "origin_sid":
			case "value":
				limit = entityMaxSelectorValueBytes
			default:
				return nil, fmt.Errorf("unknown observation selector key %q", key)
			}
			s, ok := value.(string)
			if !ok || strings.TrimSpace(s) == "" || len(s) > limit {
				return nil, fmt.Errorf("observation selector %s must be a non-empty string of at most %d bytes", key, limit)
			}
			sel[key] = s
		}
		if _, ok := sel["type"]; !ok {
			return nil, fmt.Errorf("observation selector requires type")
		}
		if _, ok := sel["value"]; !ok {
			return nil, fmt.Errorf("observation selector requires value")
		}
		out = append(out, sel)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
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
	selectors, err := entityObservationSelectors(args)
	if err != nil {
		return tools.ErrorResult(err.Error()), nil
	}
	if selectors != nil {
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
	selectors, err := entityObservationSelectors(args)
	if err != nil {
		return tools.ErrorResult(err.Error()), nil
	}
	if selectors != nil {
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
