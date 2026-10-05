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
var entityIdentifierTypes = strings.Fields("email github_user_id github_login entra_object_id okta_user_id gws_user_id aws_arn windows_sid ad_account ad_account_short username sensor_id device_id cloud_instance_id graph_urn serial mac hostname fqdn ip")

func entityMember(values []string, value string) bool {
	for _, v := range values {
		if value == v {
			return true
		}
	}
	return false
}
func registerEntity() {
	register(toolDef{name: "cloudsec_entity_search", description: "Search User and Host entity identifiers by prefix (at least two characters, at most 512 UTF-8 bytes). Returns one bounded page with index readiness and next_cursor; do not interpret an incomplete index or page as absence.", readOnly: true,
		params: []mcp.ToolOption{mcp.WithString("q", mcp.Required(), mcp.Description("Identifier prefix: at least two characters and at most 512 UTF-8 bytes")), mcp.WithString("kind", mcp.Description("Optional user or host")), mcp.WithNumber("limit", mcp.Description("Page size from 1 to 100")), mcp.WithString("cursor", mcp.Description("Opaque next_cursor from the previous page, at most 8192 bytes"))}, handler: searchEntities})

	register(toolDef{name: "cloudsec_entity_pivot", description: "Resolve an identifier to User or Host entity cards across security products. This is the default tool for 'what is this identifier?'. Ambiguous candidates and possible matches are unconfirmed; never choose one or follow a possible match automatically. Preserves index readiness, freshness and redirects.", readOnly: true,
		params: []mcp.ToolOption{mcp.WithString("identifier", mcp.Required(), mcp.Description("One identifier, at most 1024 bytes")), mcp.WithString("type", mcp.Description("Optional identifier type; omit for shape detection")), mcp.WithNumber("at", mcp.Description("Optional Unix-second timestamp for historical IP resolution"))}, handler: pivotEntity})
	register(toolDef{name: "cloudsec_entity_activity", description: "Read a bounded entity activity preview from email, detections, live sensor state and open cloud findings. Each source reports ok, forbidden, not_subscribed, unavailable or timeout plus truncation and a full-view link. Requires the caller's own permission for each product; an unavailable or truncated source is unknown, never evidence of absence.", readOnly: true,
		params: []mcp.ToolOption{mcp.WithString("entity_id", mcp.Required()), mcp.WithNumber("since", mcp.Description("Unix seconds; defaults to the last 30 days")), mcp.WithNumber("until", mcp.Description("Unix seconds; defaults to now; maximum window 30 days")), mcp.WithArray("sources", mcp.WithStringItems(), mcp.Description("Subset of email,detections,sensor,cloud; default all"))}, handler: readEntityActivity})
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
	identifier, ok := args["identifier"].(string)
	if !ok || strings.TrimSpace(identifier) == "" || len(identifier) > 1024 {
		return tools.ErrorResult("identifier must contain 1 to 1024 bytes"), nil
	}
	input := map[string]interface{}{"value": identifier}
	if value, present := args["type"]; present {
		typ, ok := value.(string)
		if !ok || !entityMember(entityIdentifierTypes, typ) {
			return tools.ErrorResult("invalid identifier type"), nil
		}
		input["type"] = typ
	}
	body := map[string]interface{}{"identifiers": []interface{}{input}}
	if at, present, err := entityTimestamp(args, "at"); err != nil {
		return tools.ErrorResult(err.Error()), nil
	} else if present {
		body["at"] = at
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
	out := map[string]interface{}{"cards": cards, "candidates": response["results"]}
	for _, key := range []string{"index_ready", "sources", "feature_disabled", "sightings"} {
		if value, present := response[key]; present {
			out[key] = value
		}
	}
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
