package cloudsec

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

const entityFixtureOID = "11111111-1111-4111-8111-111111111111"
const entityFixtureID = "eh_aaaaaaaaaaaaaaaaaaaaaaaaaa"

func entityContext(t *testing.T) context.Context {
	t.Helper()
	cache := auth.NewSDKCache(time.Minute, nil)
	t.Cleanup(cache.Close)
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Hour).Unix())))
	ctx := auth.WithSDKCache(context.Background(), cache)
	return auth.WithAuthContext(ctx, &auth.AuthContext{Mode: auth.AuthModeNormal, OID: entityFixtureOID, JWTToken: "eyJhbGciOiJIUzI1NiJ9." + payload + ".fixture"})
}
func entityResult(t *testing.T, result *mcp.CallToolResult) map[string]interface{} {
	t.Helper()
	if result == nil || result.IsError {
		t.Fatalf("unexpected error result %+v", result)
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(codeResultText(result)), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func TestEntityToolsAreReadOnlyInBothProfiles(t *testing.T) {
	for _, name := range []string{"cloudsec_entity_search", "cloudsec_entity_pivot", "cloudsec_entity_resolve",
		"cloudsec_entity_get", "cloudsec_entity_sightings", "cloudsec_entity_activity"} {
		registration, ok := tools.GetTool(name)
		if !ok || !registration.RequiresOID || registration.Schema.Annotations.ReadOnlyHint == nil || !*registration.Schema.Annotations.ReadOnlyHint || registration.Schema.Annotations.DestructiveHint == nil || *registration.Schema.Annotations.DestructiveHint {
			t.Fatalf("unsafe registration %s", name)
		}
		for _, profile := range []string{"cloud_security", "cloud_security_readonly", "historical_data", "historical_data_readonly", "email_security", "email_security_readonly"} {
			if !entityMember(tools.GetToolsForProfile(profile), name) {
				t.Fatalf("missing %s in %s", name, profile)
			}
		}
	}
}
func TestEntityToolsRejectInvalidInputBeforeAuth(t *testing.T) {
	for _, args := range []map[string]interface{}{{}, {"identifier": 123}, {"identifier": " "}, {"identifier": strings.Repeat("x", 1025)}, {"identifier": "host", "type": ""}, {"identifier": "host", "type": 5}, {"identifier": "host", "type": strings.Repeat("t", 65)}, {"identifier": "host", "at": 1.5}, {"identifier": "host", "at": true}, {"identifier": "host", "at": -1}} {
		result, err := pivotEntity(context.Background(), args)
		if err != nil || result == nil || !result.IsError {
			t.Fatalf("invalid pivot accepted %+v", args)
		}
	}
	for _, args := range []map[string]interface{}{{"entity_id": "../../other"}, {"entity_id": entityFixtureID, "since": 1.1}, {"entity_id": entityFixtureID, "since": 20, "until": 10}, {"entity_id": entityFixtureID, "since": 0, "until": 99999999}, {"entity_id": entityFixtureID, "sources": []string{}}, {"entity_id": entityFixtureID, "sources": []string{"cloud", "cloud"}}, {"entity_id": entityFixtureID, "sources": []string{"unknown"}}} {
		result, err := readEntityActivity(context.Background(), args)
		if err != nil || result == nil || !result.IsError {
			t.Fatalf("invalid activity accepted %+v", args)
		}
	}
}
func TestEntityPivotHTTPContractAndAmbiguity(t *testing.T) {
	for _, tc := range []struct {
		name, confidence           string
		ambiguous, ready, disabled bool
		gets                       int
	}{
		{"confirmed", "authoritative", false, true, false, 1}, {"corroborated", "corroborated", false, true, false, 1}, {"ambiguous", "authoritative", true, true, false, 0}, {"possible", "possible", false, true, false, 0}, {"unknown confidence", "future", false, true, false, 0}, {"not ready", "authoritative", false, false, false, 0}, {"disabled", "authoritative", false, true, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := entityContext(t)
			old := httpClient
			t.Cleanup(func() { httpClient = old })
			gets := 0
			httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host != "api.limacharlie.io" || !strings.HasPrefix(r.URL.Path, "/v1/cloudsec/"+entityFixtureOID+"/entities/") || r.Header.Get("Authorization") == "" {
					t.Fatal("tenant or authentication changed")
				}
				if _, ok := r.Context().Deadline(); !ok {
					t.Fatal("missing deadline")
				}
				var response string
				if strings.HasSuffix(r.URL.Path, "/resolve") {
					if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
						t.Fatal("resolve is not JSON POST")
					}
					var body map[string]interface{}
					_ = json.NewDecoder(r.Body).Decode(&body)
					want := map[string]interface{}{"identifiers": []interface{}{map[string]interface{}{"type": "hostname", "value": "host.example"}}, "at": float64(123)}
					if !reflect.DeepEqual(body, want) {
						t.Fatalf("body changed %+v", body)
					}
					response = fmt.Sprintf(`{"index_ready":%t,"feature_disabled":%t,"sightings":"forbidden","sources":[{"source":"fixture","stale":true}],"results":[{"input":{"value":"host.example"},"ambiguous":%t,"matches":[{"entity_id":%q,"confidence":%q}],"possible":[{"entity_id":"eu_aaaa","confidence":"possible"}]}]}`, tc.ready, tc.disabled, tc.ambiguous, entityFixtureID, tc.confidence)
				} else {
					gets++
					if !strings.HasSuffix(r.URL.Path, "/"+entityFixtureID) || r.Method != "GET" {
						t.Fatal("followed candidate or wrong route")
					}
					response = `{"card":{"entity":{"id":"` + entityFixtureID + `"}},"redirect_to":"` + entityFixtureID + `","index_ready":true}`
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response)), Header: http.Header{}}, nil
			})}
			result, err := pivotEntity(ctx, map[string]interface{}{"identifier": "host.example", "type": "hostname", "at": 123, "oid": "foreign", "url": "https://untrusted.invalid"})
			if err != nil {
				t.Fatal(err)
			}
			output := entityResult(t, result)
			if gets != tc.gets || len(output["cards"].([]interface{})) != tc.gets || len(output["candidates"].([]interface{})) != 1 {
				t.Fatalf("lost candidates or followed ambiguity: %+v gets=%d", output, gets)
			}
			if len(output["sources"].([]interface{})) != 1 {
				t.Fatal("lost freshness")
			}
			if output["sightings"] != "forbidden" {
				t.Fatal("lost sighting permission verdict")
			}
		})
	}
}
func TestEntityActivityHTTPPreservesSourceStatus(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Path != "/v1/cloudsec/"+entityFixtureOID+"/entities/"+entityFixtureID+"/activity" || r.URL.Query().Get("sources") != "email,cloud" || r.URL.Query().Get("since") != "10" || r.URL.Query().Get("until") != "20" || r.URL.Query().Get("oid") != "" {
			t.Fatalf("incorrect activity request %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"sources":[{"source":"email","status":"forbidden","items":[],"truncated":false,"link":"/mailsec/messages"},{"source":"cloud","status":"timeout","items":[],"truncated":true,"link":"/cloudsec/findings"}]}`)), Header: http.Header{}}, nil
	})}
	result, err := readEntityActivity(ctx, map[string]interface{}{"entity_id": entityFixtureID, "since": 10, "until": 20, "sources": []interface{}{"email", "cloud"}, "oid": "foreign"})
	if err != nil {
		t.Fatal(err)
	}
	output := entityResult(t, result)
	sources := output["sources"].([]interface{})
	if sources[0].(map[string]interface{})["status"] != "forbidden" || sources[1].(map[string]interface{})["truncated"] != true {
		t.Fatal("source failure became absence")
	}
}
func TestEntityPivotKeepsCandidatesWhenCardUnavailable(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		code := 200
		body := `{"index_ready":true,"results":[{"ambiguous":false,"matches":[{"entity_id":"` + entityFixtureID + `","confidence":"authoritative"}]}]}`
		if r.Method == "GET" {
			code = 503
			body = `{"error":"unavailable"}`
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})}
	result, err := pivotEntity(ctx, map[string]interface{}{"identifier": "host"})
	if err != nil {
		t.Fatal(err)
	}
	output := entityResult(t, result)
	if output["truncated"] != true || len(output["card_errors"].([]interface{})) != 1 || len(output["candidates"].([]interface{})) != 1 {
		t.Fatal("unavailable card became unresolved identifier")
	}
}

func TestEntitySearchRejectsInvalidInputBeforeHTTP(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		t.Fatal("invalid search made HTTP request")
		return nil, nil
	})}
	for _, args := range []map[string]interface{}{{}, {"q": 123}, {"q": "中"}, {"q": " "}, {"q": strings.Repeat("a", 513)}, {"q": strings.Repeat("中", 171)}, {"q": "host", "kind": "unknown"}, {"q": "host", "limit": 0}, {"q": "host", "limit": 101}, {"q": "host", "limit": 1.5}, {"q": "host", "limit": true}, {"q": "host", "cursor": strings.Repeat("x", 8193)}, {"q": "host", "cursor": 123}} {
		result, err := searchEntities(ctx, args)
		if err != nil || result == nil || !result.IsError {
			t.Fatalf("invalid search accepted %+v", args)
		}
	}
}
func TestEntitySearchHTTPByteBoundaryAndState(t *testing.T) {
	for _, prefix := range []string{strings.Repeat("a", 512), strings.Repeat("中", 170) + "ab"} {
		t.Run(fmt.Sprint(len(prefix), prefix[:1]), func(t *testing.T) {
			ctx := entityContext(t)
			old := httpClient
			t.Cleanup(func() { httpClient = old })
			calls := 0
			payload := `{"entities":[],"next_cursor":"next","index_ready":false,"feature_disabled":true}`
			httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/v1/cloudsec/"+entityFixtureOID+"/entities/search" || r.Header.Get("Authorization") == "" {
					t.Fatal("incorrect search route/auth")
				}
				if _, ok := r.Context().Deadline(); !ok {
					t.Fatal("missing deadline")
				}
				want := map[string][]string{"q": {prefix}, "kind": {"host"}, "limit": {"100"}, "cursor": {"opaque"}}
				if !reflect.DeepEqual(map[string][]string(r.URL.Query()), want) {
					t.Fatalf("incorrect selectors %+v", r.URL.Query())
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(payload)), Header: http.Header{}}, nil
			})}
			result, err := searchEntities(ctx, map[string]interface{}{"q": prefix, "kind": "host", "limit": float64(100), "cursor": "opaque", "oid": "foreign"})
			if err != nil {
				t.Fatal(err)
			}
			out := entityResult(t, result)
			if calls != 1 || out["next_cursor"] != "next" || out["index_ready"] != false || out["feature_disabled"] != true {
				t.Fatalf("search state lost %+v calls=%d", out, calls)
			}
		})
	}
}

func TestEntityGitHubLoginPreservesExternalAdapterCard(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	calls := 0
	card := map[string]interface{}{"entity": map[string]interface{}{"id": "eu_aaaa", "kind": "user", "attrs": map[string]interface{}{"external": true}},
		"telemetry_sources": []interface{}{map[string]interface{}{"sid": entityFixtureOID, "platform": "github", "identity_type": "github_login", "hostname": "octo-fixture"}},
		"pivots":            []interface{}{map[string]interface{}{"route": "/sensors/{oid}/{sid}", "permission": "sensor.get", "params": map[string]interface{}{"oid": entityFixtureOID, "sid": entityFixtureOID}}}}
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path == "/v1/cloudsec/"+entityFixtureOID+"/entities/resolve" {
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			want := map[string]interface{}{"identifiers": []interface{}{map[string]interface{}{"type": "github_login", "value": "octo-fixture"}}}
			if r.Method != "POST" || !reflect.DeepEqual(body, want) {
				t.Fatalf("GitHub lookup changed: %s %+v", r.Method, body)
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"index_ready":true,"results":[{"ambiguous":false,"matches":[{"entity_id":"eu_aaaa","confidence":"authoritative"}]}]}`)), Header: http.Header{}}, nil
		}
		if r.Method != "GET" || r.URL.Path != "/v1/cloudsec/"+entityFixtureOID+"/entities/eu_aaaa" {
			t.Fatalf("wrong adapter card request: %s", r.URL)
		}
		body, _ := json.Marshal(map[string]interface{}{"card": card, "index_ready": true})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})}
	result, err := pivotEntity(ctx, map[string]interface{}{"identifier": "octo-fixture", "type": "github_login"})
	if err != nil {
		t.Fatal(err)
	}
	out := entityResult(t, result)
	cards := out["cards"].([]interface{})
	if calls != 2 || len(cards) != 1 || !reflect.DeepEqual(cards[0].(map[string]interface{})["card"], card) {
		t.Fatalf("adapter card lost external status, telemetry or pivots: %+v", out)
	}
}

func TestEntityGitHubUserIDPreservesExternalAdapterCard(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	calls := 0
	card := map[string]interface{}{"entity": map[string]interface{}{"id": "eu_aaaa", "kind": "user", "attrs": map[string]interface{}{"external": true}},
		"telemetry_sources": []interface{}{map[string]interface{}{"sid": entityFixtureOID, "platform": "github", "identity_type": "github_login", "hostname": "12345678901234567890"}},
		"pivots":            []interface{}{map[string]interface{}{"route": "/sensors/{oid}/{sid}", "permission": "sensor.get", "params": map[string]interface{}{"oid": entityFixtureOID, "sid": entityFixtureOID}}}}
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path == "/v1/cloudsec/"+entityFixtureOID+"/entities/resolve" {
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			want := map[string]interface{}{"identifiers": []interface{}{map[string]interface{}{"type": "github_user_id", "value": "12345678901234567890"}}}
			if r.Method != "POST" || !reflect.DeepEqual(body, want) {
				t.Fatalf("GitHub lookup changed: %s %+v", r.Method, body)
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"index_ready":true,"results":[{"ambiguous":false,"matches":[{"entity_id":"eu_aaaa","confidence":"authoritative"}]}]}`)), Header: http.Header{}}, nil
		}
		if r.Method != "GET" || r.URL.Path != "/v1/cloudsec/"+entityFixtureOID+"/entities/eu_aaaa" {
			t.Fatalf("wrong adapter card request: %s", r.URL)
		}
		body, _ := json.Marshal(map[string]interface{}{"card": card, "index_ready": true})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})}
	result, err := pivotEntity(ctx, map[string]interface{}{"identifier": "12345678901234567890", "type": "github_user_id"})
	if err != nil {
		t.Fatal(err)
	}
	out := entityResult(t, result)
	cards := out["cards"].([]interface{})
	if calls != 2 || len(cards) != 1 || !reflect.DeepEqual(cards[0].(map[string]interface{})["card"], card) {
		t.Fatalf("adapter card lost external status, telemetry or pivots: %+v", out)
	}
}

func TestEntityToolsRejectInvalidResolveGetSightingsInput(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		t.Fatal("invalid input made HTTP request")
		return nil, nil
	})}
	tooMany := make([]interface{}, 101)
	for i := range tooMany {
		tooMany[i] = map[string]interface{}{"value": "h"}
	}
	value := func(v interface{}) map[string]interface{} { return map[string]interface{}{"value": v} }
	for _, args := range []map[string]interface{}{
		{}, {"identifiers": "host"}, {"identifiers": []interface{}{}}, {"identifiers": tooMany}, {"identifiers": []interface{}{"host"}},
		{"identifiers": []interface{}{value(nil)}}, {"identifiers": []interface{}{value(" ")}}, {"identifiers": []interface{}{value(strings.Repeat("x", 1025))}},
		{"identifiers": []interface{}{map[string]interface{}{"value": "h", "type": ""}}}, {"identifiers": []interface{}{map[string]interface{}{"value": "h", "type": strings.Repeat("t", 65)}}},
		{"identifiers": []interface{}{value("h")}, "at": -1}, {"identifiers": []interface{}{value("h")}, "at": 1.5},
	} {
		if result, err := resolveEntities(ctx, args); err != nil || result == nil || !result.IsError {
			t.Fatalf("invalid resolve accepted %+v", args)
		}
	}
	for _, args := range []map[string]interface{}{{}, {"entity_id": "../../other"}, {"entity_id": "ex_aaaa"}, {"entity_id": entityFixtureID, "sightings_days": 0}, {"entity_id": entityFixtureID, "sightings_days": 366}, {"entity_id": entityFixtureID, "sightings_days": 1.5}, {"entity_id": entityFixtureID, "sightings_days": "7"}} {
		if result, err := getEntity(ctx, args); err != nil || result == nil || !result.IsError {
			t.Fatalf("invalid get accepted %+v", args)
		}
	}
	for _, args := range []map[string]interface{}{{}, {"entity_id": "../../other"}, {"entity_id": entityFixtureID, "kind": "email"}, {"entity_id": entityFixtureID, "kind": 1}, {"entity_id": entityFixtureID, "since": 20, "until": 10}, {"entity_id": entityFixtureID, "since": -1}, {"entity_id": entityFixtureID, "limit": 0}, {"entity_id": entityFixtureID, "limit": 501}, {"entity_id": entityFixtureID, "limit": 1.5}, {"entity_id": entityFixtureID, "cursor": ""}, {"entity_id": entityFixtureID, "cursor": strings.Repeat("x", 8193)}, {"entity_id": entityFixtureID, "cursor": 7}} {
		if result, err := listEntitySightings(ctx, args); err != nil || result == nil || !result.IsError {
			t.Fatalf("invalid sightings accepted %+v", args)
		}
	}
}

func TestEntityResolveForwardsBatchAndUnknownTypeUnchanged(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	const payload = `{"index_ready":true,"sightings":"forbidden","sources":[{"source":"fixture"}],"observations":{"status":"ok","queries":0,"rows":0},"results":[{"input":{"value":"a@example.com"},"matches":[],"possible":[{"entity_id":"eu_aaaa","confidence":"possible"}]}]}`
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "POST" || r.URL.Path != "/v1/cloudsec/"+entityFixtureOID+"/entities/resolve" || r.Header.Get("Content-Type") != "application/json" || r.URL.Query().Get("oid") != "" {
			t.Fatalf("incorrect resolve request %s %s", r.Method, r.URL)
		}
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		want := map[string]interface{}{"identifiers": []interface{}{
			map[string]interface{}{"value": "a@example.com"},
			map[string]interface{}{"value": "203.0.113.7", "type": "ip"},
			map[string]interface{}{"value": "x", "type": "a_type_added_by_the_backend_later"},
		}, "at": float64(99)}
		if !reflect.DeepEqual(body, want) {
			t.Fatalf("body changed %+v", body)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(payload)), Header: http.Header{}}, nil
	})}
	result, err := resolveEntities(ctx, map[string]interface{}{"identifiers": []interface{}{
		map[string]interface{}{"value": "a@example.com", "ignored": "dropped"},
		map[string]interface{}{"value": "203.0.113.7", "type": "ip"},
		map[string]interface{}{"value": "x", "type": "a_type_added_by_the_backend_later"},
	}, "at": 99, "oid": "foreign"})
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]interface{}
	_ = json.Unmarshal([]byte(payload), &want)
	if got := entityResult(t, result); !reflect.DeepEqual(got, want) {
		t.Fatalf("response not returned unchanged: %+v", got)
	}
}

func TestEntityPivotForwardsUnknownTypeAndPassesThroughTopLevelKeys(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		want := map[string]interface{}{"identifiers": []interface{}{map[string]interface{}{"type": "a_type_added_by_the_backend_later", "value": "x"}}}
		if !reflect.DeepEqual(body, want) {
			t.Fatalf("unknown type was not forwarded: %+v", body)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"index_ready":false,"observations":{"status":"unavailable","reason":"timeout","queries":1,"rows":0},"future_flag":"x","results":[{"input":{"value":"x"}}]}`)), Header: http.Header{}}, nil
	})}
	result, err := pivotEntity(ctx, map[string]interface{}{"identifier": "x", "type": "a_type_added_by_the_backend_later"})
	if err != nil {
		t.Fatal(err)
	}
	out := entityResult(t, result)
	if out["future_flag"] != "x" || out["observations"].(map[string]interface{})["status"] != "unavailable" || len(out["candidates"].([]interface{})) != 1 {
		t.Fatalf("top-level resolve keys dropped: %+v", out)
	}
	if _, present := out["results"]; present {
		t.Fatal("results must only be exposed as candidates")
	}
}

func entitySelectorFixtures() []interface{} {
	return []interface{}{
		map[string]interface{}{"type": "vendor_device_id", "platform": "sophos", "value": "dev-1", "origin_sid": "11111111-2222-4333-8444-555555555555"},
		map[string]interface{}{"type": "foreign_hostname", "value": "laptop-7"},
		map[string]interface{}{"type": "a_selector_type_added_by_the_backend_later", "platform": "a_platform_added_later", "value": "x"},
	}
}

func TestEntityResolveAndPivotForwardObservationSelectorsAndPassObservedMatches(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	const payload = `{"index_ready":true,"observations":{"status":"incomplete","reason":"bounded","queries":3,"rows":20,"truncated":true},"observed_matches":[{"selector":{"type":"foreign_hostname","value":"laptop-7"},"devices":[{"hostname":"laptop-7"}],"truncated":true}],"results":[{"input":{"value":"x"},"matches":[]}]}`
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !reflect.DeepEqual(body["observation_selectors"], entitySelectorFixtures()) {
			t.Fatalf("selectors not forwarded unchanged (unknown type and platform must pass): %+v", body)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(payload)), Header: http.Header{}}, nil
	})}
	var want map[string]interface{}
	_ = json.Unmarshal([]byte(payload), &want)

	result, err := resolveEntities(ctx, map[string]interface{}{"identifiers": []interface{}{map[string]interface{}{"value": "x"}}, "observation_selectors": entitySelectorFixtures()})
	if err != nil {
		t.Fatal(err)
	}
	if got := entityResult(t, result); !reflect.DeepEqual(got, want) {
		t.Fatalf("resolve response not returned unchanged: %+v", got)
	}

	result, err = pivotEntity(ctx, map[string]interface{}{"identifier": "x", "observation_selectors": entitySelectorFixtures()})
	if err != nil {
		t.Fatal(err)
	}
	out := entityResult(t, result)
	if !reflect.DeepEqual(out["observed_matches"], want["observed_matches"]) || !reflect.DeepEqual(out["observations"], want["observations"]) || len(out["candidates"].([]interface{})) != 1 {
		t.Fatalf("pivot dropped observed_matches or observations: %+v", out)
	}
}

func TestEntityObservationSelectorsAbsentOrEmptyAreNotForwarded(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if _, present := body["observation_selectors"]; present {
			t.Fatalf("empty selectors forwarded: %+v", body)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"index_ready":false,"results":[]}`)), Header: http.Header{}}, nil
	})}
	for _, extra := range []map[string]interface{}{{}, {"observation_selectors": []interface{}{}}} {
		args := map[string]interface{}{"identifier": "x"}
		for k, v := range extra {
			args[k] = v
		}
		if result, err := pivotEntity(ctx, args); err != nil || result.IsError {
			t.Fatalf("pivot failed %+v", args)
		}
	}
}

func TestEntityObservationSelectorsRejectBadShapeBeforeHTTP(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		t.Fatal("invalid selectors made HTTP request")
		return nil, nil
	})}
	sel := func(kv ...interface{}) map[string]interface{} {
		m := map[string]interface{}{"type": "foreign_hostname", "value": "h"}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	five := []interface{}{sel(), sel(), sel(), sel(), sel()}
	for name, bad := range map[string]interface{}{
		"more than four":      five,
		"not an array":        "foreign_hostname",
		"item not an object":  []interface{}{"h"},
		"missing type":        []interface{}{map[string]interface{}{"value": "h"}},
		"missing value":       []interface{}{map[string]interface{}{"type": "foreign_hostname"}},
		"empty value":         []interface{}{sel("value", " ")},
		"non-string value":    []interface{}{sel("value", 5)},
		"value over 512":      []interface{}{sel("value", strings.Repeat("v", 513))},
		"non-string type":     []interface{}{sel("type", true)},
		"empty type":          []interface{}{sel("type", "")},
		"non-string platform": []interface{}{sel("platform", 1)},
		"platform too long":   []interface{}{sel("platform", strings.Repeat("p", 65))},
		"non-string origin":   []interface{}{sel("origin_sid", []interface{}{})},
		"origin too long":     []interface{}{sel("origin_sid", strings.Repeat("o", 65))},
		"extra key":           []interface{}{sel("extra", "x")},
	} {
		if result, err := resolveEntities(ctx, map[string]interface{}{"identifiers": []interface{}{map[string]interface{}{"value": "x"}}, "observation_selectors": bad}); err != nil || result == nil || !result.IsError {
			t.Fatalf("resolve accepted %s", name)
		}
		if result, err := pivotEntity(ctx, map[string]interface{}{"identifier": "x", "observation_selectors": bad}); err != nil || result == nil || !result.IsError {
			t.Fatalf("pivot accepted %s", name)
		}
	}
	// Exactly four, and a value of exactly 512 bytes, are accepted shapes.
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"index_ready":false,"results":[]}`)), Header: http.Header{}}, nil
	})}
	four := []interface{}{sel("value", strings.Repeat("v", 512)), sel(), sel(), sel()}
	if result, err := pivotEntity(ctx, map[string]interface{}{"identifier": "x", "observation_selectors": four}); err != nil || result.IsError {
		t.Fatalf("four selectors with a 512-byte value rejected: %+v", result)
	}
}

func TestEntityObservationSelectorsSchemaDescribesItems(t *testing.T) {
	for _, name := range []string{"cloudsec_entity_pivot", "cloudsec_entity_resolve"} {
		registration, ok := tools.GetTool(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		raw, _ := json.Marshal(registration.Schema.InputSchema.Properties["observation_selectors"])
		var prop struct {
			Type  string                 `json:"type"`
			Items map[string]interface{} `json:"items"`
		}
		if json.Unmarshal(raw, &prop) != nil || prop.Type != "array" || prop.Items["type"] != "object" || prop.Items["additionalProperties"] != false {
			t.Fatalf("%s observation_selectors schema incomplete: %s", name, raw)
		}
		props, _ := prop.Items["properties"].(map[string]interface{})
		for _, key := range []string{"type", "value", "platform", "origin_sid"} {
			if _, ok := props[key]; !ok {
				t.Fatalf("%s selector schema lacks %s", name, key)
			}
		}
		for _, required := range registration.Schema.InputSchema.Required {
			if required == "observation_selectors" {
				t.Fatalf("%s must keep observation_selectors optional", name)
			}
		}
	}
}

func TestEntityGetHTTPContract(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  map[string]interface{}
		query map[string][]string
	}{
		{"no window", map[string]interface{}{"entity_id": entityFixtureID}, map[string][]string{}},
		{"window", map[string]interface{}{"entity_id": entityFixtureID, "sightings_days": float64(365), "oid": "foreign"}, map[string][]string{"sightings_days": {"365"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := entityContext(t)
			old := httpClient
			t.Cleanup(func() { httpClient = old })
			const payload = `{"card":null,"index_ready":true,"redirect_to":"eh_bbbb","sightings":"forbidden"}`
			httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method != "GET" || r.URL.Path != "/v1/cloudsec/"+entityFixtureOID+"/entities/"+entityFixtureID || r.Header.Get("Authorization") == "" {
					t.Fatalf("incorrect get request %s", r.URL)
				}
				if got := map[string][]string(r.URL.Query()); !reflect.DeepEqual(got, tc.query) {
					t.Fatalf("incorrect query %+v", got)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(payload)), Header: http.Header{}}, nil
			})}
			result, err := getEntity(ctx, tc.args)
			if err != nil {
				t.Fatal(err)
			}
			out := entityResult(t, result)
			if out["redirect_to"] != "eh_bbbb" || out["index_ready"] != true || out["sightings"] != "forbidden" || out["card"] != nil {
				t.Fatalf("response not returned unchanged: %+v", out)
			}
		})
	}
}

func TestEntitySightingsHTTPContract(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Path != "/v1/cloudsec/"+entityFixtureOID+"/entities/"+entityFixtureID+"/sightings" || r.Header.Get("Authorization") == "" {
			t.Fatalf("incorrect sightings request %s", r.URL)
		}
		want := map[string][]string{"kind": {"ext_ip"}, "since": {"10"}, "until": {"10"}, "limit": {"500"}, "cursor": {"opaque"}}
		if got := map[string][]string(r.URL.Query()); !reflect.DeepEqual(got, want) {
			t.Fatalf("incorrect query %+v", got)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"sightings":[{"kind":"ext_ip","value":"203.0.113.9"}],"next_cursor":"more"}`)), Header: http.Header{}}, nil
	})}
	result, err := listEntitySightings(ctx, map[string]interface{}{"entity_id": entityFixtureID, "kind": "ext_ip", "since": 10, "until": float64(10), "limit": 500, "cursor": "opaque", "oid": "foreign"})
	if err != nil {
		t.Fatal(err)
	}
	if out := entityResult(t, result); out["next_cursor"] != "more" || len(out["sightings"].([]interface{})) != 1 {
		t.Fatalf("response not returned unchanged: %+v", out)
	}
}

func TestEntitySightingsSurfacesMissingPermission(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(`{"error":"missing permission insight.evt.get"}`)), Header: http.Header{}}, nil
	})}
	result, err := listEntitySightings(ctx, map[string]interface{}{"entity_id": entityFixtureID})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("403 was not surfaced as an error: %+v", result)
	}
}
