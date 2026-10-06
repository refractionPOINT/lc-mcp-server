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
	const payload = `{"index_ready":true,"sightings":"forbidden","sources":[{"source":"fixture"}],"observations":{"status":"forbidden","queries":0,"rows":0},"future_field":{"kept":true},"results":[{"input":{"value":"a@example.com"},"matches":[],"possible":[{"entity_id":"eu_aaaa","confidence":"possible"}]}]}`
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
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"index_ready":false,"observations":{"status":"unavailable","reason":"schema_missing","queries":0,"rows":0},"future_flag":"x","results":[{"input":{"value":"x"}}]}`)), Header: http.Header{}}, nil
	})}
	result, err := pivotEntity(ctx, map[string]interface{}{"identifier": "x", "type": "a_type_added_by_the_backend_later"})
	if err != nil {
		t.Fatal(err)
	}
	out := entityResult(t, result)
	if out["future_flag"] != "x" || !reflect.DeepEqual(out["observations"], map[string]interface{}{"status": "unavailable", "reason": "schema_missing", "queries": float64(0), "rows": float64(0)}) || len(out["candidates"].([]interface{})) != 1 {
		t.Fatalf("top-level resolve keys dropped: %+v", out)
	}
	if _, present := out["results"]; present {
		t.Fatal("results must only be exposed as candidates")
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

const entityObservedResolveResponse = `{"index_ready":true,"sightings":"ok",
"observations":{"status":"incomplete","reason":"deadline","queries":3,"rows":41,"truncated":true},
"observed_matches":[{"selector":{"type":"vendor_device_id","value":"dev-1","platform":"sophos"},"truncated":true,
 "devices":[{"origin_sid":"22222222-2222-4222-8222-222222222222","platform":"sophos","vendor_device_id":"dev-1","day":"2026-10-01","names":["laptop-7"],"local_ips":["10.0.0.7"],"approximate":true,"candidates":[{"entity":{"id":"eh_bbbbbbbbbbbbbbbbbbbbbbbbbb","kind":"host"},"confidence":"corroborated","reason":"same hostname and internal IP"}]}]}],
"results":[{"input":{"value":"laptop-7","type":"hostname"},"ambiguous":false,"matches":[],"possible":[]}]}`

func TestEntityResolveSendsValidatedObservationSelectorsAndPassesObservedFieldsThrough(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		want := map[string]interface{}{
			"identifiers": []interface{}{map[string]interface{}{"value": "laptop-7", "type": "hostname"}},
			"at":          float64(1790000000),
			"observation_selectors": []interface{}{
				map[string]interface{}{"type": "vendor_device_id", "value": "dev-1", "platform": "sophos", "origin_sid": "22222222-2222-4222-8222-222222222222"},
				map[string]interface{}{"type": "foreign_hostname", "value": "LAPTOP-7"},
			},
		}
		if !reflect.DeepEqual(body, want) {
			t.Fatalf("body changed %+v", body)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(entityObservedResolveResponse)), Header: http.Header{}}, nil
	})}
	result, err := resolveEntities(ctx, map[string]interface{}{
		"identifiers": []interface{}{map[string]interface{}{"value": "laptop-7", "type": "hostname"}},
		"at":          1790000000,
		"observation_selectors": []interface{}{
			map[string]interface{}{"type": "vendor_device_id", "value": "dev-1", "platform": "sophos", "origin_sid": "22222222-2222-4222-8222-222222222222", "dropped": "x"},
			map[string]interface{}{"type": "foreign_hostname", "value": "LAPTOP-7"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]interface{}
	_ = json.Unmarshal([]byte(entityObservedResolveResponse), &want)
	if got := entityResult(t, result); !reflect.DeepEqual(got, want) {
		t.Fatalf("observed fields not returned unchanged: %+v", got)
	}
}

func TestEntityResolveOmitsSelectorsWhenAbsentOrEmpty(t *testing.T) {
	for name, args := range map[string]map[string]interface{}{
		"absent": {},
		"empty":  {"observation_selectors": []interface{}{}},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := entityContext(t)
			old := httpClient
			t.Cleanup(func() { httpClient = old })
			httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
				var body map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&body)
				if _, present := body["observation_selectors"]; present {
					t.Fatalf("selectors sent without being asked: %+v", body)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"index_ready":true,"results":[]}`)), Header: http.Header{}}, nil
			})}
			args["identifiers"] = []interface{}{map[string]interface{}{"value": "a@example.com"}}
			if result, err := resolveEntities(ctx, args); err != nil || result.IsError {
				t.Fatalf("resolve failed: %+v %v", result, err)
			}
		})
	}
}

func TestEntityPivotForwardsSelectorsAndDoesNotReadObservedCandidateCards(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	const observedHost = "eh_bbbbbbbbbbbbbbbbbbbbbbbbbb"
	gets := 0
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == "GET" {
			gets++
			if strings.HasSuffix(r.URL.Path, observedHost) {
				t.Fatal("pivot read the card of an observed candidate")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"card":{"entity":{"id":"` + entityFixtureID + `"}},"index_ready":true,"observations":{"status":"ok","queries":2,"rows":3},"also_seen_as":[{"platform":"sophos","candidates":[]}],"cloud_sign_ins":[{"platform":"okta","principal":"a@example.com","samples":[]}]}`)), Header: http.Header{}}, nil
		}
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		want := []interface{}{map[string]interface{}{"type": "foreign_hostname", "value": "LAPTOP-7"}}
		if !reflect.DeepEqual(body["observation_selectors"], want) {
			t.Fatalf("pivot did not forward selectors: %+v", body)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"index_ready":true,"observations":{"status":"ok","queries":1,"rows":1},"observed_matches":[{"selector":{"type":"foreign_hostname","value":"LAPTOP-7"},"devices":[{"candidates":[{"entity":{"id":"` + observedHost + `"},"confidence":"corroborated"}]}]}],"results":[{"ambiguous":false,"matches":[{"entity_id":"` + entityFixtureID + `","confidence":"authoritative"}]}]}`)), Header: http.Header{}}, nil
	})}
	result, err := pivotEntity(ctx, map[string]interface{}{"identifier": "host", "observation_selectors": []interface{}{map[string]interface{}{"type": "foreign_hostname", "value": "LAPTOP-7"}}})
	if err != nil {
		t.Fatal(err)
	}
	out := entityResult(t, result)
	cards := out["cards"].([]interface{})
	if gets != 1 || len(cards) != 1 || len(out["observed_matches"].([]interface{})) != 1 || out["observations"].(map[string]interface{})["status"] != "ok" {
		t.Fatalf("observed fields lost or extra cards read: %+v gets=%d", out, gets)
	}
	card := cards[0].(map[string]interface{})
	if len(card["also_seen_as"].([]interface{})) != 1 || len(card["cloud_sign_ins"].([]interface{})) != 1 || card["observations"].(map[string]interface{})["queries"] != float64(2) {
		t.Fatalf("card observed pivots reshaped: %+v", card)
	}
}

func TestEntityGetPassesThroughObservedFieldsAndChromeIdentity(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	const payload = `{"card":{"entity":{"id":"eu_aaaa","kind":"user"},"telemetry_sources":[{"platform":"chrome","identity_source":"mapping"}]},"index_ready":true,"redirect_to":"eu_aaaa","observations":{"status":"unavailable","reason":"query_budget","queries":0,"rows":0},"also_seen_as":[],"cloud_sign_ins":[]}`
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(payload)), Header: http.Header{}}, nil
	})}
	result, err := getEntity(ctx, map[string]interface{}{"entity_id": entityFixtureID})
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]interface{}
	_ = json.Unmarshal([]byte(payload), &want)
	if got := entityResult(t, result); !reflect.DeepEqual(got, want) {
		t.Fatalf("get response not returned unchanged: %+v", got)
	}
}

func TestEntityObservationSelectorsAreValidatedBeforeAnyHTTPCall(t *testing.T) {
	ctx := entityContext(t)
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		t.Fatal("invalid observation selector made an HTTP request")
		return nil, nil
	})}
	sel := func(typ string, kv ...interface{}) interface{} {
		m := map[string]interface{}{"type": typ}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	good := sel("foreign_hostname", "value", "h")
	five := []interface{}{good, good, good, good, good}
	const sid = "22222222-2222-4222-8222-222222222222"
	for name, selectors := range map[string]interface{}{
		"not an array":            "foreign_hostname",
		"too many":                five,
		"item not an object":      []interface{}{"h"},
		"unknown type":            []interface{}{sel("hostname", "value", "h")},
		"missing type":            []interface{}{map[string]interface{}{"value": "h"}},
		"missing value":           []interface{}{sel("foreign_hostname")},
		"non-string value":        []interface{}{sel("foreign_hostname", "value", 7)},
		"blank value":             []interface{}{sel("foreign_hostname", "value", " \t")},
		"invalid utf8":            []interface{}{sel("foreign_hostname", "value", "a\xffb")},
		"hostname too long":       []interface{}{sel("foreign_hostname", "value", strings.Repeat("h", 513))},
		"hostname with platform":  []interface{}{sel("foreign_hostname", "value", "h", "platform", "sophos")},
		"hostname with origin":    []interface{}{sel("foreign_hostname", "value", "h", "origin_sid", sid)},
		"device without platform": []interface{}{sel("vendor_device_id", "value", "d")},
		"device unknown platform": []interface{}{sel("vendor_device_id", "value", "d", "platform", "github")},
		"device platform case":    []interface{}{sel("vendor_device_id", "value", "d", "platform", "Sophos")},
		"device non-string plat":  []interface{}{sel("vendor_device_id", "value", "d", "platform", 3)},
		"device id too long":      []interface{}{sel("vendor_device_id", "value", strings.Repeat("d", 129), "platform", "okta")},
		"origin uppercase":        []interface{}{sel("vendor_device_id", "value", "d", "platform", "okta", "origin_sid", strings.ToUpper("abcdefab-abcd-4abc-8abc-abcdefabcdef"))},
		"origin not a uuid":       []interface{}{sel("vendor_device_id", "value", "d", "platform", "okta", "origin_sid", "abc")},
		"one bad among good":      []interface{}{good, sel("vendor_device_id", "value", "d")},
	} {
		t.Run(name, func(t *testing.T) {
			identifiers := []interface{}{map[string]interface{}{"value": "h"}}
			if result, err := resolveEntities(ctx, map[string]interface{}{"identifiers": identifiers, "observation_selectors": selectors}); err != nil || result == nil || !result.IsError {
				t.Fatal("invalid selectors accepted by resolve")
			}
			if result, err := pivotEntity(ctx, map[string]interface{}{"identifier": "h", "observation_selectors": selectors}); err != nil || result == nil || !result.IsError {
				t.Fatal("invalid selectors accepted by pivot")
			}
		})
	}
}

func TestEntityObservationSelectorsAcceptBoundaryValues(t *testing.T) {
	for _, platform := range []string{"sophos", "crowdstrike", "office365", "entraid", "okta", "duo"} {
		selectors, ok, err := entitySelectors(map[string]interface{}{"observation_selectors": []interface{}{
			map[string]interface{}{"type": "vendor_device_id", "value": strings.Repeat("d", 128), "platform": platform},
		}})
		if err != nil || !ok || len(selectors) != 1 {
			t.Fatalf("platform %s refused: %v", platform, err)
		}
	}
	four := []interface{}{}
	for i := 0; i < 4; i++ {
		four = append(four, map[string]interface{}{"type": "foreign_hostname", "value": strings.Repeat("h", 512)})
	}
	if selectors, ok, err := entitySelectors(map[string]interface{}{"observation_selectors": four}); err != nil || !ok || len(selectors) != 4 {
		t.Fatalf("four 512-byte hostnames refused: %v", err)
	}
	// Typed as []map[string]interface{} the way in-process callers may build it.
	if _, ok, err := entitySelectors(map[string]interface{}{"observation_selectors": []map[string]interface{}{{"type": "foreign_hostname", "value": "h"}}}); err != nil || !ok {
		t.Fatalf("typed slice refused: %v", err)
	}
}

func TestEntityObservationToolsDescribeTheContract(t *testing.T) {
	for _, name := range []string{"cloudsec_entity_resolve", "cloudsec_entity_pivot"} {
		registration, ok := tools.GetTool(name)
		if !ok {
			t.Fatal(name)
		}
		if _, present := registration.Schema.InputSchema.Properties["observation_selectors"]; !present {
			t.Fatalf("%s lacks observation_selectors", name)
		}
	}
	for _, name := range []string{"cloudsec_entity_resolve", "cloudsec_entity_pivot", "cloudsec_entity_get"} {
		registration, _ := tools.GetTool(name)
		for _, term := range []string{"UNKNOWN", "schema_missing", "query_budget", "observations", "redirect_to"} {
			if name == "cloudsec_entity_get" && term == "observations" {
				continue
			}
			if !strings.Contains(registration.Schema.Description, term) {
				t.Fatalf("%s description lacks %q", name, term)
			}
		}
	}
}
