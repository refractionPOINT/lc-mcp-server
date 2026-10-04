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
	for _, name := range []string{"cloudsec_entity_search",
		"cloudsec_entity_pivot", "cloudsec_entity_activity"} {
		registration, ok := tools.GetTool(name)
		if !ok || !registration.RequiresOID || registration.Schema.Annotations.ReadOnlyHint == nil || !*registration.Schema.Annotations.ReadOnlyHint || registration.Schema.Annotations.DestructiveHint == nil || *registration.Schema.Annotations.DestructiveHint {
			t.Fatalf("unsafe registration %s", name)
		}
		for _, profile := range []string{"cloud_security", "cloud_security_readonly"} {
			if !entityMember(tools.GetToolsForProfile(profile), name) {
				t.Fatalf("missing %s in %s", name, profile)
			}
		}
	}
}
func TestEntityToolsRejectInvalidInputBeforeAuth(t *testing.T) {
	for _, args := range []map[string]interface{}{{}, {"identifier": 123}, {"identifier": " "}, {"identifier": strings.Repeat("x", 1025)}, {"identifier": "host", "type": "unknown"}, {"identifier": "host", "at": 1.5}, {"identifier": "host", "at": true}, {"identifier": "host", "at": -1}} {
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
