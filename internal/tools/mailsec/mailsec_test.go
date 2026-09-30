package mailsec

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

const fixtureOID = "11111111-1111-4111-8111-111111111111"

type mockTransport func(*http.Request) (*http.Response, error)

func (f mockTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fixtureContext(t *testing.T, fn mockTransport) context.Context {
	t.Helper()
	cache := auth.NewSDKCache(time.Minute, nil)
	t.Cleanup(cache.Close)
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: fn, CheckRedirect: original.CheckRedirect}
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Hour).Unix())))
	ctx := auth.WithSDKCache(context.Background(), cache)
	return auth.WithAuthContext(ctx, &auth.AuthContext{Mode: auth.AuthModeNormal, OID: fixtureOID, JWTToken: "eyJhbGciOiJIUzI1NiJ9." + payload + ".synthetic"})
}

func response(status int, data string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(data)), Header: http.Header{}}
}

func call(t *testing.T, ctx context.Context, name string, args map[string]interface{}, wantError bool) *mcp.CallToolResult {
	t.Helper()
	reg, ok := tools.GetTool(name)
	if !ok {
		t.Fatalf("tool not registered: %s", name)
	}
	result, err := reg.Invoke(ctx, args)
	if err != nil || result == nil || result.IsError != wantError {
		t.Fatalf("%s: got result %+v err %v, want IsError %v", name, result, err, wantError)
	}
	return result
}

func resultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	var text strings.Builder
	for _, item := range result.Content {
		if v, ok := item.(mcp.TextContent); ok {
			text.WriteString(v.Text)
		}
	}
	return text.String()
}

// These expectations are independent of the declarative definitions: a typo in
// an API method, permission or path must fail, not become the test's expectation.
func TestRegisteredRouteContracts(t *testing.T) {
	cases := []struct {
		name, method, path, permission string
		readOnly, destructive          bool
		args                           map[string]interface{}
	}{
		{"mailsec_get_coverage", "GET", "coverage", "mailsec.get", true, false, nil},
		{"mailsec_list_messages", "GET", "messages", "mailsec.get", true, false, nil},
		{"mailsec_get_message", "GET", "messages/message", "mailsec.get", true, false, map[string]interface{}{"msg_uuid": "message"}},
		{"mailsec_get_message_eml", "GET", "messages/message/eml", "mailsec.get AND mailsec.get.eml", true, false, map[string]interface{}{"msg_uuid": "message", "justification": "Investigate report"}},
		{"mailsec_list_similar_messages", "GET", "messages/message/similar", "mailsec.get", true, false, map[string]interface{}{"msg_uuid": "message"}},
		{"mailsec_list_verdict_revisions", "GET", "messages/message/revisions", "mailsec.get", true, false, map[string]interface{}{"msg_uuid": "message"}},
		{"mailsec_revise_verdict", "POST", "messages/message/verdict", "mailsec.act", false, true, map[string]interface{}{"msg_uuid": "message", "verdict": "malicious", "rationale": []string{"Confirmed impersonation"}}},
		{"mailsec_act_on_message", "POST", "messages/message/actions", "mailsec.act", false, true, map[string]interface{}{"msg_uuid": "message", "action": "trash_message"}},
		{"mailsec_list_campaigns", "GET", "campaigns", "mailsec.get", true, false, nil},
		{"mailsec_get_campaign", "GET", "campaigns/campaign", "mailsec.get", true, false, map[string]interface{}{"campaign_id": "campaign"}},
		{"mailsec_preview_campaign_action", "POST", "campaigns/campaign/actions", "mailsec.act", true, false, map[string]interface{}{"campaign_id": "campaign", "action": "trash_message"}},
		{"mailsec_act_on_campaign", "POST", "campaigns/campaign/actions", "mailsec.act", false, true, map[string]interface{}{"campaign_id": "campaign", "action": "trash_message", "confirm": "reviewed"}},
		{"mailsec_preview_bulk_action", "POST", "actions/bulk/preview", "mailsec.get", true, false, map[string]interface{}{"action": "trash_message", "msg_uuids": []string{"message"}}},
		{"mailsec_execute_bulk_action", "POST", "actions/bulk/execute", "mailsec.act", false, true, map[string]interface{}{"action": "trash_message", "msg_uuids": []string{"message"}, "confirm": "reviewed"}},
		{"mailsec_get_bulk_action", "GET", "actions/bulk/bulk", "mailsec.get", true, false, map[string]interface{}{"bulk_id": "bulk"}},
		{"mailsec_get_sender_profile", "GET", "senders/sender", "mailsec.get", true, false, map[string]interface{}{"key": "sender"}},
		{"mailsec_get_action", "GET", "actions/action", "mailsec.get", true, false, map[string]interface{}{"action_id": "action"}},
		{"mailsec_analyze", "POST", "analyze", "mailsec.get", true, false, map[string]interface{}{"eml_b64": "U3ViamVjdDogZXhhbXBsZQ=="}},
		{"mailsec_list_reports", "GET", "reports", "mailsec.get", true, false, nil},
		{"mailsec_get_report", "GET", "reports/report", "mailsec.get", true, false, map[string]interface{}{"report_id": "report"}},
		{"mailsec_resolve_report", "POST", "reports/report/resolve", "mailsec.set", false, true, map[string]interface{}{"report_id": "report", "disposition": "true_positive"}},
		{"mailsec_reopen_report", "POST", "reports/report/reopen", "mailsec.set", false, false, map[string]interface{}{"report_id": "report"}},
		{"mailsec_validate_rule", "POST", "rules/validate", "mailsec.get", true, false, map[string]interface{}{"rule": map[string]interface{}{"name": "fixture"}}},
		{"mailsec_backtest_rule", "POST", "rules/backtest", "mailsec.get", true, false, map[string]interface{}{"rule": map[string]interface{}{"phase": "pre_verdict"}}},
		{"mailsec_test_connection", "POST", "connections/connection/test", "mailsec.act", false, false, map[string]interface{}{"record": "connection"}},
		{"mailsec_get_onboarding", "GET", "onboarding", "mailsec.get", true, false, nil},
		{"mailsec_prepare_tenant_purge", "GET", "tenant", "mailsec.act AND billing.ctrl AND user.ctrl", true, false, nil},
		{"mailsec_purge_tenant", "DELETE", "tenant", "mailsec.act AND billing.ctrl AND user.ctrl", false, true, map[string]interface{}{"confirmation": "owner-reviewed"}},
	}
	if len(definitions()) != len(cases) {
		t.Fatal("route coverage matrix needs updating")
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg, _ := tools.GetTool(tc.name)
			if reg == nil || reg.Profile != "email_security" || !reg.RequiresOID {
				t.Fatal("missing registration/profile/org gate")
			}
			if !strings.Contains(reg.Description, "Requires "+tc.permission+".") || reg.Schema.Annotations.ReadOnlyHint == nil || *reg.Schema.Annotations.ReadOnlyHint != tc.readOnly || reg.Schema.Annotations.DestructiveHint == nil || *reg.Schema.Annotations.DestructiveHint != tc.destructive {
				t.Fatal("permission or annotations differ from the gateway contract")
			}
			calls := 0
			ctx := fixtureContext(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != tc.method || r.URL.EscapedPath() != "/v1/mailsec/"+fixtureOID+"/"+tc.path {
					t.Fatalf("wrong request %s %s", r.Method, r.URL)
				}
				if !strings.HasPrefix(r.Header.Get("Authorization"), "bearer ") || r.URL.Host != "api.limacharlie.io" {
					t.Fatal("authentication or API root changed")
				}
				if _, ok := r.Context().Deadline(); !ok {
					t.Fatal("no request deadline")
				}
				if tc.method == "POST" {
					if r.Header.Get("Content-Type") != "application/json" {
						t.Fatal("SDK form encoding would discard request fields")
					}
					body := map[string]interface{}{}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					for _, key := range []string{"oid", "actor", "by", "source", "url", "msg_uuid", "campaign_id", "report_id", "record"} {
						if _, exists := body[key]; exists {
							t.Fatalf("identity/path field leaked into body: %s", key)
						}
					}
					if tc.name == "mailsec_revise_verdict" && body["mode"] != "ai" {
						t.Fatal("agent revision should default to ai mode")
					}
				}
				switch tc.name {
				case "mailsec_get_message_eml":
					return response(200, `{"eml_b64":"AP+A","size":3}`), nil
				case "mailsec_execute_bulk_action":
					return response(200, `{"accepted":true,"bulk_id":"bulk"}`), nil
				case "mailsec_purge_tenant":
					if r.URL.Query().Get("confirmation") != "owner-reviewed" {
						t.Fatal("purge confirmation missing from query")
					}
					return response(200, `{"complete":true}`), nil
				default:
					return response(200, `{"ok":true}`), nil
				}
			})
			args := map[string]interface{}{"oid": "foreign", "actor": "forged", "by": "forged", "source": "forged", "url": "https://untrusted.invalid"}
			for k, v := range tc.args {
				args[k] = v
			}
			call(t, ctx, tc.name, args, false)
			if calls != 1 {
				t.Fatalf("want one call, got %d", calls)
			}
		})
	}
}

func TestSelectorsAndOpaqueCursorPreserved(t *testing.T) {
	want := url.Values{"verdict": {"malicious", "suspicious"}, "state": {"quarantined", "delivered"}, "direction": {"inbound", "internal"}, "user_reported": {"false"}, "since": {"2026-09-01T00:00:00Z"}, "until": {"1790726400"}, "cursor": {"opaque +/= token"}, "q": {"invoice"}, "limit": {"17"}, "lane": {"backfill"}, "min_score": {"0"}}
	ctx := fixtureContext(t, func(r *http.Request) (*http.Response, error) {
		if !reflect.DeepEqual(r.URL.Query(), want) {
			t.Fatalf("filters changed: got %v want %v", r.URL.Query(), want)
		}
		return response(200, `{"messages":[],"next_cursor":"next +/= token"}`), nil
	})
	result := call(t, ctx, "mailsec_list_messages", map[string]interface{}{"verdict": []interface{}{"malicious", "suspicious"}, "state": []string{"quarantined", "delivered"}, "direction": []string{"inbound", "internal"}, "user_reported": false, "since": "2026-09-01T00:00:00Z", "until": "1790726400", "cursor": "opaque +/= token", "q": "invoice", "limit": float64(17), "lane": "backfill", "min_score": 0}, false)
	if !strings.Contains(resultText(t, result), "next +/= token") {
		t.Fatal("response cursor changed")
	}
}

func TestOnboardingAndSavedConnectionContracts(t *testing.T) {
	calls := 0
	ctx := fixtureContext(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			want := url.Values{"provider": {"gworkspace"}, "project_id": {"customer-project"}, "sa_email": {"mail@example.iam.gserviceaccount.com"}, "topic": {"mail-topic"}, "subscription": {"mail-pull"}}
			if !reflect.DeepEqual(r.URL.Query(), want) {
				t.Fatal("onboarding placeholders lost")
			}
		} else {
			if !strings.HasSuffix(r.URL.EscapedPath(), "connections/saved%2Frecord/test") {
				t.Fatal("saved record path not escaped")
			}
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			if !reflect.DeepEqual(body, map[string]interface{}{"include_watch": false}) {
				t.Fatal("watch opt-in broadened or saved connection changed", body)
			}
		}
		return response(200, `{"ok":true}`), nil
	})
	call(t, ctx, "mailsec_get_onboarding", map[string]interface{}{"provider": "gworkspace", "project_id": "customer-project", "sa_email": "mail@example.iam.gserviceaccount.com", "topic": "mail-topic", "subscription": "mail-pull"}, false)
	call(t, ctx, "mailsec_test_connection", map[string]interface{}{"record": "saved/record", "include_watch": false, "credentials": "not sent"}, false)
}

func TestExplicitConfirmationAndNormalizedBulkSelection(t *testing.T) {
	steps := 0
	ctx := fixtureContext(t, func(r *http.Request) (*http.Response, error) {
		steps++
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if strings.Contains(r.URL.Path, "/bulk/") {
			if !reflect.DeepEqual(body["msg_uuids"], []interface{}{"a", "b"}) || body["attempt"] != "run 1" {
				t.Fatal("bulk token inputs not normalized identically", body)
			}
		}
		if strings.HasSuffix(r.URL.Path, "/preview") || steps == 3 {
			if body["confirm"] != nil || body["force"] != nil {
				t.Fatal("preview can execute", body)
			}
		} else if body["confirm"] != "reviewed token" || body["force"] != false || body["reason"] != "IR approved" {
			t.Fatal("execution lost explicit confirmation/override/audit reason", body)
		}
		return response(200, `{"accepted":true,"bulk_id":"job","confirm":"reviewed token"}`), nil
	})
	call(t, ctx, "mailsec_preview_bulk_action", map[string]interface{}{"action": "quarantine_message", "msg_uuids": []string{" b ", "a", "b", " "}, "attempt": "run 1"}, false)
	call(t, ctx, "mailsec_execute_bulk_action", map[string]interface{}{"action": "quarantine_message", "msg_uuids": []string{"b", " a "}, "attempt": "run 1", "confirm": "reviewed token", "force": false, "reason": "IR approved"}, false)
	call(t, ctx, "mailsec_preview_campaign_action", map[string]interface{}{"campaign_id": "campaign", "action": "trash_message"}, false)
	call(t, ctx, "mailsec_act_on_campaign", map[string]interface{}{"campaign_id": "campaign", "action": "trash_message", "confirm": "reviewed token", "force": false, "reason": "IR approved"}, false)
	if steps != 4 {
		t.Fatal("tools autonomously executed/polled/retried")
	}
}

func TestInvalidConstraintsRefusedBeforeAnyRequest(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
	}{
		{"mailsec_list_messages", map[string]interface{}{"user_reported": "false"}},
		{"mailsec_list_messages", map[string]interface{}{"verdict": []interface{}{"malicious", 3}}},
		{"mailsec_list_messages", map[string]interface{}{"state": []string{}}},
		{"mailsec_list_messages", map[string]interface{}{"limit": 0}},
		{"mailsec_list_messages", map[string]interface{}{"limit": 1001}},
		{"mailsec_list_messages", map[string]interface{}{"limit": 1.5}},
		{"mailsec_list_messages", map[string]interface{}{"min_score": -1}},
		{"mailsec_list_messages", map[string]interface{}{"q": "invoice", "sender_root_domain": "example.com"}},
		{"mailsec_list_messages", map[string]interface{}{"q": strings.Repeat("x", 513), "since": "1790726400"}},
		{"mailsec_list_messages", map[string]interface{}{"lane": "live", "mailbox": "pilot@example.com"}},
		{"mailsec_list_messages", map[string]interface{}{"lane": "invalid"}},
		{"mailsec_get_coverage", map[string]interface{}{"window_days": 36}},
		{"mailsec_get_coverage", map[string]interface{}{"window_days": 7, "until": "1790726400"}},
		{"mailsec_get_message_eml", map[string]interface{}{"msg_uuid": "message", "justification": " "}},
		{"mailsec_get_message", map[string]interface{}{"msg_uuid": ".."}},
		{"mailsec_get_campaign", map[string]interface{}{"campaign_id": "."}},
		{"mailsec_get_sender_profile", map[string]interface{}{"key": ".."}},
		{"mailsec_test_connection", map[string]interface{}{"record": ".."}},
		{"mailsec_list_similar_messages", map[string]interface{}{"msg_uuid": "message", "cursor": "opaque"}},
		{"mailsec_list_similar_messages", map[string]interface{}{"msg_uuid": "message", "limit": 2}},
		{"mailsec_revise_verdict", map[string]interface{}{"msg_uuid": "message", "verdict": "malicious", "rationale": []string{" "}}},
		{"mailsec_revise_verdict", map[string]interface{}{"msg_uuid": "message", "verdict": "malicious", "rationale": []string{strings.Repeat("é", 281)}}},
		{"mailsec_revise_verdict", map[string]interface{}{"msg_uuid": "message", "verdict": "malicious", "rationale": []string{"evidence"}, "mode": "impersonate"}},
		{"mailsec_preview_campaign_action", map[string]interface{}{"campaign_id": "campaign", "action": "trash_message", "confirm": "would execute"}},
		{"mailsec_preview_campaign_action", map[string]interface{}{"campaign_id": "campaign", "action": "trash_message", "force": false}},
		{"mailsec_act_on_campaign", map[string]interface{}{"campaign_id": "campaign", "action": "trash_message"}},
		{"mailsec_execute_bulk_action", map[string]interface{}{"action": "trash_message", "msg_uuids": []string{"a"}}},
		{"mailsec_preview_bulk_action", map[string]interface{}{"action": "trash_message", "msg_uuids": []string{" "}}},
		{"mailsec_analyze", nil},
		{"mailsec_validate_rule", map[string]interface{}{"rule": "not a rule object"}},
		{"mailsec_purge_tenant", nil},
		{"mailsec_purge_tenant", map[string]interface{}{"confirmation": "owner-reviewed", "reason": strings.Repeat("x", 1025)}},
		{"mailsec_prepare_tenant_purge", map[string]interface{}{"confirmation": "would delete"}},
	}
	ids := []string{}
	for i := 0; i < 501; i++ {
		ids = append(ids, fmt.Sprint(i))
	}
	cases = append(cases, struct {
		name string
		args map[string]interface{}
	}{"mailsec_preview_bulk_action", map[string]interface{}{"action": "trash_message", "msg_uuids": ids}})
	for _, tc := range cases {
		t.Run(tc.name+fmt.Sprint(tc.args), func(t *testing.T) {
			// A bare context has no credentials: validation must still name the
			// invalid constraint instead of authenticating or issuing a request.
			result := call(t, context.Background(), tc.name, tc.args, true)
			if strings.Contains(resultText(t, result), "cannot get organization") {
				t.Fatal("invalid constraint got as far as authentication")
			}
		})
	}
}

func TestEMLAndUncertainOutcomesRemainHonest(t *testing.T) {
	cases := []struct {
		name, data, want string
		args             map[string]interface{}
	}{
		{"mailsec_get_message_eml", `{"eml_b64":"AP+A","size":4}`, "mismatched size", map[string]interface{}{"msg_uuid": "message", "justification": "Incident review"}},
		{"mailsec_get_message_eml", `{"eml_b64":"not-base64","size":4}`, "invalid base64", map[string]interface{}{"msg_uuid": "message", "justification": "Incident review"}},
		{"mailsec_execute_bulk_action", `{"accepted":false,"bulk_id":""}`, "not accepted", map[string]interface{}{"action": "trash_message", "msg_uuids": []string{"a"}, "confirm": "reviewed"}},
		{"mailsec_execute_bulk_action", `{"accepted":true,"bulk_id":123}`, "not accepted", map[string]interface{}{"action": "trash_message", "msg_uuids": []string{"a"}, "confirm": "reviewed"}},
		{"mailsec_execute_bulk_action", `{"accepted":true,"bulk_id":true}`, "not accepted", map[string]interface{}{"action": "trash_message", "msg_uuids": []string{"a"}, "confirm": "reviewed"}},
		{"mailsec_purge_tenant", `{"complete":false,"deleted_messages":23,"error":"storage unavailable"}`, "deleted_messages", map[string]interface{}{"confirmation": "owner-reviewed"}},
	}
	for _, tc := range cases {
		t.Run(tc.name+tc.want, func(t *testing.T) {
			calls := 0
			ctx := fixtureContext(t, func(r *http.Request) (*http.Response, error) { calls++; return response(200, tc.data), nil })
			result := call(t, ctx, tc.name, tc.args, true)
			if calls != 1 || !strings.Contains(resultText(t, result), tc.want) {
				t.Fatal("lost incomplete outcome or retried", result, calls)
			}
		})
	}
	for _, status := range []int{401, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			ctx := fixtureContext(t, func(r *http.Request) (*http.Response, error) {
				calls++
				return response(status, `{"reason":"try later"}`), nil
			})
			result := call(t, ctx, "mailsec_purge_tenant", map[string]interface{}{"confirmation": "owner-reviewed"}, true)
			if calls != 1 || !strings.Contains(resultText(t, result), fmt.Sprint(status)) {
				t.Fatal("write was retried or refusal swallowed")
			}
		})
	}
	t.Run("ambiguous timeout", func(t *testing.T) {
		calls := 0
		ctx := fixtureContext(t, func(r *http.Request) (*http.Response, error) { calls++; return nil, context.DeadlineExceeded })
		result := call(t, ctx, "mailsec_act_on_message", map[string]interface{}{"msg_uuid": "message", "action": "trash_message"}, true)
		if calls != 1 || !strings.Contains(resultText(t, result), "inspect the action audit") {
			t.Fatal("ambiguous provider action retried or presented as definite failure")
		}
	})
	if httpClient.CheckRedirect == nil || httpClient.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("authenticated requests can follow an untrusted redirect")
	}
}

func TestGatewayPathSegmentsRemainOpaque(t *testing.T) {
	for _, key := range []string{"email:person+tag@example.com", "domain:example.com", "saved/record?oid=foreign#fragment", "../coverage"} {
		t.Run(key, func(t *testing.T) {
			ctx := fixtureContext(t, func(r *http.Request) (*http.Response, error) {
				// Gateway matches EscapedPath before decoding each path parameter
				// (service/server.go, service/router.go). Decode after splitting,
				// matching that order: slashes/query characters stay in one key.
				segments := strings.Split(r.URL.EscapedPath(), "/")
				if len(segments) != 6 || segments[4] != "senders" || r.URL.RawQuery != "" || r.URL.Fragment != "" {
					t.Fatal("key altered gateway route or query", r.URL)
				}
				decoded, err := url.PathUnescape(segments[5])
				if err != nil || decoded != key {
					t.Fatal("gateway key would differ", decoded, err)
				}
				return response(200, `{"profile":null}`), nil
			})
			call(t, ctx, "mailsec_get_sender_profile", map[string]interface{}{"key": key}, false)
		})
	}
}

func TestReadOnlyRuleAndReportBodiesArePreserved(t *testing.T) {
	checks := []struct {
		name string
		args map[string]interface{}
	}{
		{"mailsec_analyze", map[string]interface{}{"eml_b64": "AP+A", "org_domains": []string{"example.com"}, "direction": "internal"}},
		{"mailsec_validate_rule", map[string]interface{}{"rule": map[string]interface{}{"name": "purpose-aware", "phase": "pre_verdict", "detect": map[string]interface{}{"op": "is", "path": "mail_type/type", "value": "solicitation"}}, "rule_id": "customer-purpose"}},
		{"mailsec_backtest_rule", map[string]interface{}{"rule": map[string]interface{}{"phase": "pre_verdict"}, "since": "2026-09-01T00:00:00Z", "until": "1790726400", "rule_id": "customer-purpose"}},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			ctx := fixtureContext(t, func(r *http.Request) (*http.Response, error) {
				var body map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				got, _ := json.Marshal(body)
				want, _ := json.Marshal(tc.args)
				if string(got) != string(want) {
					t.Fatal("nested rule/raw data/selectors lost", string(got), string(want))
				}
				return response(200, `{"valid":false,"reason":"candidate refused","precision":null,"truncated":true}`), nil
			})
			result := call(t, ctx, tc.name, tc.args, false)
			if !strings.Contains(resultText(t, result), "candidate refused") || !strings.Contains(resultText(t, result), "truncated") {
				t.Fatal("application-level validation/coverage discarded")
			}
		})
	}
	ctx := fixtureContext(t, func(r *http.Request) (*http.Response, error) {
		if !reflect.DeepEqual(r.URL.Query(), url.Values{"status": {"open", "triaging"}, "oldest_first": {"false"}, "limit": {"3"}, "cursor": {"reports + cursor"}}) {
			t.Fatal("report selector or ordering lost", r.URL)
		}
		return response(200, `{"reports":[],"next_cursor":""}`), nil
	})
	call(t, ctx, "mailsec_list_reports", map[string]interface{}{"status": []string{"open", "triaging"}, "oldest_first": false, "limit": 3, "cursor": "reports + cursor"}, false)
}

func TestOversizedJSONRefusedBeforeAuthentication(t *testing.T) {
	result := call(t, context.Background(), "mailsec_analyze", map[string]interface{}{"eml": strings.Repeat("x", maxRequestBytes)}, true)
	if !strings.Contains(resultText(t, result), "1 MiB") {
		t.Fatal("oversized payload did not fail before authentication")
	}
}

func TestPrivilegedEMLResponseHasRoomBeyondOrdinaryJSONCap(t *testing.T) {
	// Whitespace padding keeps the fixture small after decoding while exercising
	// real bounded HTTP reads on both routes at the ordinary response ceiling.
	data := strings.Repeat(" ", maxResponseBytes) + `{"eml_b64":"AP+A","size":3}`
	ctx := fixtureContext(t, func(r *http.Request) (*http.Response, error) {
		return response(200, data), nil
	})
	ordinary := call(t, ctx, "mailsec_get_message", map[string]interface{}{"msg_uuid": "message"}, true)
	if !strings.Contains(resultText(t, ordinary), "response exceeded") {
		t.Fatal("ordinary JSON response cap was not enforced")
	}
	call(t, ctx, "mailsec_get_message_eml", map[string]interface{}{"msg_uuid": "message", "justification": "Incident investigation"}, false)
	if maxEMLResponseBytes < (100<<20)*4/3 {
		t.Fatal("EML cap cannot represent the parser's raw-byte ceiling")
	}
}
