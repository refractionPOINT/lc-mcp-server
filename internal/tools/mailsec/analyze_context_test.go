package mailsec

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func TestAnalyzeOrganizationContextSelectionAndPreviewResponse(t *testing.T) {
	reg, _ := tools.GetTool("mailsec_analyze")
	property, ok := reg.Schema.InputSchema.Properties["with_org_context"].(map[string]interface{})
	if !ok || property["type"] != "boolean" {
		t.Fatal("org context must be advertised as an optional boolean", property)
	}
	for _, name := range reg.Schema.InputSchema.Required {
		if name == "with_org_context" {
			t.Fatal("org context became mandatory")
		}
	}
	const preview = `{"context":"preview","org_context_read":false,"unavailable_evidence":["attachment_explosion","link_detonation"],"unevaluated_rules":[{"rule_id":"synthetic-rule","unavailable_evidence":["threat_feeds"]}],"mdm":{"verdict":{"top_signals":[{"rule_id":"synthetic-rule","depends_on_missing_context":true}]}}}`
	for _, tc := range []struct {
		name           string
		present, value bool
	}{
		{"omitted", false, false}, {"false", true, false}, {"true", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]interface{}{"eml_b64": "AP+A", "org_domains": []string{"corp.example"}}
			if tc.present {
				args["with_org_context"] = tc.value
			}
			requests := 0
			ctx := fixtureContext(t, func(r *http.Request) (*http.Response, error) {
				requests++
				if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
					t.Fatal("analyze must use the JSON POST body", r.Method, r.URL, r.Header)
				}
				var body map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				value, present := body["with_org_context"]
				if present != tc.present || (present && value != tc.value) || body["eml_b64"] != "AP+A" {
					t.Fatal("context selection or original bytes lost", body)
				}
				if _, present := body["direction"]; present {
					t.Fatal("tool invented a direction", body)
				}
				return response(200, preview), nil
			})
			result := call(t, ctx, "mailsec_analyze", args, false)
			var got, want map[string]interface{}
			if err := json.Unmarshal([]byte(resultText(t, result)), &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(preview), &want); err != nil {
				t.Fatal(err)
			}
			if requests != 1 || !reflect.DeepEqual(got, want) {
				t.Fatal("preview evidence or conditional signal was discarded", got)
			}
		})
	}
	bad := call(t, context.Background(), "mailsec_analyze", map[string]interface{}{"eml": "From: sender@example.test\r\n\r\nHello", "with_org_context": "true"}, true)
	if !strings.Contains(resultText(t, bad), "boolean") {
		t.Fatal("wrong type silently dropped", resultText(t, bad))
	}
}

// Literal sizes independently protect the public route-specific contract.
func TestAnalyzeLargeEMLRequestLimit(t *testing.T) {
	for _, tc := range []struct {
		name        string
		base64Bytes int
		wantError   bool
	}{
		{"above ordinary limit is sent", 2 << 20, false},
		{"above analyze limit is refused", 17 << 20, true},
		{"JSON envelope counts toward limit", 16 << 20, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eml := strings.Repeat("A", tc.base64Bytes)
			requests := 0
			ctx := fixtureContext(t, func(r *http.Request) (*http.Response, error) {
				requests++
				if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/analyze") {
					t.Fatal("wrong large EML route", r.Method, r.URL)
				}
				var body map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body["eml_b64"] != eml {
					t.Fatal("large EML was truncated or discarded")
				}
				return response(200, `{"context":"preview"}`), nil
			})
			result := call(t, ctx, "mailsec_analyze", map[string]interface{}{"eml_b64": eml}, tc.wantError)
			if tc.wantError {
				if requests != 0 || !strings.Contains(resultText(t, result), "16 MiB (16777216 bytes)") {
					t.Fatal("oversized analyze must fail locally with the envelope limit", requests, resultText(t, result))
				}
			} else if requests != 1 {
				t.Fatal("large supported analyze was not sent", requests)
			}
		})
	}
}
