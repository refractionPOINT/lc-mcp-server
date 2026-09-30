package cloudsec

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func productTestContext(t *testing.T) context.Context {
	cache := auth.NewSDKCache(time.Minute, nil)
	t.Cleanup(cache.Close)
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Hour).Unix())))
	return auth.WithAuthContext(auth.WithSDKCache(context.Background(), cache), &auth.AuthContext{Mode: auth.AuthModeNormal, OID: oidForProvenanceTest, JWTToken: "eyJhbGciOiJIUzI1NiJ9." + payload + ".synthetic"})
}
func productTransport(t *testing.T, handler func(*http.Request) string) {
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		require.Equal(t, "api.limacharlie.io", r.URL.Host)
		require.NotEmpty(t, r.Header.Get("Authorization"))
		_, deadline := r.Context().Deadline()
		require.True(t, deadline)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(handler(r))), Header: http.Header{}}, nil
	})}
}

func TestExpandedCloudSecWireContracts(t *testing.T) {
	sha := strings.Repeat("a", 40)
	for _, tc := range []struct {
		name, method, suffix string
		args                 map[string]interface{}
		query                url.Values
		body                 map[string]interface{}
	}{
		{name: "cloudsec_code_status", method: "GET", suffix: "code/status"},
		{name: "cloudsec_code_sbom", method: "GET", suffix: "code/sbom", args: map[string]interface{}{"repo": "group/sub/repo", "provider": "gitlab"}, query: url.Values{"repo": {"group/sub/repo"}, "provider": {"gitlab"}}},
		{name: "cloudsec_code_rescan", method: "POST", suffix: "code/scan", args: map[string]interface{}{"repo": "acme/repo", "ref": "main", "provider": "gitlab"}, body: map[string]interface{}{"repo": "acme/repo", "ref": "main", "provider": "gitlab"}},
		{name: "cloudsec_code_pr_check", method: "POST", suffix: "code/pr_check", args: map[string]interface{}{"repo": "acme/repo", "pr": float64(42), "head_sha": sha, "provider": "gitlab", "action": "synchronize"}, body: map[string]interface{}{"repo": "acme/repo", "pr": float64(42), "head_sha": sha, "provider": "gitlab", "action": "synchronize"}},
		{name: "cloudsec_code_webhook", method: "POST", suffix: "code/webhook", args: map[string]interface{}{"connection": "github-acme", "url": "https://us.hook.limacharlie.io/adapter", "secret": "fixture-secret"}, body: map[string]interface{}{"connection": "github-acme", "url": "https://us.hook.limacharlie.io/adapter", "secret": "fixture-secret"}},
		{name: "cloudsec_code_ingest", method: "POST", suffix: "code/ingest", args: map[string]interface{}{"source": "sarif", "repo": "acme/repo", "commit": sha, "document": map[string]interface{}{"version": "2.1.0", "runs": []interface{}{}}}, body: map[string]interface{}{"source": "sarif", "repo": "acme/repo", "commit": sha, "document": map[string]interface{}{"version": "2.1.0", "runs": []interface{}{}}}},
		{name: "cloudsec_mint_m365_certificate", method: "POST", suffix: "providers/m365/certificate", args: map[string]interface{}{"connection": "entra", "client_id": "fixture-app", "replace": false}, body: map[string]interface{}{"connection": "entra", "client_id": "fixture-app", "replace": false}},
		{name: "cloudsec_code_image_repos", method: "GET", suffix: "code/image-repos", args: map[string]interface{}{"provider": []interface{}{"aws", "gcp"}, "region": []interface{}{"us-east-1"}, "has_images": false, "sort": "images", "limit": float64(500)}, query: url.Values{"provider": {"aws", "gcp"}, "region": {"us-east-1"}, "has_images": {"false"}, "sort": {"images"}, "limit": {"500"}}},
		{name: "cloudsec_code_image_repo_facets", method: "GET", suffix: "code/image-repos/facets", args: map[string]interface{}{"lineage_facet": false, "account": []interface{}{"prod"}}, query: url.Values{"lineage_facet": {"false"}, "account": {"prod"}}},
		{name: "cloudsec_code_image", method: "GET", suffix: "code/images/sha256:" + strings.Repeat("a", 64), args: map[string]interface{}{"digest": "sha256:" + strings.Repeat("a", 64)}},
		{name: "cloudsec_list_compliance_runs", method: "GET", suffix: "compliance/runs", args: map[string]interface{}{"run_id": "fixture-run", "limit": float64(17)}, query: url.Values{"run_id": {"fixture-run"}, "limit": {"17"}}},
		{name: "cloudsec_list_compliance_attestations", method: "GET", suffix: "compliance/attestations", args: map[string]interface{}{"assignment": "prod", "framework": "cis-gcp"}, query: url.Values{"assignment": {"prod"}, "framework": {"cis-gcp"}}},
		{name: "cloudsec_list_compliance_events", method: "GET", suffix: "compliance/events", args: map[string]interface{}{"assignment": "prod", "days": float64(14)}, query: url.Values{"assignment": {"prod"}, "days": {"14"}}},
		{name: "cloudsec_export_compliance_run", method: "GET", suffix: "compliance/export", args: map[string]interface{}{"run_id": "fixture-run", "format": "pdf", "brand": "acme"}, query: url.Values{"run_id": {"fixture-run"}, "format": {"pdf"}, "brand": {"acme"}}},
		{name: "cloudsec_list_compliance_schedules", method: "GET", suffix: "compliance/schedules"},
		{name: "cloudsec_get_azure_scope_hierarchy", method: "GET", suffix: "azure/scope-hierarchy"},
		{name: "cloudsec_create_compliance_run", method: "POST", suffix: "compliance/v2", args: map[string]interface{}{"assignment": "prod", "run_id": "fixture-run"}, body: map[string]interface{}{"assignment": "prod", "run_id": "fixture-run"}},
		{name: "cloudsec_create_compliance_attestation", method: "POST", suffix: "compliance/attestations", args: map[string]interface{}{"attestation": map[string]interface{}{"id": "att-1", "revision": float64(1), "assignment": "prod", "framework_id": "cis-gcp", "control_key": "control-1", "outcome": "pass"}}, body: map[string]interface{}{"id": "att-1", "revision": float64(1), "assignment": "prod", "framework_id": "cis-gcp", "control_key": "control-1", "outcome": "pass"}},
		{name: "cloudsec_set_compliance_schedule", method: "POST", suffix: "compliance/schedules", args: map[string]interface{}{"schedule": map[string]interface{}{"id": "weekly", "enabled": false, "destination_ref": "output://compliance"}}, body: map[string]interface{}{"id": "weekly", "enabled": false, "destination_ref": "output://compliance"}},
		{name: "cloudsec_code_iac_map_status", method: "GET", suffix: "code/iac-map/status", args: map[string]interface{}{"repository": "acme/repo", "provider": "github", "workspace": "prod", "source_kind": "state_identity", "hash": strings.Repeat("a", 64)}, query: url.Values{"repository": {"acme/repo"}, "provider": {"github"}, "workspace": {"prod"}, "source_kind": {"state_identity"}, "hash": {strings.Repeat("a", 64)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			productTransport(t, func(r *http.Request) string {
				calls++
				assert.Equal(t, tc.method, r.Method)
				assert.Equal(t, "/v1/cloudsec/"+oidForProvenanceTest+"/"+tc.suffix, r.URL.Path)
				if tc.query != nil {
					assert.Equal(t, tc.query, r.URL.Query())
				} else {
					assert.Empty(t, r.URL.RawQuery)
				}
				if tc.body != nil {
					var b map[string]interface{}
					require.NoError(t, json.NewDecoder(r.Body).Decode(&b))
					assert.Equal(t, tc.body, b)
				}
				return `{"accepted":true,"url":"https://untrusted.invalid/signed","controls":[{"control_key":"historical"}]}`
			})
			args := tc.args
			if args == nil {
				args = map[string]interface{}{}
			}
			args["oid"] = "untrusted"
			args["api_url"] = "https://untrusted.invalid"
			reg, ok := tools.GetTool(tc.name)
			require.True(t, ok)
			result, e := reg.Handler(productTestContext(t), args)
			require.NoError(t, e)
			require.False(t, result.IsError, codeResultText(result))
			assert.Equal(t, 1, calls)
		})
	}
}

func TestLineageReceiptFailsClosed(t *testing.T) {
	for _, receipt := range []string{`null`, `[]`, `["verified"]`, `["verified","unknown"]`, `["unknown","verified"]`} {
		t.Run(receipt, func(t *testing.T) {
			productTransport(t, func(r *http.Request) string {
				assert.Equal(t, []string{"unknown", "verified"}, r.URL.Query()["lineage_status"])
				assert.Equal(t, "false", r.URL.Query().Get("signed"))
				return `{"images":[{"secret":"private-fixture-row"}],"applied_lineage_status":` + receipt + `}`
			})
			reg, _ := tools.GetTool("cloudsec_code_images")
			result, e := reg.Handler(productTestContext(t), map[string]interface{}{"lineage_status": []interface{}{" VERIFIED ", "unknown", "verified"}, "signed": false})
			require.NoError(t, e)
			assert.Equal(t, receipt != `["unknown","verified"]`, result.IsError)
			if result.IsError {
				assert.NotContains(t, codeResultText(result), "private-fixture-row")
			}
		})
	}
	for _, v := range []interface{}{nil, []interface{}{}, []interface{}{"verified", nil}, []interface{}{"not-real"}, true} {
		result, e := handleImageRead(context.Background(), map[string]interface{}{"lineage_status": v}, "code/images", true, false)
		require.NoError(t, e)
		require.True(t, result.IsError)
		assert.Contains(t, codeResultText(result), "lineage_status")
	}
}

func TestPRCheckValidationAndProviderCommitRules(t *testing.T) {
	sha := strings.Repeat("a", 40)
	for _, tc := range []struct {
		provider, action, base, head, previous string
		pr                                     interface{}
		valid                                  bool
	}{
		{"github", "opened", sha, sha, "", float64(1), true}, {"github", "opened", "", sha, "", 1, false},
		{"gitlab", "opened", "", sha, "", 1, true}, {"bitbucket", "synchronize", "", strings.Repeat("b", 12), "", 1, true},
		{"gitlab", "edited", "", sha, sha, 1, false}, {"github", "edited", sha, sha, "", 1, false}, {"github", "edited", sha, sha, sha, 1, true},
		{"github", "opened", sha, sha, "", 1.5, false}, {"github", "closed", sha, sha, "", 1, false}, {"github", "opened", sha, "main", "", 1, false},
	} {
		args := map[string]interface{}{"repo": "acme/repo", "provider": tc.provider, "action": tc.action, "pr": tc.pr, "base_sha": tc.base, "head_sha": tc.head, "prev_base_sha": tc.previous}
		result, e := handleCodePRCheck(context.Background(), args)
		require.NoError(t, e)
		if tc.valid {
			assert.Contains(t, codeResultText(result), "organization")
		} else {
			assert.NotContains(t, codeResultText(result), "organization")
		}
		require.True(t, result.IsError)
	}
}

func TestResumableCSVContract(t *testing.T) {
	for _, dataset := range []string{"findings", "inventory"} {
		t.Run(dataset, func(t *testing.T) {
			productTransport(t, func(r *http.Request) string {
				assert.Equal(t, "/v1/cloudsec/"+oidForProvenanceTest+"/"+dataset, r.URL.Path)
				assert.Equal(t, "1000", r.URL.Query().Get("max_rows"))
				assert.Equal(t, "opaque", r.URL.Query().Get("cursor"))
				assert.Equal(t, "csv", r.URL.Query().Get("format"))
				if dataset == "findings" {
					assert.Equal(t, []string{"breached"}, r.URL.Query()["sla"])
				} else {
					assert.Equal(t, "true", r.URL.Query().Get("account_empty"))
				}
				return "id,value\n1,ok\n# next_cursor=next-token\n"
			})
			args := map[string]interface{}{"dataset": dataset, "max_rows": 1000, "cursor": "opaque"}
			if dataset == "findings" {
				args["sla"] = []interface{}{"breached"}
			} else {
				args["account_empty"] = true
			}
			r, e := handleExportCSV(productTestContext(t), args)
			require.NoError(t, e)
			require.False(t, r.IsError, codeResultText(r))
			assert.Contains(t, codeResultText(r), "# next_cursor=next-token")
		})
	}
	for _, args := range []map[string]interface{}{{"dataset": "findings", "cursor": "ignored"}, {"dataset": "findings", "max_rows": 1.5}, {"dataset": "findings", "max_rows": 0}, {"dataset": "findings", "max_rows": 100001}, {"dataset": "query", "max_rows": 1}, {"dataset": "inventory", "grain": []interface{}{"cve"}}} {
		r, e := handleExportCSV(context.Background(), args)
		require.NoError(t, e)
		assert.True(t, r.IsError)
		assert.NotContains(t, codeResultText(r), "organization")
	}
	productTransport(t, func(r *http.Request) string {
		return "id,value\n" + strings.Repeat("x", 100) + "\n# next_cursor=next\n"
	})
	r, e := handleExportCSV(productTestContext(t), map[string]interface{}{"dataset": "findings", "max_rows": 1000, "max_bytes": 20})
	require.NoError(t, e)
	require.True(t, r.IsError)
	assert.Contains(t, codeResultText(r), "no resumable CSV")
}

func TestNewFindingSelectorsAndCSVRecordBoundaries(t *testing.T) {
	q := map[string]interface{}{}
	args := map[string]interface{}{"sla": []interface{}{"due_soon", "breached"}, "image_urn": []interface{}{"lcrn:image"}, "grain": []interface{}{"cve"}, "fix_state": []interface{}{"unknown"}, "exploit_band": []interface{}{"none"}, "cause": "cause:key", "sort": "due_at"}
	require.Nil(t, addFindingSelector(q, args, false))
	assert.Equal(t, []string{"due_soon", "breached"}, q["sla"])
	assert.Equal(t, "cause:key", q["cause"])
	assert.Equal(t, "due_at", q["sort"])
	for _, key := range []string{"sla", "image_urn", "grain", "fix_state", "exploit_band"} {
		for _, invalid := range []interface{}{nil, true, float64(42), map[string]interface{}{}, []interface{}{}} {
			require.NotNil(t, addFindingSelector(map[string]interface{}{}, map[string]interface{}{key: []interface{}{"valid", invalid}}, false), "%s must refuse %T", key, invalid)
		}
	}
	doc := "id,value\n1,\"line one\nline two\"\n2,ok\n"
	cut := truncateCSV(doc, 20)
	assert.Equal(t, "id,value\n", strings.Split(cut, "# truncated")[0])
	assert.NotContains(t, cut, "line one")
	// A legitimate data row can start with '#'. Treating it as a comment would
	// skip the opening quote and mistake a line inside its value for a row boundary.
	cut = truncateCSV("id,value\n#finding,\"line one\nline two\nline three\"\n2,ok\n", 40)
	assert.Equal(t, "id,value\n", strings.Split(cut, "# truncated")[0])
}

func TestCSVExportDoesNotReportAbortedChunksAsComplete(t *testing.T) {
	for _, tc := range []struct {
		name, document     string
		bounded, wantError bool
	}{
		{"backend failure", "id,value\n1,ok\n# export aborted: backend error after 1 rows\n", true, true},
		{"stuck cursor", "id,value\n1,ok\n# export aborted: cursor did not advance after 1 rows\n", true, true},
		{"full export failure", "id,value\n1,ok\n# export aborted: exceeded 2000 pages after 1 rows\n", false, true},
		{"legacy cap without continuation", "id,value\n1,ok\n# truncated at 100000 rows - narrow the filter set for a complete export\n", true, true},
		{"resume marker", "id,value\n1,ok\n# next_cursor=opaque - export chunk ended after 1 rows; repeat the request with cursor=opaque for the rest\n", true, false},
		{"marker in a quoted field", "id,value\n1,\"evidence\n# export aborted: untrusted message\"\n", true, false},
		{"malformed complete body", "id,value\n1,\"unterminated", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			productTransport(t, func(*http.Request) string { return tc.document })
			args := map[string]interface{}{"dataset": "findings"}
			if tc.bounded {
				args["max_rows"] = 1000
			}
			result, err := handleExportCSV(productTestContext(t), args)
			require.NoError(t, err)
			assert.Equal(t, tc.wantError, result.IsError, codeResultText(result))
		})
	}
}

func TestCSVByteLimitStillAppliesAfterRemovingIaCReceipt(t *testing.T) {
	receipt := "# lc_iac_filters_v1=" + base64.RawURLEncoding.EncodeToString([]byte(`{"has_iac_origin":true}`)) + "\n"
	for _, value := range []string{strings.Repeat("x", 100), "\"line one\n" + strings.Repeat("x", 100) + "\""} {
		productTransport(t, func(*http.Request) string { return receipt + "id,value\n1," + value + "\n" })
		result, err := handleExportCSV(productTestContext(t), map[string]interface{}{"dataset": "findings", "has_iac_origin": true, "max_bytes": len(receipt) + 20})
		require.NoError(t, err)
		require.False(t, result.IsError, codeResultText(result))
		text := codeResultText(result)
		assert.Equal(t, "id,value\n", strings.Split(text, "# truncated")[0])
		assert.Contains(t, text, "# truncated by lc-mcp-server")
		assert.NotContains(t, text, "lc_iac_filters_v1")
	}
	productTransport(t, func(*http.Request) string { return receipt + "id,value\n1,ok\n" })
	result, err := handleExportCSV(productTestContext(t), map[string]interface{}{"dataset": "findings", "has_iac_origin": true, "max_bytes": len(receipt)})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, codeResultText(result), "raise max_bytes")
}

func TestImageFiltersRefuseMalformedSelectorsBeforeAuthentication(t *testing.T) {
	for _, args := range []map[string]interface{}{
		{"running": "false"}, {"signed": 0}, {"limit": 1.5}, {"limit": 0}, {"limit": 1001},
		{"account": map[string]interface{}{"name": "prod"}}, {"registry": []interface{}{"valid", nil}},
		{"provider": []interface{}{}}, {"q": true}, {"repo_urn": []interface{}{""}},
	} {
		result, err := handleImageRead(context.Background(), args, "code/images", true, false)
		require.NoError(t, err)
		require.True(t, result.IsError)
		assert.NotContains(t, codeResultText(result), "organization")
	}
	for _, args := range []map[string]interface{}{{"has_images": "false"}, {"lineage_facet": 1}, {"region": false}} {
		result, err := handleImageRead(context.Background(), args, "code/image-repos/facets", false, true)
		require.NoError(t, err)
		require.True(t, result.IsError)
		assert.NotContains(t, codeResultText(result), "organization")
	}
}

func TestRawCloudSecTransportDoesNotFollowRedirects(t *testing.T) {
	destinationCalls := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationCalls++; w.Write([]byte(`{"accepted":true}`)) }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	defer redirect.Close()
	response, err := httpClient.Get(redirect.URL)
	require.NoError(t, err)
	defer response.Body.Close()
	assert.Equal(t, http.StatusFound, response.StatusCode)
	assert.Equal(t, 0, destinationCalls, "gateway redirects must not cause a second credentialed request")
}

func TestLocalScannerUsesOnlyOperatorImageBinaryAndRulesConfiguration(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("test requires POSIX shell")
	}
	directory := t.TempDir()
	trace := filepath.Join(directory, "argv")
	cli := filepath.Join(directory, "limacharlie")
	script := "#!/bin/sh\n[ \"$1\" = cloudsec ] && exit 0\nprintf '%s\\n' \"$@\" > \"$LC_TEST_ARGV\"\nprev=\nreport=\nfor arg do\n [ \"$prev\" = -o ] && report=$arg\n prev=$arg\ndone\nprintf '%s' '{}' > \"$report\"\n"
	require.NoError(t, os.WriteFile(cli, []byte(script), 0700))
	t.Setenv("LC_TEST_ARGV", trace)
	t.Setenv("LC_CODE_SCANNER_IMAGE", "accessible/scanner:v1")
	t.Setenv("LC_CODE_SCANNER_BINARY", "/operator/scanner")
	t.Setenv("LC_CODE_SCANNER_RULES_FILE", "/operator/rules.json")
	document, err := runLocalCodeScan(context.Background(), localScanSpec{CLI: cli, Path: directory, Scanners: "sast", Timeout: time.Minute})
	require.NoError(t, err)
	assert.Equal(t, []byte("{}"), document)
	raw, err := os.ReadFile(trace)
	require.NoError(t, err)
	argv := string(raw)
	assert.Contains(t, argv, "--no-ingest\n")
	assert.Contains(t, argv, "--image\naccessible/scanner:v1\n")
	assert.Contains(t, argv, "--binary\n/operator/scanner\n")
	assert.Contains(t, argv, "--rules-file\n/operator/rules.json\n")
	reg, _ := tools.GetTool("cloudsec_code_scan_local")
	for _, key := range []string{"cli", "image", "binary", "rules_file"} {
		_, present := reg.Schema.InputSchema.Properties[key]
		assert.False(t, present, "executable choices remain operator-only")
	}
}

func TestEmptyAccountAndCauseSelectorsRejectWrongTypes(t *testing.T) {
	for _, key := range []string{"account_empty", "account_unscoped"} {
		query := map[string]interface{}{}
		require.NotNil(t, addInventorySelector(query, map[string]interface{}{key: "false"}))
		assert.NotContains(t, query, key)
		require.Nil(t, addInventorySelector(query, map[string]interface{}{key: false}))
		assert.Equal(t, false, query[key])
	}
	require.NotNil(t, addFindingSelector(map[string]interface{}{}, map[string]interface{}{"cause": map[string]interface{}{"key": "cause:one"}}, false))
}
