package cloudsec

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sanitizedMapFixture() map[string]interface{} {
	return map[string]interface{}{"schema": "lc-iac-map/v1", "repository": map[string]interface{}{"provider": "github", "name": "acme/repo", "commit": strings.Repeat("a", 40)}, "tool": "terraform", "workspace": "prod", "source_kind": "state_identity", "observed_at": "2026-09-30T12:00:00Z", "complete": true, "successful": true, "resources": []interface{}{map[string]interface{}{"address": "google_storage_bucket.logs", "type": "google_storage_bucket", "provider": "gcp", "scope": map[string]interface{}{"project": "fixture-project"}, "identity": map[string]interface{}{"name": "fixture-bucket"}}}}
}
func TestSanitizedMapRefusesRawOrArbitraryDataBeforeTransport(t *testing.T) {
	for _, mutate := range []func(map[string]interface{}){
		func(d map[string]interface{}) { d["terraform_version"] = "1.8" },
		func(d map[string]interface{}) { d["oid"] = "foreign" },
		func(d map[string]interface{}) { d["schema"] = "terraform-state" },
		func(d map[string]interface{}) { d["complete"] = "false" },
		func(d map[string]interface{}) { d["repository"].(map[string]interface{})["commit"] = "main" },
		func(d map[string]interface{}) {
			d["resources"].([]interface{})[0].(map[string]interface{})["values"] = map[string]interface{}{"token": "secret"}
		},
		func(d map[string]interface{}) {
			d["resources"].([]interface{})[0].(map[string]interface{})["desired"] = map[string]interface{}{"force_destroy": "secret"}
		},
		func(d map[string]interface{}) {
			d["resources"].([]interface{})[0].(map[string]interface{})["desired"] = map[string]interface{}{"password": true}
		},
		func(d map[string]interface{}) {
			d["resources"].([]interface{})[0].(map[string]interface{})["scope"].(map[string]interface{})["password"] = "secret"
		},
		func(d map[string]interface{}) {
			d["resources"].([]interface{})[0].(map[string]interface{})["desired"] = map[string]interface{}{"force_destroy": true}
		},
	} {
		d := sanitizedMapFixture()
		mutate(d)
		_, e := validateSanitizedMap(d)
		require.Error(t, e)
		reg, _ := tools.GetTool("cloudsec_code_iac_map_push")
		r, e := reg.Handler(context.Background(), map[string]interface{}{"document": d})
		require.NoError(t, e)
		require.True(t, r.IsError)
		assert.NotContains(t, codeResultText(r), "secret")
		assert.NotContains(t, codeResultText(r), "organization")
	}
	d := sanitizedMapFixture()
	d["source_kind"] = "plan_desired"
	d["resources"].([]interface{})[0].(map[string]interface{})["desired"] = map[string]interface{}{"force_destroy": false}
	_, e := validateSanitizedMap(d)
	require.NoError(t, e)
}
func TestSanitizedMapPushUsesExactSafeEnvelope(t *testing.T) {
	doc := sanitizedMapFixture()
	productTransport(t, func(r *http.Request) string {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/v1/cloudsec/"+oidForProvenanceTest+"/code/iac-map", r.URL.Path)
		var b map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&b))
		assert.Equal(t, doc, b)
		return `{"result":{"status":"processing","hash":"fixture"}}`
	})
	reg, _ := tools.GetTool("cloudsec_code_iac_map_push")
	r, e := reg.Handler(productTestContext(t), map[string]interface{}{"document": doc, "oid": "foreign"})
	require.NoError(t, e)
	require.False(t, r.IsError, codeResultText(r))
	assert.Contains(t, codeResultText(r), "processing")
}
func TestIaCExtractorIsOperatorOptInLocalAndDoesNotLeakEnvironment(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("test requires POSIX shell")
	}
	t.Setenv("MCP_MODE", "http")
	reg, _ := tools.GetTool("cloudsec_code_iac_map_extract")
	r, e := reg.Handler(context.Background(), map[string]interface{}{})
	require.NoError(t, e)
	require.True(t, r.IsError)
	t.Setenv("MCP_MODE", "stdio")
	t.Setenv("LC_IAC_MAP_EXTRACTOR", "")
	args := map[string]interface{}{"input": "/tmp/terraform.json", "repository": "acme/repo", "commit": strings.Repeat("a", 40), "source_kind": "state_identity"}
	r, e = reg.Handler(context.Background(), args)
	require.NoError(t, e)
	require.True(t, r.IsError)
	assert.Contains(t, codeResultText(r), "explicitly configure")
	t.Setenv("LC_AUTH_SECRET", "do-not-leak")
	raw, e := json.Marshal(sanitizedMapFixture())
	require.NoError(t, e)
	binary := filepath.Join(t.TempDir(), "extractor")
	script := "#!/bin/sh\n[ -z \"$LC_AUTH_SECRET\" ] || exit 9\nprintf '%s' '" + string(raw) + "'\n"
	require.NoError(t, os.WriteFile(binary, []byte(script), 0700))
	t.Setenv("LC_IAC_MAP_EXTRACTOR", binary)
	r, e = reg.Handler(context.Background(), args)
	require.NoError(t, e)
	require.False(t, r.IsError, codeResultText(r))
	assert.Contains(t, codeResultText(r), `"uploaded":false`)
	assert.NotContains(t, codeResultText(r), "do-not-leak")
	require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\nprintf 'sensitive raw input' >&2\nexit 1\n"), 0700))
	r, e = reg.Handler(context.Background(), args)
	require.NoError(t, e)
	require.True(t, r.IsError)
	assert.NotContains(t, codeResultText(r), "sensitive raw input")
	// A successful binary still cannot return raw state as the tool's result.
	require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s' '{\"terraform_version\":\"1.8\",\"password\":\"sensitive\"}'\n"), 0700))
	r, e = reg.Handler(context.Background(), args)
	require.NoError(t, e)
	require.True(t, r.IsError)
	assert.NotContains(t, codeResultText(r), "sensitive")
}
func TestCertificateRotationCarriesOnlyPublicResponse(t *testing.T) {
	productTransport(t, func(r *http.Request) string {
		body, e := io.ReadAll(r.Body)
		require.NoError(t, e)
		assert.JSONEq(t, `{"connection":"entra","replace":true}`, string(body))
		return `{"certificate":"Zml4dHVyZQ==","thumbprint":"fixture"}`
	})
	reg, _ := tools.GetTool("cloudsec_mint_m365_certificate")
	r, e := reg.Handler(productTestContext(t), map[string]interface{}{"connection": "entra", "replace": true})
	require.NoError(t, e)
	require.False(t, r.IsError)
	assert.NotContains(t, codeResultText(r), "private_key")
}

func TestExtractorOutputIsBoundedDuringWrite(t *testing.T) {
	var output bytes.Buffer
	stopped := false
	writer := &boundedExtractionWriter{writer: &output, remaining: 5, stop: func() { stopped = true }}
	n, err := writer.Write([]byte("123456789"))
	require.Error(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "12345", output.String())
	assert.True(t, stopped)
	n, err = writer.Write([]byte("more"))
	require.Error(t, err)
	assert.Equal(t, 0, n)
	assert.Equal(t, "12345", output.String())
}
