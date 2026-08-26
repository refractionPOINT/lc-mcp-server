package cloudsec

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// codeResultText flattens a tool result's text content for assertions.
func codeResultText(result *mcp.CallToolResult) string {
	if result == nil {
		return ""
	}
	var b strings.Builder
	for _, content := range result.Content {
		if text, ok := content.(mcp.TextContent); ok {
			b.WriteString(text.Text)
		}
	}
	return b.String()
}

// ------------------------------------------------------------------
// cloudsec_code_findings scoping
// ------------------------------------------------------------------

// The whole reason this tool exists separately from cloudsec_list_findings is the
// scoping rule, and getting it wrong is silent: the findings route has no "has a
// repository" selector, so a list call that drops the repo constraint returns the
// organization's CLOUD findings too, under a tool named for the code lane.
func TestCodeFindingsWillNotListUnscoped(t *testing.T) {
	t.Run("a list with no repo is refused, not widened", func(t *testing.T) {
		_, _, errResult := codeFindingsRequest(map[string]interface{}{})
		require.NotNil(t, errResult)
		assert.Contains(t, codeResultText(errResult), "any repository")
	})

	t.Run("a list whose only repo is blank is refused too", func(t *testing.T) {
		// An empty repository key cannot match: the column is NULL for every
		// non-repository finding rather than "". Forwarding it would send an
		// unconstrained list under the guise of a filtered one.
		_, _, errResult := codeFindingsRequest(map[string]interface{}{
			"repo": []interface{}{"", "   "},
		})
		require.NotNil(t, errResult)
	})

	t.Run("facets need no repo and go to the facets route", func(t *testing.T) {
		suffix, q, errResult := codeFindingsRequest(map[string]interface{}{"facets": true})
		require.Nil(t, errResult)
		assert.Equal(t, "findings/facets", suffix)
		// The facet mode is not paginated; forwarding a cursor would be a lie about
		// what the counts describe.
		assert.NotContains(t, q, "cursor")
		assert.NotContains(t, q, "limit")
	})

	t.Run("a repo scopes the list and the rest of the selector rides along", func(t *testing.T) {
		suffix, q, errResult := codeFindingsRequest(map[string]interface{}{
			"repo":          []interface{}{"acme/api", "", "acme/web"},
			"severity":      []interface{}{"CRITICAL", "HIGH"},
			"finding_class": []interface{}{"code_weakness"},
			"kev":           false,
			"limit":         float64(50),
			"cursor":        "abc",
		})
		require.Nil(t, errResult)
		assert.Equal(t, "findings", suffix)
		assert.Equal(t, []string{"acme/api", "acme/web"}, q["repo"])
		assert.Equal(t, []string{"CRITICAL", "HIGH"}, q["severity"])
		assert.Equal(t, []string{"code_weakness"}, q["finding_class"])
		// kev=false is a REAL selection (findings on resources with no KEV), so it
		// has to survive; absent would leave the dimension unconstrained.
		assert.Equal(t, false, q["kev"])
		assert.Equal(t, 50, q["limit"])
		assert.Equal(t, "abc", q["cursor"])
	})

	t.Run("a blank repo is dropped from an otherwise real selection", func(t *testing.T) {
		_, q, errResult := codeFindingsRequest(map[string]interface{}{
			"repo": []interface{}{"acme/api", ""},
		})
		require.Nil(t, errResult)
		assert.Equal(t, []string{"acme/api"}, q["repo"])
	})
}

// ------------------------------------------------------------------
// cloudsec_code_scan_local
// ------------------------------------------------------------------

func TestResolveLocalScanners(t *testing.T) {
	t.Run("empty takes the default set", func(t *testing.T) {
		got, errResult := resolveLocalScanners("")
		require.Nil(t, errResult)
		assert.Equal(t, defaultLocalScanners, got)
	})

	t.Run("secrets is refused with the reason", func(t *testing.T) {
		_, errResult := resolveLocalScanners("sca,secrets")
		require.NotNil(t, errResult)
		assert.Contains(t, codeResultText(errResult), "hosted lane")
	})

	t.Run("an unknown engine is refused, never dropped", func(t *testing.T) {
		// Dropping it would run a narrower scan and report success — a clean result
		// for a pass that never happened.
		_, errResult := resolveLocalScanners("sca,iacc")
		require.NotNil(t, errResult)
		assert.Contains(t, codeResultText(errResult), "unknown scanner")
	})

	t.Run("names are normalized and re-joined", func(t *testing.T) {
		got, errResult := resolveLocalScanners(" SCA , iac ")
		require.Nil(t, errResult)
		assert.Equal(t, "sca,iac", got)
	})

	t.Run("a list of only separators is refused", func(t *testing.T) {
		_, errResult := resolveLocalScanners(", ,")
		require.NotNil(t, errResult)
	})
}

func TestLocalScanSpecValidation(t *testing.T) {
	dir := t.TempDir()

	t.Run("a missing path is refused", func(t *testing.T) {
		_, errResult := localScanSpecFrom(map[string]interface{}{})
		require.NotNil(t, errResult)
	})

	t.Run("a path that is not a directory is refused before the scan", func(t *testing.T) {
		file := filepath.Join(dir, "a-file")
		require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
		_, errResult := localScanSpecFrom(map[string]interface{}{"path": file})
		require.NotNil(t, errResult)
		assert.Contains(t, codeResultText(errResult), "ROOT of a working copy")
	})

	t.Run("a nonexistent path is refused before the scan", func(t *testing.T) {
		_, errResult := localScanSpecFrom(map[string]interface{}{"path": filepath.Join(dir, "nope")})
		require.NotNil(t, errResult)
	})

	t.Run("the timeout is clamped to the hosted job's own ceiling", func(t *testing.T) {
		spec, errResult := localScanSpecFrom(map[string]interface{}{
			"path": dir, "timeout": float64(99999),
		})
		require.Nil(t, errResult)
		assert.Equal(t, codeScanMaxTimeout, spec.Timeout)
	})

	t.Run("an absent timeout takes the default", func(t *testing.T) {
		spec, errResult := localScanSpecFrom(map[string]interface{}{"path": dir})
		require.Nil(t, errResult)
		assert.Equal(t, codeScanDefaultTimeout, spec.Timeout)
		assert.Equal(t, defaultLocalScanners, spec.Scanners)
	})
}

// A local scan runs a container on the machine hosting this process. In stdio mode
// that machine is the caller's own; in HTTP mode it is a shared server holding many
// tenants' credentials, where "scan this path" is one tenant asking the process to
// read a directory it chose.
func TestCodeScanLocalIsStdioOnly(t *testing.T) {
	t.Setenv("MCP_MODE", "http")
	result, err := handleCodeScanLocal(context.Background(), map[string]interface{}{"path": t.TempDir()})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, codeResultText(result), "stdio mode")

	// The control: the same call in stdio mode must get PAST the mode gate. It is
	// asserted through a different failure, because a guard that also rejects the
	// allowed case proves nothing about the guard.
	t.Setenv("MCP_MODE", "stdio")
	result, err = handleCodeScanLocal(context.Background(), map[string]interface{}{
		"path": t.TempDir(), "scanners": "secrets",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.NotContains(t, codeResultText(result), "stdio mode")
}

func TestCodeScanLocalRefusesToGuessTheRepository(t *testing.T) {
	t.Setenv("MCP_MODE", "stdio")
	// Nothing may run: the refusal has to land before minutes are spent scanning.
	restore := stubCodeScanRunner(t, func(context.Context, localScanSpec) ([]byte, error) {
		t.Fatal("the scan must not start when the ingest target is unknown")
		return nil, nil
	})
	defer restore()

	result, err := handleCodeScanLocal(context.Background(), map[string]interface{}{
		"path": t.TempDir(), "ingest": true,
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, codeResultText(result), "identity")
}

// A scan that found things and pushed nothing reads like "nothing was found" unless
// the answer says otherwise.
func TestCodeScanLocalWithoutIngestSaysSoAndPushesNothing(t *testing.T) {
	t.Setenv("MCP_MODE", "stdio")
	dir := t.TempDir()
	restore := stubCodeScanRunner(t, func(_ context.Context, spec localScanSpec) ([]byte, error) {
		assert.Equal(t, dir, spec.Path)
		return []byte("REPORT-BYTES"), nil
	})
	defer restore()

	// No organization is in the context: if this path tried to push, it would fail
	// here rather than return a success.
	result, err := handleCodeScanLocal(context.Background(), map[string]interface{}{
		"path": dir, "repo": "acme/api",
	})
	require.NoError(t, err)
	require.False(t, result.IsError, codeResultText(result))

	var out map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(codeResultText(result)), &out))
	assert.Equal(t, false, out["report_ingested"])
	assert.Equal(t, float64(len("REPORT-BYTES")), out["report_bytes"])
	assert.Contains(t, out["note"], "NOT pushed")
}

func TestCodeScanLocalSurfacesTheScannerFailure(t *testing.T) {
	t.Setenv("MCP_MODE", "stdio")
	restore := stubCodeScanRunner(t, func(context.Context, localScanSpec) ([]byte, error) {
		return nil, errors.New("error_code=mirror_stale")
	})
	defer restore()

	result, err := handleCodeScanLocal(context.Background(), map[string]interface{}{"path": t.TempDir()})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, codeResultText(result), "error_code=mirror_stale")
}

// The ingest body is the SDK's own shape. A report is a gzip stream, so it rides
// base64; sending it any other way would either corrupt it or cost a double parse.
func TestCodeIngestBody(t *testing.T) {
	document := []byte{0x1f, 0x8b, 0x00, 0xff}
	body := codeIngestBody(
		localScanSpec{Repo: "acme/api", Commit: "c0ffee"},
		map[string]interface{}{"ref": "refs/heads/main", "provider": "github"},
		document)

	assert.Equal(t, "acme/api", body["repo"])
	assert.Equal(t, "report", body["source"])
	assert.Equal(t, "c0ffee", body["commit"])
	assert.Equal(t, "refs/heads/main", body["ref"])
	assert.Equal(t, "github", body["provider"])
	assert.NotContains(t, body, "document")

	decoded, err := base64.StdEncoding.DecodeString(body["document_b64"].(string))
	require.NoError(t, err)
	assert.Equal(t, document, decoded)

	t.Run("optional context stays absent rather than empty", func(t *testing.T) {
		bare := codeIngestBody(localScanSpec{Repo: "acme/api"}, map[string]interface{}{}, document)
		assert.NotContains(t, bare, "commit")
		assert.NotContains(t, bare, "ref")
		assert.NotContains(t, bare, "provider")
	})
}

func TestCodeScanLocalRefusesAnOverCapReport(t *testing.T) {
	t.Setenv("MCP_MODE", "stdio")
	restore := stubCodeScanRunner(t, func(context.Context, localScanSpec) ([]byte, error) {
		return make([]byte, maxCodeIngestBytes+1), nil
	})
	defer restore()

	// Refused here, with the size, instead of arriving as a gateway 400 about a body.
	result, err := handleCodeScanLocal(context.Background(), map[string]interface{}{
		"path": t.TempDir(), "repo": "acme/api", "ingest": true,
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, codeResultText(result), "ingest limit")
}

func stubCodeScanRunner(t *testing.T, fn func(context.Context, localScanSpec) ([]byte, error)) func() {
	t.Helper()
	previous := codeScanRunner
	codeScanRunner = fn
	return func() { codeScanRunner = previous }
}

// ------------------------------------------------------------------
// cloudsec_code_autofix
// ------------------------------------------------------------------

// The stub's whole value is that its refusal is machine-readable: an agent has to be
// able to tell "this capability does not exist" from "this call failed", because only
// one of the two is worth retrying.
func TestCodeAutofixRefusesStructurally(t *testing.T) {
	reg, exists := tools.GetTool("cloudsec_code_autofix")
	require.True(t, exists)

	result, err := reg.Handler(context.Background(), map[string]interface{}{
		"finding_id": "fnd_123", "repo": "acme/api",
	})
	require.NoError(t, err)
	require.True(t, result.IsError)

	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(codeResultText(result)), &payload))
	assert.Equal(t, autofixReason, payload["reason"])
	assert.Equal(t, false, payload["retryable"])
	assert.Equal(t, "fnd_123", payload["finding_id"])
	assert.Equal(t, "acme/api", payload["repo"])
	// It must point somewhere real, or a caller is simply stuck.
	assert.Contains(t, payload["remediation"], "cloudsec_code_findings")
}

// Every code tool's honest empty answer is indistinguishable from "the lane was never
// switched on", which is the likelier cause — so each description has to name the two
// hive records that turn it on.
func TestCodeToolsNameTheOptInSwitch(t *testing.T) {
	for _, name := range []string{
		"cloudsec_code_repos",
		"cloudsec_code_findings",
		"cloudsec_code_scan_local",
		"cloudsec_code_autofix",
	} {
		reg, exists := tools.GetTool(name)
		require.True(t, exists, name)
		assert.Contains(t, reg.Description, "cloudsec_policy", name)
		assert.Contains(t, reg.Description, "cloudsec_provider", name)
	}
}

// The gateway page cap is mirrored client-side so an over-large ask is refused rather
// than silently reshaped server-side.
func TestCodeRepoLimitIsClamped(t *testing.T) {
	reg, exists := tools.GetTool("cloudsec_code_repos")
	require.True(t, exists)
	assert.NotNil(t, reg.Handler)
	assert.Equal(t, 500, maxCodeRepoLimit)
	assert.Less(t, int64(codeScanDefaultTimeout), int64(codeScanMaxTimeout)+1)
	assert.Equal(t, 30*time.Minute, codeScanMaxTimeout)
}

// The `repo` filter is matched exactly against a lower-cased stored key, while a
// finding's own code.repo_name carries the platform's display casing. An agent that
// reads one off a finding and feeds it back gets zero rows and no reason — so an empty
// page under a mixed-case key says why.
func TestRepoCaseNote(t *testing.T) {
	empty := map[string]interface{}{"findings": []interface{}{}}

	t.Run("an empty page under a mixed-case key names the key that matches", func(t *testing.T) {
		note := repoCaseNote(lc.Dict{"repo": []string{"refractionPOINT/lc-appsec-fixtures"}}, empty)
		assert.Contains(t, note, "refractionpoint/lc-appsec-fixtures")
	})

	t.Run("an empty page under an already-lower key says nothing", func(t *testing.T) {
		// The control: the note must describe a CASING problem, not every empty page,
		// or it becomes noise that hides the real one.
		assert.Equal(t, "", repoCaseNote(lc.Dict{"repo": []string{"acme/api"}}, empty))
	})

	t.Run("a non-empty page says nothing", func(t *testing.T) {
		full := map[string]interface{}{"findings": []interface{}{map[string]interface{}{}}}
		assert.Equal(t, "", repoCaseNote(lc.Dict{"repo": []string{"Acme/API"}}, full))
	})

	t.Run("a response with no findings key at all says nothing", func(t *testing.T) {
		assert.Equal(t, "", repoCaseNote(lc.Dict{"repo": []string{"Acme/API"}}, map[string]interface{}{}))
	})
}
