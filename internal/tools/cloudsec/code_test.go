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

// The tool WRITES to a customer's repository, so the input it is given has to be the one
// thing that authorizes the write. An agent asked to "fix this" will reach for whatever
// string is nearest — a CVE id, a package name, the whole finding object — and every one of
// those would come back from the gateway as "no finding with that id", which reads as "it
// was already fixed" and is the wrong thing for a model to learn.
func TestCodeAutofixRefusesAnythingThatIsNotAFindingID(t *testing.T) {
	reg, exists := tools.GetTool("cloudsec_code_autofix")
	require.True(t, exists)

	for _, bad := range []string{
		"", "   ", "fnd_123", "CVE-2021-23337", "lodash",
		"fnd_" + strings.Repeat("z", 32), "fnd_" + strings.Repeat("a", 31),
		`{"finding_id":"fnd_` + strings.Repeat("a", 32) + `"}`,
	} {
		result, err := reg.Handler(context.Background(), map[string]interface{}{"finding_id": bad})
		require.NoError(t, err, bad)
		require.True(t, result.IsError, "finding_id %q was accepted", bad)
		// The refusal has to say what a finding id looks like AND where to get one;
		// "invalid input" leaves an agent guessing at the same wrong string again.
		assert.Contains(t, codeResultText(result), "cloudsec_code_findings", bad)
	}
}

// The description has to carry the two things a caller cannot discover from the response,
// because the response is only "accepted": that the pull request is the actual result, and
// that for npm and go the lockfile is NOT regenerated. An agent that reports "fixed" on the
// strength of an accepted call, or that believes an npm bump changed what installs, is
// worse than no tool.
func TestCodeAutofixDescriptionCarriesWhatTheResponseCannot(t *testing.T) {
	reg, exists := tools.GetTool("cloudsec_code_autofix")
	require.True(t, exists)
	for _, want := range []string{
		"WRITES", "queued", "lockfile", "MALICIOUS", "fixed version",
	} {
		assert.Contains(t, reg.Description, want)
	}
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

// An empty page under a repo filter is diagnosed by LOOKING, not by asserting a
// transformation: the stored key's owner segment carries the casing the source-control
// connection was configured with, which is not necessarily lower case, so suggesting a
// lower-cased key would send an agent after something that matches nothing.
func TestEmptyRepoPageNoteBranches(t *testing.T) {
	t.Run("a non-empty page says nothing", func(t *testing.T) {
		full := map[string]interface{}{"findings": []interface{}{map[string]interface{}{}}}
		assert.Equal(t, "", emptyRepoPageNote(context.Background(), nil, lc.Dict{"repo": []string{"Acme/API"}}, full))
	})

	t.Run("a response with no findings key says nothing", func(t *testing.T) {
		assert.Equal(t, "", emptyRepoPageNote(context.Background(), nil, lc.Dict{"repo": []string{"Acme/API"}}, map[string]interface{}{}))
	})

	t.Run("several repositories are not diagnosed", func(t *testing.T) {
		// There is no single thing to look up, and naming the wrong one would be
		// worse than saying nothing. (nil org proves no lookup is attempted.)
		empty := map[string]interface{}{"findings": []interface{}{}}
		assert.Equal(t, "", emptyRepoPageNote(context.Background(), nil,
			lc.Dict{"repo": []string{"a/b", "c/d"}}, empty))
	})
}

func TestRepoKeysOf(t *testing.T) {
	keys := repoKeysOf(map[string]interface{}{"repos": []interface{}{
		map[string]interface{}{"repo": "acme/api"},
		map[string]interface{}{"repo": ""},  // a row without a key is not a key
		map[string]interface{}{"name": "x"}, // nor is a row that has another one
		"not-a-row",
	}})
	assert.Equal(t, []string{"acme/api"}, keys)
	assert.Nil(t, repoKeysOf(map[string]interface{}{}))
}

// The repository a finding belongs to is an identity, so a remote that does not name a
// hosted repository must yield nothing rather than a plausible guess: "/home/me/src/api"
// would produce the wrong-but-believable key "src/api".
func TestRepoKeyFromRemote(t *testing.T) {
	for remote, want := range map[string]string{
		"https://github.com/acme/api.git":      "acme/api",
		"https://github.com/acme/api/":         "acme/api",
		"git@github.com:acme/api.git":          "acme/api",
		"ssh://git@github.com:22/acme/api.git": "acme/api",
		"https://user:tok@github.com/acme/api": "acme/api",
		"https://gitlab.example.com/g/sub/api": "sub/api",
		"/home/me/src/api":                     "",
		"file:///home/me/src/api":              "",
		"../sibling/api":                       "",
		"https://github.com/acme":              "",
		"":                                     "",
		"   ":                                  "",
	} {
		assert.Equal(t, want, repoKeyFromRemote(remote), remote)
	}
}

// Every absolute Windows path contains a colon, and the container runtime handles the
// drive-letter one specially. Rejecting it outright made the tool unusable for every
// Windows user, with advice that could not be followed.
func TestMountablePartKeepsWindowsPathsUsable(t *testing.T) {
	assert.Equal(t, `\Users\me\src\api`, mountablePart(`C:\Users\me\src\api`))
	assert.Equal(t, `\src\api`, mountablePart(`d:\src\api`))
	// The control: a colon anywhere else is still a colon, drive letter or not.
	assert.Contains(t, mountablePart(`C:\src\od:d\api`), ":")
	assert.Equal(t, "/home/me/src/api", mountablePart("/home/me/src/api"))
	assert.Contains(t, mountablePart("/home/me/we:rd"), ":")
	// Not a drive letter — a two-character path that merely starts with ':'.
	assert.Equal(t, "1:/x", mountablePart("1:/x"))
}

// A scan costs minutes and its report lives only in a temporary directory, so a failed
// push is unrecoverable unless a copy was kept. The failure has to say which case it is.
func TestCodeScanLocalIngestFailureSaysWhetherThereIsACopy(t *testing.T) {
	t.Setenv("MCP_MODE", "stdio")
	restore := stubCodeScanRunner(t, func(context.Context, localScanSpec) ([]byte, error) {
		return []byte("REPORT"), nil
	})
	defer restore()

	dir := t.TempDir()
	out := filepath.Join(dir, "report.json.gz")

	// No organization in the context, so the push cannot happen.
	result, err := handleCodeScanLocal(context.Background(), map[string]interface{}{
		"path": dir, "repo": "acme/api", "ingest": true, "output_path": out,
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, codeResultText(result), "without rescanning")

	// The control: with no output_path the same failure must say the opposite, or the
	// message is decoration rather than information.
	result, err = handleCodeScanLocal(context.Background(), map[string]interface{}{
		"path": dir, "repo": "acme/api", "ingest": true,
	})
	require.NoError(t, err)
	require.True(t, result.IsError)
	assert.Contains(t, codeResultText(result), "pass output_path")
}

func TestCodeScanLocalWritesTheRequestedCopy(t *testing.T) {
	t.Setenv("MCP_MODE", "stdio")
	restore := stubCodeScanRunner(t, func(context.Context, localScanSpec) ([]byte, error) {
		return []byte("REPORT"), nil
	})
	defer restore()

	dir := t.TempDir()
	out := filepath.Join(dir, "report.json.gz")
	result, err := handleCodeScanLocal(context.Background(), map[string]interface{}{
		"path": dir, "repo": "acme/api", "output_path": out,
	})
	require.NoError(t, err)
	require.False(t, result.IsError, codeResultText(result))
	body, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, []byte("REPORT"), body)

	t.Run("an unwritable destination is refused BEFORE the scan", func(t *testing.T) {
		restore := stubCodeScanRunner(t, func(context.Context, localScanSpec) ([]byte, error) {
			t.Fatal("the scan must not start when the report has nowhere to land")
			return nil, nil
		})
		defer restore()
		res, err := handleCodeScanLocal(context.Background(), map[string]interface{}{
			"path": dir, "output_path": filepath.Join(dir, "no-such-dir", "r.gz"),
		})
		require.NoError(t, err)
		require.True(t, res.IsError)
		assert.Contains(t, codeResultText(res), "cannot write output_path")
	})
}

// The executable this tool runs is named by the OPERATOR, never by the caller: in stdio
// mode the text the calling agent reads is tenant-influenced, so a tool argument naming
// an executable would be a prompt-injection-to-exec primitive.
func TestScannerCLIComesFromTheEnvironmentNotTheCaller(t *testing.T) {
	reg, exists := tools.GetTool("cloudsec_code_scan_local")
	require.True(t, exists)
	assert.NotContains(t, reg.Schema.InputSchema.Properties, "cli")

	spec, errResult := localScanSpecFrom(map[string]interface{}{
		"path": t.TempDir(), "cli": "/tmp/evil",
	})
	require.Nil(t, errResult)
	assert.Equal(t, "limacharlie", spec.CLI, "a 'cli' argument must be ignored, not honored")

	t.Setenv("LC_CODE_SCANNER_CLI", "/opt/lc/limacharlie")
	spec, errResult = localScanSpecFrom(map[string]interface{}{"path": t.TempDir()})
	require.Nil(t, errResult)
	assert.Equal(t, "/opt/lc/limacharlie", spec.CLI)
}
