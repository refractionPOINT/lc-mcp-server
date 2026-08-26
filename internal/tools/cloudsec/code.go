package cloudsec

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// The AppSec "code lane" surface: the repositories a connected source-control
// organization exposes to Cloud Security, the findings scanning them produced, a local
// scan an IDE agent can run against a working copy before anything is pushed, and the
// reserved name for dependency AutoFix.
//
// The read half is the SAME pipeline as the cloud half — a repository is a DataStore row
// of kind `repo`, its findings are ordinary cs_findings rows — so these tools wrap the
// gateway's /cloudsec/{oid}/code/* routes and the findings routes' `repo` selector rather
// than introducing a second way to read a finding.

const (
	// maxCodeRepoLimit is the /code/repos page cap (endpoint_cloudsec_code.go: "default
	// 100, max 500"). Clamped here so an over-large ask is not silently reshaped.
	maxCodeRepoLimit = 500

	// maxCodeIngestBytes mirrors the collection host's own ingest cap, so an over-cap
	// report is refused here — with its size — instead of arriving as a gateway 400
	// about a request body. Same constant the CLI mirrors (MAX_CODE_INGEST_BYTES).
	maxCodeIngestBytes = 20 << 20

	// codeScanDefaultTimeout / codeScanMaxTimeout bound a local scan. The hosted sandbox
	// caps a job at 30 minutes (roadmap 15 D11) and a local scan has no reason to be
	// allowed to run longer than the thing it is standing in for.
	codeScanDefaultTimeout = 30 * time.Minute
	codeScanMaxTimeout     = 30 * time.Minute

	// codeIngestTimeout covers the host's server-side conversion + reconcile of a pushed
	// document, which walks up to MaxIngestResults results.
	codeIngestTimeout = 180 * time.Second
)

// codeFindingClasses is the finding-class vocabulary the code lane produces. It is
// offered as a HINT in the tool description, never applied as a hidden default: three of
// these classes (vulnerability, misconfig, malware) are shared with the cloud lane, so
// filtering on them is not the same thing as scoping to a repository — only the `repo`
// selector does that. cloudsec_list_finding_classes serves the live vocabulary.
var codeFindingClasses = []string{
	"vulnerability", "secret", "malware", "misconfig",
	"code_weakness", "license_risk", "eol_runtime",
}

// registerCode registers the AppSec code-lane tools.
func registerCode() {
	registerCodeRepos()
	registerCodeFindings()
	registerCodeScanLocal()
	registerCodeAutofix()
}

// ------------------------------------------------------------------
// cloudsec_code_repos
// ------------------------------------------------------------------

func registerCodeRepos() {
	register(toolDef{
		name: "cloudsec_code_repos",
		description: "List the organization's source repositories as Cloud Security's AppSec code lane sees them: identity (repo, urn, owner, provider), " +
			"the source-control facts the connector collected (visibility, archived, branch protection), the code-scan state (scan_status, code_scanned_at, " +
			"code_scan_commit, languages, packages_total, scan_limits) and the OPEN finding rollup (open_findings, findings_by_class, findings_by_severity, top_severity). " +
			"The 'repo' value ('<owner>/<name>') is the key every other code tool takes. scan_status is scanned | partial | unknown — 'partial' means a scan tripped a limit " +
			"and its finding set is INCOMPLETE, and 'unknown' means this surface has no scan state for the repository and says so rather than implying it is clean " +
			"(a machine-readable 'scan_status_reason' accompanies it). Keyset-paginated: pass the response's 'next_cursor' back as 'cursor'. A page may be SHORT while " +
			"'next_cursor' is set — the cursor, not the page length, says whether the walk is done. " + codeLaneNote,
		readOnly: true,
		params: []mcp.ToolOption{
			mcp.WithString("q",
				mcp.Description("Case-insensitive substring filter over the repository key ('<owner>/<name>') and its urn")),
			mcp.WithBoolean("has_findings",
				mcp.Description("Restrict to repositories that do (or do not) carry at least one OPEN finding. Omit entirely for no constraint — absent is not false, and has_findings=false is a real selection (the repositories with a clean bill)")),
			mcp.WithString("provider",
				mcp.Description("Source-control provider filter (e.g. 'github'); omit for every provider that produces repositories")),
			mcp.WithString("cursor",
				mcp.Description("Opaque keyset token returned as 'next_cursor' by a previous page; omit for the first page")),
			// NOT pagingParams: that helper states the findings routes' cap of 1000,
			// and this route's own cap is 500. Advertising a limit the handler then
			// silently halves is exactly what mirroring the cap client-side is for.
			mcp.WithNumber("limit",
				mcp.Description(fmt.Sprintf("Maximum number of repositories for this page (backend default 100, max %d — a larger ask is reduced to that)", maxCodeRepoLimit))),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			q := lc.Dict{}
			addScalars(q, args, "q", "provider", "cursor")
			addTriState(q, args, "has_findings")
			addInt(q, args, "limit", maxCodeRepoLimit)
			return readGET(ctx, "code/repos", q)
		},
	})
}

// ------------------------------------------------------------------
// cloudsec_code_findings
// ------------------------------------------------------------------

// codeFindingParams is the findings selector as the code lane uses it: the shared
// worklist filters plus the repeatable `repo` key.
func codeFindingParams(paging bool) []mcp.ToolOption {
	params := []mcp.ToolOption{
		mcp.WithArray("repo", mcp.WithStringItems(),
			mcp.Description("Repository filter, keyed '<owner>/<name>' EXACTLY as cloudsec_code_repos and the 'repo' facet return it. It is matched exactly and its owner segment carries the casing the source-control CONNECTION was configured with — a finding's own code.repo_name is the platform's DISPLAY casing and may not match as a filter, so take the key from cloudsec_code_repos rather than from a finding. Repeatable (OR within the key); at most 100 values are honored. REQUIRED unless facets=true — see the tool description for why")),
	}
	params = append(params, findingSelectorParams(paging)...)
	return params
}

func registerCodeFindings() {
	register(toolDef{
		name: "cloudsec_code_findings",
		description: "List the AppSec code lane's findings for one or more repositories — dependency vulnerabilities (SCA), secrets, infrastructure-as-code " +
			"misconfigurations, static-analysis weaknesses, licence risk and end-of-life runtimes — risk-ranked, under the same selectors as the cloud worklist. " +
			"Set facets=true instead of listing to get the cross-filtered COUNTS: each dimension is counted against the other active filters, and the 'repo' facet " +
			"is code-lane-only by construction (it counts only findings that HAVE a repository), which makes it the way to survey the whole estate. " +
			"'repo' is required to LIST because the backend has no 'any repository' selector: an unscoped list would return the cloud worklist too, so the honest " +
			"order is facets (or cloudsec_code_repos) to choose repositories, then this tool to read them. " +
			"Finding classes the lane produces: " + strings.Join(codeFindingClasses, ", ") + " — but note that vulnerability, misconfig and malware are SHARED with the " +
			"cloud lane, so a class filter narrows what is returned and does not by itself scope to code. " +
			"Each finding's 'code' evidence carries the producing scanner in 'detected_via' ('lc-code-scanner' for the hosted sandbox scan, 'lc-code-scanner-byo' for a " +
			"pushed local scan, 'sarif-ingest'/'cyclonedx-ingest' for a converted document); there is no server-side selector on it, so read it per finding rather " +
			"than expecting to filter by it. " + codeLaneNote,
		readOnly: true,
		params: append(codeFindingParams(true),
			mcp.WithBoolean("facets",
				mcp.Description("Return the cross-filtered facet counts and total instead of a page of findings. In this mode 'repo' is optional and 'cursor'/'limit'/'sort'/'order' do not apply")),
		),
		handler: handleCodeFindings,
	})
}

func handleCodeFindings(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	suffix, q, errResult := codeFindingsRequest(args)
	if errResult != nil {
		return errResult, nil
	}
	if suffix != "findings" {
		return readGET(ctx, suffix, q)
	}

	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResultf("failed to get organization: %v", err), nil
	}
	path := orgPath(org, suffix)
	resp, err := getJSON(ctx, org, path, q)
	if err != nil {
		return tools.ErrorResultf("cloudsec request to %s failed: %s", path, describeErr(err)), nil
	}
	if note := emptyRepoPageNote(ctx, org, q, resp); note != "" {
		resp["note"] = note
	}
	return tools.SuccessResult(resp), nil
}

// codeFindingsRequest is handleCodeFindings's pure half: it picks the route and builds
// the query, so the scoping rule is testable without a gateway.
func codeFindingsRequest(args map[string]interface{}) (string, lc.Dict, *mcp.CallToolResult) {
	facets, _ := argBool(args, "facets")
	repos, _ := argStrings(args, "repo")
	repos = nonEmpty(repos)

	if !facets && len(repos) == 0 {
		// Refused rather than widened. The findings route has no "has a repository"
		// selector, so dropping the constraint does not return "all code findings" —
		// it returns the whole estate's worklist, cloud findings included, under a
		// tool named for the code lane.
		return "", nil, tools.ErrorResult(
			"cloudsec_code_findings needs at least one 'repo' to list: the findings backend has no 'any repository' selector, " +
				"so an unscoped list would return the organization's cloud findings as well. " +
				"Call this tool with facets=true, or call cloudsec_code_repos, to get the repository keys first.")
	}

	q := lc.Dict{}
	addFindingSelector(q, args, !facets)
	if len(repos) > 0 {
		q["repo"] = repos
	}
	if facets {
		return "findings/facets", q, nil
	}
	return "findings", q, nil
}

// nonEmpty drops blank elements from a repeatable filter.
//
// Unlike the findings 'owner' dimension — where "" is a real selection, the unassigned
// bucket — an empty repository key selects nothing: `repo IN UNNEST(...)` cannot match,
// because the column is NULL for every non-repository finding rather than "". Keeping a
// blank would silently turn a two-repository ask into a one-repository answer.
func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

// emptyRepoPageNote turns a silent empty page into a diagnosable one, by LOOKING rather
// than guessing.
//
// The trap it exists for: `repo` is matched exactly, and the stored key's owner segment
// carries whatever casing the SOURCE-CONTROL CONNECTION was configured with — not the
// display casing a person reads on the platform, and not necessarily lower case either
// (legion_graph/service/code_handlers.go says so where it builds the two candidate urns).
// A finding's own `code.repo_name` is the display casing, so an agent that reads one off a
// finding and feeds it straight back as a filter can get zero rows and no reason.
//
// Rather than assert a transformation — an earlier version of this suggested the
// lower-cased key, which is right only for a connection that happens to be configured in
// lower case — it asks /code/repos what the repository is actually called. That is one
// bounded extra request, spent only on an empty page under a repo filter, and it answers
// with a fact: either the real key, or that no such repository is in the inventory.
//
// It never fails the read: any error from the lookup produces no note.
func emptyRepoPageNote(ctx context.Context, org *lc.Organization, q lc.Dict, resp map[string]interface{}) string {
	if findings, ok := resp["findings"].([]interface{}); !ok || len(findings) > 0 {
		return ""
	}
	repos, ok := q["repo"].([]string)
	if !ok || len(repos) != 1 {
		// With several keys in play there is no single thing to look up, and naming
		// the wrong one would be worse than saying nothing.
		return ""
	}
	asked := repos[0]

	// The name segment, matched case-insensitively by the route's own `q`.
	name := asked
	if i := strings.LastIndex(asked, "/"); i >= 0 {
		name = asked[i+1:]
	}
	if name == "" {
		return ""
	}
	known, complete := lookupRepoKeys(ctx, org, name)
	if len(known) == 0 {
		if !complete {
			// The walk did not finish, so "no such repository" is not something this
			// knows. Saying it anyway would be a confident wrong answer about the
			// caller's own estate.
			return ""
		}
		return "no findings matched, and no repository whose key contains " + name +
			" is in this organization's collected inventory — check the source-control connection and the code_scanning policy scope."
	}
	for _, k := range known {
		if k == asked {
			// The key is right, so the empty page is the real answer: nothing matched
			// under these filters. Saying that is worth a line, because the alternative
			// reading is "the filter was wrong".
			return "no findings matched; the repository key is correct, so this is an empty result under the other filters rather than a mis-typed key."
		}
	}
	return "no findings matched, and '" + asked + "' is not the stored key. The 'repo' filter is matched EXACTLY, and the owner segment carries the casing the " +
		"source-control connection was configured with (a finding's code.repo_name is the platform's display casing, which can differ). This organization has: " +
		strings.Join(known, ", ")
}

// maxRepoLookupPages bounds the walk emptyRepoPageNote does. Four pages of 500 covers an
// estate several times larger than any we have; past it the note says nothing rather than
// spending more of the caller's latency on a diagnostic.
const maxRepoLookupPages = 4

// lookupRepoKeys walks /code/repos for a name fragment, returning the matching keys and
// whether the walk COMPLETED.
//
// The page size is the route's maximum on purpose. `q` is applied WITHIN a keyset page,
// not across the walk, so a small limit makes a repository that exists look absent — a
// 20-row lookup on this estate returned nothing for a repository whose findings were on
// screen at the time. The completion flag exists for the same reason: a truncated walk
// can only report what it saw, never that something is missing.
func lookupRepoKeys(ctx context.Context, org *lc.Organization, name string) ([]string, bool) {
	var keys []string
	cursor := ""
	for page := 0; page < maxRepoLookupPages; page++ {
		q := lc.Dict{"q": name, "limit": maxCodeRepoLimit}
		if cursor != "" {
			q["cursor"] = cursor
		}
		resp, err := getJSON(ctx, org, orgPath(org, "code/repos"), q)
		if err != nil {
			return keys, false
		}
		keys = append(keys, repoKeysOf(resp)...)
		next, _ := resp["next_cursor"].(string)
		if next == "" {
			return keys, true
		}
		// A page may be SHORT while next_cursor is set: the cursor, not the page
		// length, says whether the walk is done.
		cursor = next
	}
	return keys, false
}

// repoKeysOf pulls the `repo` keys out of a /code/repos payload.
func repoKeysOf(resp map[string]interface{}) []string {
	list, ok := resp["repos"].([]interface{})
	if !ok {
		return nil
	}
	var out []string
	for _, item := range list {
		row, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if key, ok := row["repo"].(string); ok && key != "" {
			out = append(out, key)
		}
	}
	return out
}

// ------------------------------------------------------------------
// cloudsec_code_scan_local
// ------------------------------------------------------------------

// codeScanRunner runs the local scanner and returns the report document. It is a
// variable so the tests can exercise the argv and the ingest without a container.
var codeScanRunner = runLocalCodeScan

// localScanSpec is one local-scan request, already validated.
type localScanSpec struct {
	Path     string
	Repo     string
	Commit   string
	Scanners string
	Timeout  time.Duration
	CLI      string
	// OutputPath, when set, keeps a copy of the report outside the temporary
	// directory the scan runs in. It is what a failed ingest is retried from.
	OutputPath string
}

func registerCodeScanLocal() {
	register(toolDef{
		name: "cloudsec_code_scan_local",
		description: "Scan a LOCAL working copy with the same LimaCharlie code scanner the hosted lane runs, and optionally push the result to this organization. " +
			"This is the IDE-agent door: it answers 'what would Cloud Security say about the code on this disk' before anything is committed or pushed. " +
			"The scan runs in a container on the machine hosting this MCP server via the 'limacharlie' CLI ('limacharlie cloudsec code scan'), which owns the scanner " +
			"image pin — nothing but the report leaves the machine, and with ingest=false nothing leaves it at all. With ingest=true the report is pushed through this " +
			"server's own credential to /code/ingest, where it deduplicates against the hosted scan BY IDENTITY: the report format is loss-free, so a laptop scan lands " +
			"on exactly the rows a hosted scan of the same repository would write, and re-pushing an identical report writes nothing. A pushed report can only close " +
			"findings IT previously reported, never one the hosted scanner found. " +
			"SECRET SCANNING CANNOT RUN LOCALLY and asking for it is an error, not a silent omission: a credential's identity here is a digest keyed by a value only the " +
			"hosted lane holds, so local secrets would neither deduplicate nor be accepted. Use the hosted lane for secrets. " +
			"Requires stdio mode (a local scan on a shared hosted server would run a container on somebody else's behalf), Docker, and the 'limacharlie' CLI on PATH. " +
			"Expect minutes, not seconds. " + codeLaneNote,
		readOnly:    false,
		destructive: false, // writes findings for a repository the caller already owns; nothing is deleted
		params: []mcp.ToolOption{
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("Absolute path of the working copy to scan")),
			mcp.WithBoolean("ingest",
				mcp.Description("Push the report to this organization when the scan finishes (default false). Requires 'repo'")),
			mcp.WithString("repo",
				mcp.Description("Repository key '<owner>/<name>' to attribute the results to. Required with ingest=true, and read from the checkout's git origin when omitted. The repository must already be in the org's collected inventory and be selected by an enabled code_scanning policy — the same switch the hosted lane uses")),
			mcp.WithString("commit",
				mcp.Description("The revision scanned. Read from the checkout when omitted. Recorded, not verified")),
			mcp.WithString("ref",
				mcp.Description("The branch or tag scanned, for context (refs/heads/main)")),
			mcp.WithString("provider",
				mcp.Description("Source-control provider the repository key belongs to; defaults to 'github'")),
			mcp.WithString("scanners",
				mcp.Description("Comma-separated engines to run. Available locally: "+strings.Join(localScanners, ", ")+" (default "+defaultLocalScanners+"). 'secrets' and 'secrets_history' are refused — see the tool description")),
			mcp.WithNumber("timeout",
				mcp.Description(fmt.Sprintf("Seconds to allow the scan (default %d, max %d)", int(codeScanDefaultTimeout/time.Second), int(codeScanMaxTimeout/time.Second)))),
			mcp.WithString("output_path",
				mcp.Description("Write the report here as well. Worth passing whenever ingest=true: a scan takes minutes and a failed push cannot be retried without rescanning, so this is the copy you retry from")),
		},
		handler: handleCodeScanLocal,
	})
}

// localScanners / unavailableLocalScanners mirror the CLI's own vocabulary
// (LOCAL_SCANNERS / UNAVAILABLE_LOCAL_SCANNERS). They are restated so an unrunnable or
// misspelled engine is refused HERE, with the reason, rather than after the caller has
// waited out a scan that quietly ran narrower than they asked for.
var localScanners = []string{"sca", "iac", "sast", "licenses", "images"}
var unavailableLocalScanners = []string{"secrets", "secrets_history"}

const defaultLocalScanners = "sca,iac,licenses"

func handleCodeScanLocal(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	if errResult := requireStdio(); errResult != nil {
		return errResult, nil
	}

	spec, errResult := localScanSpecFrom(args)
	if errResult != nil {
		return errResult, nil
	}
	// Filled from the checkout when the caller did not say. This process is the one
	// that pushes, so these have to be resolved here: what the CLI infers stays inside
	// its own report, while the commit and repository that land on a finding are the
	// ones sent from here.
	if spec.Commit == "" {
		spec.Commit = gitHead(ctx, spec.Path)
	}
	if spec.Repo == "" {
		spec.Repo = gitRepoKey(ctx, spec.Path)
	}

	ingest, _ := argBool(args, "ingest")
	if ingest && spec.Repo == "" {
		return tools.ErrorResult(
			"ingest=true needs 'repo' as '<owner>/<name>': the checkout's git origin did not name one, " +
				"and which repository a finding belongs to is an identity rather than something to guess"), nil
	}

	document, err := codeScanRunner(ctx, spec)
	if err != nil {
		return tools.ErrorResultf("local code scan failed: %v", err), nil
	}

	out := map[string]interface{}{
		"path":            spec.Path,
		"repo":            spec.Repo,
		"commit":          spec.Commit,
		"scanners":        spec.Scanners,
		"report_bytes":    len(document),
		"report_ingested": false,
	}
	if spec.OutputPath != "" {
		if err := os.WriteFile(spec.OutputPath, document, 0o600); err != nil {
			// Reported, not fatal: the scan happened and the ingest below can still
			// succeed. Losing the copy is worth saying out loud, because it is the
			// copy a failed push would have been retried from.
			out["output_error"] = fmt.Sprintf("could not write %s: %v", spec.OutputPath, err)
		} else {
			out["report_written"] = spec.OutputPath
		}
	}
	if !ingest {
		// Said plainly, because a scan that produced findings and pushed none is easy
		// to read as "nothing was found".
		out["note"] = "the report was NOT pushed (ingest=false); nothing about this scan is visible in Cloud Security"
		return tools.SuccessResult(out), nil
	}

	if len(document) > maxCodeIngestBytes {
		return tools.ErrorResultf(
			"the report is %d bytes and the ingest limit is %d; narrow the scan with 'scanners' and push the sections separately",
			len(document), maxCodeIngestBytes), nil
	}

	body := codeIngestBody(spec, args, document)

	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResultf("the scan succeeded but the report could not be pushed (failed to get organization: %v) — %s",
			err, retryAdvice(out)), nil
	}
	path := orgPath(org, "code/ingest")
	resp, err := postJSON(ctx, org, path, body, codeIngestTimeout)
	if err != nil {
		return tools.ErrorResultf("the scan succeeded but the ingest to %s failed: %s — %s",
			path, describeErr(err), retryAdvice(out)), nil
	}
	out["report_ingested"] = true
	out["ingest"] = resp
	return tools.SuccessResult(out), nil
}

// codeIngestBody builds the /code/ingest request for a report this process just
// produced. It is the same body the SDK sends (limacharlie/sdk/cloudsec.py
// ingest_code_results), so a report pushed from here lands exactly where a report
// pushed by the CLI would.
func codeIngestBody(spec localScanSpec, args map[string]interface{}, document []byte) map[string]interface{} {
	body := map[string]interface{}{
		"repo": spec.Repo,
		// `report` and not `sarif`/`cyclonedx`: this is the scanner's own document, which
		// is loss-free, and its provenance token is the one that lets a local push update
		// the hosted scan's rows instead of duplicating them.
		"source": "report",
		// Base64 rather than decoded and re-encoded: it is a gzip stream, which JSON
		// cannot carry, and re-parsing megabytes to send the same bytes buys nothing.
		"document_b64": base64.StdEncoding.EncodeToString(document),
	}
	if spec.Commit != "" {
		body["commit"] = spec.Commit
	}
	addScalarsTo(body, args, "ref", "provider")
	return body
}

// retryAdvice says whether a failed push can be retried without rescanning.
//
// The report lives only in the scan's temporary directory, which is removed the moment
// the scanner returns. A scan costs minutes, so a push that fails for any ordinary reason
// — not subscribed, the repository not in the collected inventory, no enabled
// code_scanning policy, the free-tier quota, a transient 502 — otherwise costs those
// minutes again with nothing said about why.
func retryAdvice(out map[string]interface{}) string {
	if p, ok := out["report_written"].(string); ok && p != "" {
		return "the report is at " + p + "; retry the push without rescanning"
	}
	return "the report was not kept, so a retry means rescanning: pass output_path to keep a copy"
}

// addScalarsTo is addScalars for a plain JSON body rather than a query Dict.
func addScalarsTo(dst map[string]interface{}, args map[string]interface{}, keys ...string) {
	for _, k := range keys {
		if v := argString(args, k); v != "" {
			dst[k] = v
		}
	}
}

// requireStdio refuses a local scan outside stdio mode.
//
// The tool runs a container on the machine hosting this process. In stdio mode that
// machine is the caller's own and the working copy is theirs. In HTTP mode it is a
// shared server holding many tenants' credentials, the caller has no filesystem there,
// and "scan this path" would be one tenant asking the server to read a path it chose.
func requireStdio() *mcp.CallToolResult {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("MCP_MODE")))
	if mode == "" || mode == "stdio" {
		return nil
	}
	return tools.ErrorResult(
		"cloudsec_code_scan_local runs a scanner container on the machine hosting this MCP server, so it is available only in stdio mode " +
			"(this server is running in " + mode + " mode). Run the LimaCharlie MCP server locally to scan a local working copy, " +
			"or use the hosted code lane, which scans the connected source-control organization's repositories in the datacenter.")
}

// localScanSpecFrom validates the arguments a local scan needs BEFORE the scan, because
// every one of these failures is otherwise discovered minutes later.
func localScanSpecFrom(args map[string]interface{}) (localScanSpec, *mcp.CallToolResult) {
	path := argString(args, "path")
	if path == "" {
		return localScanSpec{}, tools.ErrorResult("path parameter is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return localScanSpec{}, tools.ErrorResultf("path %q could not be resolved: %v", path, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return localScanSpec{}, tools.ErrorResultf("path %q cannot be read: %v", abs, err)
	}
	if !info.IsDir() {
		return localScanSpec{}, tools.ErrorResultf("path %q is a file; the scanner takes the ROOT of a working copy", abs)
	}
	if strings.Contains(mountablePart(abs), ":") {
		// The checkout is bind-mounted as "<path>:/scan/src:ro", so a ':' mis-splits and
		// the container runtime answers with an opaque "invalid mode".
		return localScanSpec{}, tools.ErrorResultf(
			"path %q contains ':', which cannot be mounted into the scanner; scan it from a path without one", abs)
	}

	scanners, errResult := resolveLocalScanners(argString(args, "scanners"))
	if errResult != nil {
		return localScanSpec{}, errResult
	}

	timeout := codeScanDefaultTimeout
	if n, ok := argInt(args, "timeout"); ok && n > 0 {
		timeout = time.Duration(n) * time.Second
		if timeout > codeScanMaxTimeout {
			timeout = codeScanMaxTimeout
		}
	}

	// The CLI is named by the OPERATOR, never by the caller.
	//
	// This tool runs the named executable. In stdio mode the descriptions and finding
	// text the calling agent reads are tenant-influenced content (a repository name, a
	// finding's evidence), so a tool ARGUMENT naming an executable is a
	// prompt-injection-to-exec primitive for an agent that has no shell otherwise.
	// LC_CODE_SCANNER_CLI covers the "installed somewhere unusual" case without handing
	// the choice to the model.
	cli := strings.TrimSpace(os.Getenv("LC_CODE_SCANNER_CLI"))
	if cli == "" {
		cli = "limacharlie"
	}

	outputPath := strings.TrimSpace(argString(args, "output_path"))
	if outputPath != "" {
		// Probed BEFORE the scan: discovering an unwritable destination after twenty
		// minutes of scanning helps nobody.
		f, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return localScanSpec{}, tools.ErrorResultf("cannot write output_path %q: %v", outputPath, err)
		}
		_ = f.Close()
	}

	return localScanSpec{
		Path:       abs,
		Repo:       strings.TrimSpace(argString(args, "repo")),
		Commit:     strings.TrimSpace(argString(args, "commit")),
		Scanners:   scanners,
		Timeout:    timeout,
		CLI:        cli,
		OutputPath: outputPath,
	}, nil
}

// mountablePart strips a Windows drive-letter prefix before the ':' check.
//
// Every absolute Windows path contains a colon — `C:\Users\me\src\api` — and the
// container runtime handles that one specially (`C:\src:/scan/src:ro` is a valid mount).
// Rejecting it outright made the tool unusable for every Windows user of Claude Code or
// Cursor, with advice ("scan it from a path without one") that cannot be followed.
func mountablePart(abs string) string {
	if len(abs) >= 2 && abs[1] == ':' {
		c := abs[0]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			return abs[2:]
		}
	}
	return abs
}

// resolveLocalScanners validates the engine list against what a local scan can run.
func resolveLocalScanners(raw string) (string, *mcp.CallToolResult) {
	if strings.TrimSpace(raw) == "" {
		return defaultLocalScanners, nil
	}
	var wanted []string
	for _, part := range strings.Split(raw, ",") {
		s := strings.ToLower(strings.TrimSpace(part))
		if s == "" {
			continue
		}
		wanted = append(wanted, s)
	}
	if len(wanted) == 0 {
		return "", tools.ErrorResultf("'scanners' is empty; name at least one of: %s", strings.Join(localScanners, ", "))
	}
	var unavailable, unknown []string
	for _, s := range wanted {
		switch {
		case contains(unavailableLocalScanners, s):
			unavailable = append(unavailable, s)
		case !contains(localScanners, s):
			unknown = append(unknown, s)
		}
	}
	if len(unavailable) > 0 {
		return "", tools.ErrorResultf(
			"%s cannot run in a local scan: a credential's identity here is a digest keyed by a value only the hosted lane holds, "+
				"so locally-found secrets would neither deduplicate against the hosted scan's nor be accepted by the ingest. "+
				"Use the hosted lane for secrets.", strings.Join(unavailable, ", "))
	}
	if len(unknown) > 0 {
		// Refused rather than dropped: a silently narrower scan reports success and
		// looks like a clean result for a pass that never ran.
		return "", tools.ErrorResultf("unknown scanner(s) %s; available locally: %s",
			strings.Join(unknown, ", "), strings.Join(localScanners, ", "))
	}
	return strings.Join(wanted, ","), nil
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// runLocalCodeScan shells out to `limacharlie cloudsec code scan`.
//
// The scan is DELEGATED rather than reimplemented. The CLI owns the scanner image pin,
// the mounts, the identity the container runs as and the vulnerability-database sources
// the scanner refuses to start without; a second copy of that argv here would drift from
// it silently, and the drift would show up as findings that differ between a local scan
// and the hosted one they are supposed to deduplicate against.
//
// The INGEST is deliberately NOT delegated (`--no-ingest`): the push has to ride this
// server's own organization credential and gateway, which is what makes the tool work
// against a non-production gateway and keeps one credential in play instead of two.
func runLocalCodeScan(ctx context.Context, spec localScanSpec) ([]byte, error) {
	bin, err := exec.LookPath(spec.CLI)
	if err != nil {
		return nil, fmt.Errorf(
			"the 'limacharlie' CLI is required for a local scan and was not found (%v). Install it with 'pip install limacharlie', "+
				"or pass 'cli' with its full path", err)
	}
	if err := checkCodeScanSupported(ctx, bin); err != nil {
		return nil, err
	}

	workdir, err := os.MkdirTemp("", "lc-mcp-code-scan-")
	if err != nil {
		return nil, fmt.Errorf("could not create a working directory: %w", err)
	}
	defer os.RemoveAll(workdir)
	reportPath := filepath.Join(workdir, "report.json.gz")

	// The context deadline is the scan timeout PLUS a margin, so the CLI's own timeout
	// fires first and reports the timeout in its own words; killing it from here would
	// also orphan the container it started.
	runCtx, cancel := context.WithTimeout(ctx, spec.Timeout+2*time.Minute)
	defer cancel()

	argv := []string{"--output", "json", "cloudsec", "code", "scan", spec.Path,
		"--no-ingest",
		"-o", reportPath,
		"--scanners", spec.Scanners,
		"--timeout", strconv.Itoa(int(spec.Timeout / time.Second)),
	}
	if spec.Repo != "" {
		argv = append(argv, "--repo", spec.Repo)
	}
	if spec.Commit != "" {
		argv = append(argv, "--commit", spec.Commit)
	}

	cmd := exec.CommandContext(runCtx, bin, argv...)
	// The CLI reads its own configuration; it needs no credential for --no-ingest.
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s exited with an error: %v\n%s", spec.CLI, err, tailLines(string(out), 20))
	}
	document, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("the scan reported success but wrote no report: %w\n%s", err, tailLines(string(out), 20))
	}
	if len(document) == 0 {
		return nil, fmt.Errorf("the scan reported success but the report is empty\n%s", tailLines(string(out), 20))
	}
	return document, nil
}

// checkCodeScanSupported refuses an installed-but-too-old CLI up front.
//
// `cloudsec code scan` is newer than most installed copies. Without this the failure
// arrives as a click "no such command" on stderr after the caller has been told a scan
// started, which reads like a broken scanner rather than an old CLI.
func checkCodeScanSupported(ctx context.Context, bin string) error {
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(probeCtx, bin, "cloudsec", "code", "scan", "--help").CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"this 'limacharlie' CLI has no 'cloudsec code scan' command, so it is older than the code lane. "+
				"Upgrade it with 'pip install --upgrade limacharlie'.\n%s", tailLines(string(out), 10))
	}
	return nil
}

// tailLines keeps the last n lines of a subprocess's output: the scanner prints a
// machine-readable `error_code=` line before a fatal exit, and it is at the end.
func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// ------------------------------------------------------------------
// cloudsec_code_autofix (reserved)
// ------------------------------------------------------------------

// autofixReason is the machine-readable token a caller can branch on. It is a token
// rather than prose so an agent can tell "this capability is not built" apart from "this
// call failed", which are different things to retry.
const autofixReason = "code_autofix_not_available"

func registerCodeAutofix() {
	register(toolDef{
		name: "cloudsec_code_autofix",
		description: "RESERVED — NOT AVAILABLE YET. Named now so the tool surface is stable, and it returns a structured refusal on every call rather than doing anything. " +
			"When it ships it will open a pull request bumping the manifest/lockfile for a dependency finding that carries a fixed_version, using a separate, " +
			"opt-in, write-scoped source-control credential that does not exist yet either (the read connector this organization uses is read-only, permanently). " +
			"Until then the remediation path for a dependency finding is the fixed_version on the finding itself: call cloudsec_code_findings, read " +
			"'code.fixed_version' (or the vulnerability evidence), make the bump yourself, and cloudsec_code_scan_local will confirm it before you push. " +
			"Do not retry this tool; nothing about the organization's configuration will change its answer. " + codeLaneNote,
		readOnly:    false,
		destructive: false,
		params: []mcp.ToolOption{
			mcp.WithString("finding_id",
				mcp.Description("The dependency finding (fnd_...) a fix would be opened for. Accepted and echoed back so a caller can see the request was understood; nothing is done with it")),
			mcp.WithString("repo",
				mcp.Description("Repository key '<owner>/<name>'. Same: accepted, echoed, unused")),
		},
		handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			payload := map[string]interface{}{
				"error":  "cloudsec_code_autofix is reserved and not available yet",
				"reason": autofixReason,
				"detail": "Dependency AutoFix pull requests are not built. This tool exists so the code-lane tool surface is stable and so " +
					"a caller gets one clear answer instead of a guess; it will never open a pull request in this build.",
				"remediation": "Read the finding's fixed_version with cloudsec_code_findings, apply the bump yourself, and verify it with " +
					"cloudsec_code_scan_local before pushing.",
				"retryable": false,
			}
			if v := argString(args, "finding_id"); v != "" {
				payload["finding_id"] = v
			}
			if v := argString(args, "repo"); v != "" {
				payload["repo"] = v
			}
			return tools.ErrorResult(tools.ToJSON(payload)), nil
		},
	})
}

// codeLaneNote points at the switch that turns the whole lane on. Without it, every code
// tool's honest empty answer ("no repositories", "no findings") is indistinguishable
// from "the lane was never enabled", which is the likelier cause by far.
const codeLaneNote = `The code lane is OPT-IN per organization: it runs only where a "code_scanning" record exists in the "cloudsec_policy" hive (read/write it with the generic hive tools) and a source-control provider is connected in the "cloudsec_provider" hive. An empty answer from a code tool usually means one of those two is missing, NOT that the code is clean.`

// ------------------------------------------------------------------
// reading the checkout
// ------------------------------------------------------------------

// The commit and the repository key are resolved HERE rather than left to the CLI,
// even though the CLI resolves them too, for one reason: this process is the one that
// PUSHES. The CLI runs with --no-ingest, so whatever it infers stays inside its own
// report; the `commit` and `repo` that land on the finding are the ones this process
// sends. Reporting an empty commit while the document carries one — which is what
// happened the first time this ran against a real clone — is a finding labelled with
// the wrong checkout.

// gitHead is the checked-out revision, or "".
//
// A directory that is not a git working tree is a perfectly good thing to scan; it just
// cannot say which revision it is, and a fabricated one would mislabel every finding.
func gitHead(ctx context.Context, root string) string {
	return gitOutput(ctx, root, "rev-parse", "HEAD")
}

// gitRepoKey is the '<owner>/<name>' key from the checkout's origin remote, or "".
func gitRepoKey(ctx context.Context, root string) string {
	return repoKeyFromRemote(gitOutput(ctx, root, "config", "--get", "remote.origin.url"))
}

// repoKeyFromRemote parses a remote URL into the repository key, mirroring the CLI's
// rules (limacharlie/commands/cloudsec.py _git_repo_key) so a local scan and a CLI scan
// of the same checkout attribute their findings to the same node.
//
// It is read from the REMOTE, never from the directory name: the directory is whatever
// the person cloned it as, and the repository a finding belongs to is an identity. A
// remote that names no hosted repository — a local path, a file:// clone — is refused
// rather than parsed, because "/home/me/src/api" would yield the plausible and WRONG
// key "src/api", which is exactly the guess the ingest guard exists to prevent.
func repoKeyFromRemote(raw string) string {
	u := strings.TrimRight(strings.TrimSpace(raw), "/")
	if u == "" {
		return ""
	}
	u = strings.TrimSuffix(u, ".git")

	var tail string
	switch {
	case strings.Contains(u, "://"):
		parts := strings.SplitN(u, "://", 2)
		scheme, rest := strings.ToLower(parts[0]), parts[1]
		if scheme == "file" || !strings.Contains(rest, "/") {
			return ""
		}
		host, t, _ := strings.Cut(rest, "/")
		// Strip any credentials before judging the host.
		if i := strings.LastIndex(host, "@"); i >= 0 {
			host = host[i+1:]
		}
		host, _, _ = strings.Cut(host, ":") // drop an explicit port
		if !strings.Contains(host, ".") && strings.ToLower(host) != "localhost" {
			return ""
		}
		tail = t
	case strings.Contains(u, ":"):
		// scp-style: [user@]host:owner/name
		host, t, _ := strings.Cut(u, ":")
		if i := strings.LastIndex(host, "@"); i >= 0 {
			host = host[i+1:]
		}
		if !strings.Contains(host, ".") {
			return ""
		}
		tail = t
	default:
		return ""
	}

	var segments []string
	for _, p := range strings.Split(tail, "/") {
		if p != "" {
			segments = append(segments, p)
		}
	}
	if len(segments) < 2 {
		return ""
	}
	return segments[len(segments)-2] + "/" + segments[len(segments)-1]
}

// gitOutput runs one git command in root and returns its trimmed stdout, or "" for any
// failure. Every caller treats "" as "the checkout did not say", which is a real answer.
func gitOutput(ctx context.Context, root string, args ...string) string {
	cmdCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, "git", append([]string{"-C", root}, args...)...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
