package cloudsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// New tools use the same organization-bound transport as the existing code lane.
// URLs returned by SBOM/export reads are data, never followed with the org token.
func registerCodeWorkflows() {
	register(toolDef{name: "cloudsec_code_status", description: "Read hosted code-scan run status. An empty or partial scan is not proof of clean code. " + codeLaneNote, readOnly: true, handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
		return readProductGET(ctx, "code/status", lc.Dict{})
	}})
	register(toolDef{name: "cloudsec_code_sbom", description: "Request the repository's retained SBOM export. Returns metadata and a short-lived signed download URL; this tool never follows that URL or sends organization credentials to storage. " + codeLaneNote, readOnly: true, params: []mcp.ToolOption{mcp.WithString("repo", mcp.Required(), mcp.Description("Repository key owner/name (full namespace for GitLab)")), mcp.WithString("provider", mcp.Description("github (default), gitlab or bitbucket"))}, handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
		q, err := boundedCodeFields(args, []string{"repo"}, "repo", "provider")
		if err != nil {
			return tools.ErrorResult(err.Error()), nil
		}
		if _, ok := normalizedRepoKey(q["repo"].(string)); !ok {
			return tools.ErrorResult("repo must be a repository key owner/name"), nil
		}
		return readProductGET(ctx, "code/sbom", lc.Dict(q))
	}})
	register(toolDef{name: "cloudsec_code_rescan", description: "Queue a hosted scan of one repository/ref (cloudsec.set). Acceptance is not scan completion: follow cloudsec_code_status and repository scan_limits. " + codeLaneNote, params: []mcp.ToolOption{mcp.WithString("repo", mcp.Required(), mcp.Description("Repository key, bare collected name, or canonical URN")), mcp.WithString("ref", mcp.Description("Branch, tag or commit; default branch when omitted")), mcp.WithString("provider", mcp.Description("github, gitlab or bitbucket")), mcp.WithString("source", mcp.Description("Trigger source label"))}, handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
		b, e := boundedCodeFields(args, []string{"repo"}, "repo", "ref", "provider", "source")
		if e != nil {
			return tools.ErrorResult(e.Error()), nil
		}
		return callPOST(ctx, "code/scan", b, defaultTimeout)
	}})
	register(toolDef{name: "cloudsec_code_pr_check", description: "Queue a provider-verified pull-request check; publishes a GitHub check run or GitLab/Bitbucket status/comment when enabled. WRITES to source control; ask the user first. Provider-reported base/head win; caller-chosen base cannot make a PR clean. Acceptance is not a verdict. GitHub needs base_sha and full head_sha; GitLab base_sha is optional; Bitbucket head_sha may be 12–39 hex. GitHub edited requires prev_base_sha (actual retarget only). " + codeLaneNote, params: []mcp.ToolOption{mcp.WithString("repo", mcp.Required()), mcp.WithNumber("pr", mcp.Required(), mcp.Description("Positive pull/merge request number")), mcp.WithString("head_sha", mcp.Required()), mcp.WithString("base_sha"), mcp.WithString("action", mcp.Required(), mcp.Description("opened, synchronize, reopened; edited only for GitHub retarget")), mcp.WithString("prev_base_sha"), mcp.WithString("base_ref"), mcp.WithString("head_ref"), mcp.WithString("provider", mcp.Description("github (default), gitlab or bitbucket; write workflow availability is deployment-dependent"))}, handler: handleCodePRCheck})
	register(toolDef{name: "cloudsec_code_webhook", description: "Repair a GitHub App's webhook to this organization's existing github-code-webhook adapter URL. Changes the App's GLOBAL hook (possibly shared by installations); cloudsec.set and adapter/secret.get/secret.set permissions are required. Use the actual adapter hook URL and its signing secret, never invent them. The gateway verifies this organization's hook domain and adapter path. GitLab/Bitbucket use separate provider webhooks. Ask the user before changing it; never print the signing secret.", destructive: true, params: []mcp.ToolOption{mcp.WithString("connection", mcp.Required(), mcp.Description("Existing GitHub cloudsec_provider record name")), mcp.WithString("url", mcp.Required(), mcp.Description("Existing adapter's HTTPS LimaCharlie hook URL")), mcp.WithString("secret", mcp.Required(), mcp.Description("Adapter signing secret, distinct from the URL secret"))}, handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
		b, e := boundedCodeFields(args, []string{"connection", "url", "secret"}, "connection", "url", "secret")
		if e != nil {
			return tools.ErrorResult(e.Error()), nil
		}
		return callPOST(ctx, "code/webhook", b, providerTestTimeout)
	}})
	register(toolDef{name: "cloudsec_code_ingest", description: "Push BYO scanner results to Cloud Security (cloudsec.set): lossless report, SARIF, or CycloneDX. Requires enabled code_scanning policy and an in-scope repository; no source-control connection is required for BYO ingestion. Findings are producer-scoped: a pushed report cannot close hosted findings. Only a complete successful report can retire prior findings of that producer. Keep source text, secrets and credentials out of reports. At most 20 MiB including envelope. No remote URL/file is fetched.", params: []mcp.ToolOption{mcp.WithString("source", mcp.Required(), mcp.Description("report, sarif or cyclonedx")), mcp.WithString("repo", mcp.Required(), mcp.Description("Repository key owner/name (full namespace for GitLab)")), mcp.WithString("commit"), mcp.WithString("ref"), mcp.WithString("default_branch"), mcp.WithString("provider"), mcp.WithObject("document", mcp.Description("Uncompressed JSON document; exactly one document carrier")), mcp.WithString("document_b64", mcp.Description("Base64 JSON document, optionally gzipped; exactly one document carrier"))}, handler: handleCodeIngest})
	register(toolDef{name: "cloudsec_mint_m365_certificate", description: "Generate the public certificate for a Microsoft Entra/Microsoft 365 connection. Requires cloudsec.set AND secret.set. Private key stays in the org secret store; response includes base64 DER certificate for upload to the Entra app registration. Idempotent unless replace=true. Replacement immediately changes the stored private key: an existing connection may stop authenticating until the new public certificate is uploaded. Ask the user before rotation.", destructive: true, params: []mcp.ToolOption{mcp.WithString("connection", mcp.Required(), mcp.Description("cloudsec_provider record name")), mcp.WithString("client_id"), mcp.WithBoolean("replace", mcp.Description("Rotate existing key immediately; default false"))}, handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
		b, e := boundedCodeFields(args, []string{"connection"}, "connection", "client_id")
		if e != nil {
			return tools.ErrorResult(e.Error()), nil
		}
		if raw, present := args["replace"]; present {
			v, ok := raw.(bool)
			if !ok {
				return tools.ErrorResult("replace must be boolean"), nil
			}
			b["replace"] = v
		}
		return callPOST(ctx, "providers/m365/certificate", b, providerTestTimeout)
	}})
	registerImageReads()
}

func boundedCodeFields(args map[string]interface{}, required []string, keys ...string) (map[string]interface{}, error) {
	out := map[string]interface{}{}
	for _, key := range keys {
		if raw, present := args[key]; present {
			v, ok := raw.(string)
			if !ok || len(v) > 4096 || strings.ContainsAny(v, "\r\n\x00") {
				return nil, fmt.Errorf("%s must be a string at most 4096 bytes without control characters", key)
			}
			if strings.TrimSpace(v) != "" {
				out[key] = v
			}
		}
	}
	for _, key := range required {
		if _, ok := out[key]; !ok {
			return nil, fmt.Errorf("%s is required", key)
		}
	}
	return out, nil
}

// Whole numbers are validated rather than rounded: a rounded PR id is another PR.
func strictPositiveInt(args map[string]interface{}, key string, max int) (int, error) {
	raw, ok := args[key]
	if !ok {
		return 0, fmt.Errorf("%s is required", key)
	}
	b, e := json.Marshal(raw)
	if e != nil {
		return 0, fmt.Errorf("%s must be a positive whole number", key)
	}
	var n json.Number
	if e = json.Unmarshal(b, &n); e != nil {
		return 0, fmt.Errorf("%s must be a positive whole number", key)
	}
	f, e := n.Float64()
	if e != nil || f < 1 || f > float64(max) || f != float64(int(f)) {
		return 0, fmt.Errorf("%s must be a whole number between 1 and %d", key, max)
	}
	return int(f), nil
}

func handleCodePRCheck(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	b, e := boundedCodeFields(args, []string{"repo", "head_sha", "action"}, "repo", "head_sha", "base_sha", "action", "prev_base_sha", "base_ref", "head_ref", "provider")
	if e != nil {
		return tools.ErrorResult(e.Error()), nil
	}
	provider := strings.ToLower(argString(args, "provider"))
	if provider == "" {
		provider = "github"
	}
	if !contains([]string{"github", "gitlab", "bitbucket"}, provider) {
		return tools.ErrorResult("provider must be github, gitlab or bitbucket"), nil
	}
	b["provider"] = provider
	action := strings.ToLower(argString(args, "action"))
	if !contains([]string{"opened", "synchronize", "reopened", "edited"}, action) || action == "edited" && provider != "github" {
		return tools.ErrorResult("action must be opened, synchronize, reopened; edited is GitHub-only"), nil
	}
	b["action"] = action
	pr, e := strictPositiveInt(args, "pr", 2147483647)
	if e != nil {
		return tools.ErrorResult(e.Error()), nil
	}
	b["pr"] = pr
	for _, k := range []string{"head_sha", "base_sha", "prev_base_sha"} {
		v := strings.ToLower(argString(args, k))
		required := k == "head_sha" || k == "base_sha" && provider == "github" || k == "prev_base_sha" && action == "edited"
		if v == "" && !required {
			continue
		}
		valid := commitRe.MatchString(v) || k == "head_sha" && provider == "bitbucket" && regexp.MustCompile(`^[0-9a-f]{12,39}$`).MatchString(v)
		if !valid {
			return tools.ErrorResultf("%s must be a full hexadecimal commit (Bitbucket head may be abbreviated)", k), nil
		}
		b[k] = v
	}
	return callPOST(ctx, "code/pr_check", b, providerTestTimeout)
}

func handleCodeIngest(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	b, e := boundedCodeFields(args, []string{"source", "repo"}, "source", "repo", "commit", "ref", "default_branch", "provider")
	if e != nil {
		return tools.ErrorResult(e.Error()), nil
	}
	if !contains([]string{"report", "sarif", "cyclonedx"}, argString(args, "source")) {
		return tools.ErrorResult("source must be report, sarif or cyclonedx"), nil
	}
	if _, ok := normalizedRepoKey(argString(args, "repo")); !ok {
		return tools.ErrorResult("repo must be a repository key owner/name"), nil
	}
	doc, hasDoc := args["document"]
	encoded, hasEncoded := args["document_b64"]
	if hasDoc == hasEncoded {
		return tools.ErrorResult("supply exactly one of document or document_b64"), nil
	}
	if hasDoc {
		if v, ok := doc.(map[string]interface{}); !ok || len(v) == 0 {
			return tools.ErrorResult("document must be a nonempty JSON object"), nil
		}
		b["document"] = doc
	} else {
		if v, ok := encoded.(string); !ok || v == "" {
			return tools.ErrorResult("document_b64 must be nonempty base64 JSON, optionally gzipped"), nil
		}
		b["document_b64"] = encoded
	}
	raw, e := json.Marshal(b)
	if e != nil || len(raw) > maxCodeIngestBytes {
		return tools.ErrorResult("code ingest envelope exceeds 20 MiB or is not JSON"), nil
	}
	return callPOST(ctx, "code/ingest", b, codeIngestTimeout)
}

func registerImageReads() {
	for _, spec := range []struct {
		name, suffix, description string
		images, facets            bool
	}{
		{"cloudsec_code_image_repos", "code/image-repos", "List connected container-image repositories with exact image/open-finding counts. Page with next_cursor, even when a page is short.", false, false},
		{"cloudsec_code_image_repo_facets", "code/image-repos/facets", "Get cross-filtered registry facets. lineage_facet=true also counts digest-global effective source-lineage statuses; repository selectors do not narrow those lineage counts.", false, true},
		{"cloudsec_code_images", "code/images", "List digest-global container images, including images without findings. Source lineage is distinct from signing. A stale lineage claim reads unknown immediately; asserted or inferred never means verified provenance. Filter acknowledgement is checked so an older server cannot silently return an unfiltered page.", true, false},
	} {
		params := []mcp.ToolOption{mcp.WithString("q"), mcp.WithArray("provider", mcp.WithStringItems()), mcp.WithArray("account", mcp.WithStringItems()), mcp.WithArray("registry", mcp.WithStringItems())}
		if spec.images {
			params = append(params, mcp.WithArray("repo_urn", mcp.WithStringItems()), mcp.WithArray("tag", mcp.WithStringItems()), mcp.WithString("findings", mcp.Description("any, with, without")), mcp.WithBoolean("running"), mcp.WithBoolean("signed"), mcp.WithArray("lineage_status", mcp.WithStringItems(), mcp.Description("OR set: verified, asserted, inferred, ambiguous, unknown (omit for unconstrained)")))
		} else {
			params = append(params, mcp.WithArray("region", mcp.WithStringItems()), mcp.WithBoolean("has_findings"), mcp.WithBoolean("has_images"), mcp.WithString("scanning_state"))
		}
		if spec.facets {
			params = append(params, mcp.WithBoolean("lineage_facet"))
		} else {
			sorts := "name, risk, images, last_pushed"
			if spec.images {
				sorts = "name, risk, pushed"
			}
			params = append(params, mcp.WithString("sort", mcp.Description(sorts)), mcp.WithString("order", mcp.Description("asc or desc")))
			params = append(params, pagingParams("images")...)
		}
		register(toolDef{name: spec.name, description: spec.description, readOnly: true, params: params, handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return handleImageRead(ctx, args, spec.suffix, spec.images, spec.facets)
		}})
	}
	register(toolDef{name: "cloudsec_code_image", description: "Read a digest-global image with memberships, bounded source/workload samples, source-lineage decision and per-workload deployment evidence. Stale deployment observations read unknown; inference does not prove a build commit.", readOnly: true, params: []mcp.ToolOption{mcp.WithString("digest", mcp.Required(), mcp.Description("sha256: followed by 64 hexadecimal characters"))}, handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
		d := strings.ToLower(argString(args, "digest"))
		if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(d) {
			return tools.ErrorResult("digest must be sha256: followed by 64 hex characters"), nil
		}
		return readProductGET(ctx, "code/images/"+url.PathEscape(d), lc.Dict{})
	}})
}

func lineageSelector(args map[string]interface{}) ([]string, error) {
	raw, present := args["lineage_status"]
	if !present {
		return nil, nil
	}
	values, ok := argStrings(args, "lineage_status")
	if !ok || len(values) == 0 || len(values) > 100 {
		return nil, fmt.Errorf("lineage_status must contain 1 to 100 valid statuses")
	}
	if list, ok := raw.([]interface{}); ok && len(list) != len(values) {
		return nil, fmt.Errorf("lineage_status must contain only strings")
	}
	seen := map[string]bool{}
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if !contains([]string{"verified", "asserted", "inferred", "ambiguous", "unknown"}, v) {
			return nil, fmt.Errorf("invalid lineage_status %q", v)
		}
		seen[v] = true
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out, nil
}
func handleImageRead(ctx context.Context, args map[string]interface{}, suffix string, images, facets bool) (*mcp.CallToolResult, error) {
	arrays := []string{"provider", "account", "registry"}
	booleans := []string{"has_findings", "has_images"}
	scalars := []string{"q", "scanning_state"}
	if images {
		arrays = append(arrays, "repo_urn", "tag")
		booleans = []string{"running", "signed"}
		scalars = []string{"q", "findings"}
	} else {
		arrays = append(arrays, "region")
	}
	if facets {
		booleans = append(booleans, "lineage_facet")
	} else {
		scalars = append(scalars, "sort", "order", "cursor")
	}
	for _, key := range arrays {
		if raw, present := args[key]; present {
			var values []string
			switch v := raw.(type) {
			case string:
				values = []string{v}
			case []string:
				values = v
			case []interface{}:
				for _, item := range v {
					str, ok := item.(string)
					if !ok {
						return tools.ErrorResultf("%s must contain only strings", key), nil
					}
					values = append(values, str)
				}
			default:
				return tools.ErrorResultf("%s must be an array of strings", key), nil
			}
			if len(values) == 0 || len(values) > 100 {
				return tools.ErrorResultf("%s must contain 1 to 100 values", key), nil
			}
			for _, value := range values {
				if strings.TrimSpace(value) == "" || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
					return tools.ErrorResultf("%s contains an invalid empty or oversized value", key), nil
				}
			}
		}
	}
	for _, key := range booleans {
		if raw, present := args[key]; present {
			if _, ok := raw.(bool); !ok {
				return tools.ErrorResultf("%s must be boolean; omit it for no constraint", key), nil
			}
		}
	}
	for _, key := range scalars {
		if raw, present := args[key]; present {
			if value, ok := raw.(string); !ok || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
				return tools.ErrorResultf("%s must be a bounded string", key), nil
			}
		}
	}
	if _, present := args["limit"]; present && !facets {
		if _, err := strictPositiveInt(args, "limit", maxPageLimit); err != nil {
			return tools.ErrorResult(err.Error()), nil
		}
	}
	q := lc.Dict{}
	addStrings(q, args, "provider", "account", "registry")
	addScalars(q, args, "q", "scanning_state")
	if images {
		addStrings(q, args, "repo_urn", "tag")
		addScalars(q, args, "findings")
		addTriState(q, args, "running", "signed")
	} else {
		addStrings(q, args, "region")
		addTriState(q, args, "has_findings", "has_images")
	}
	var statuses []string
	if images {
		var e error
		statuses, e = lineageSelector(args)
		if e != nil {
			return tools.ErrorResult(e.Error()), nil
		}
		if len(statuses) > 0 {
			q["lineage_status"] = statuses
		}
	}
	if facets {
		addTriState(q, args, "lineage_facet")
	} else {
		addScalars(q, args, "sort", "order", "cursor")
		addInt(q, args, "limit", maxPageLimit)
	}
	org, e := tools.GetOrganization(ctx)
	if e != nil {
		return tools.ErrorResultf("failed to get organization: %v", e), nil
	}
	resp, e := decodeRaw(rawRequest(ctx, org, http.MethodGet, orgPath(org, suffix), queryValues(q), nil, defaultTimeout, maxJSONResponseBytes))
	if e != nil {
		return tools.ErrorResultf("image read failed: %s", describeErr(e)), nil
	}
	if len(statuses) > 0 {
		got, ok := resp["applied_lineage_status"].([]interface{})
		matches := ok && len(got) == len(statuses)
		for i := range got {
			if i >= len(statuses) || got[i] != statuses[i] {
				matches = false
				break
			}
		}
		if !matches {
			return tools.ErrorResult("lineage_status was not acknowledged exactly by this server; refusing an unfiltered or partially filtered page"), nil
		}
	}
	return tools.SuccessResult(resp), nil
}

// Bounded, cancellable reads for the expanded product API; never follow signed URLs.
func readProductGET(ctx context.Context, suffix string, query lc.Dict) (*mcp.CallToolResult, error) {
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResultf("failed to get organization: %v", err), nil
	}
	response, err := decodeRaw(rawRequest(ctx, org, http.MethodGet, orgPath(org, suffix), queryValues(query), nil, defaultTimeout, maxJSONResponseBytes))
	if err != nil {
		return tools.ErrorResultf("cloudsec read failed: %s", describeErr(err)), nil
	}
	return tools.SuccessResult(response), nil
}
