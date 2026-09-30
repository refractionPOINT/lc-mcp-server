package cloudsec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

const maxIaCMapBytes = 20 << 20

func registerIaCMap() {
	register(toolDef{name: "cloudsec_code_iac_map_push", description: "Push ONLY sanitized lc-iac-map/v1 metadata, never raw Terraform state/plan, source, secrets, credentials or arbitrary desired values (20 MiB maximum). Run cloudsec_code_iac_map_extract locally first. Requires cloudsec.set and enabled provenance. A processing receipt is accepted but unpublished: poll cloudsec_code_iac_map_status. Resubmit the same document only for retryable. Partial/unsuccessful maps cannot delete mappings; replay writes nothing. Publication is not deployment or remediation verification.", params: []mcp.ToolOption{mcp.WithObject("document", mcp.Required(), mcp.Description("Sanitized extractor output object; no URL, file, compressed data or tenant fields"))}, handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
		doc, e := validateSanitizedMap(args["document"])
		if e != nil {
			return tools.ErrorResult(e.Error()), nil
		}
		org, e := tools.GetOrganization(ctx)
		if e != nil {
			return tools.ErrorResult("organization authentication required"), nil
		}
		response, e := decodeRaw(rawRequest(ctx, org, http.MethodPost, orgPath(org, "code/iac-map"), nil, doc, 90*time.Second, maxJSONResponseBytes))
		if e != nil {
			return tools.ErrorResultf("sanitized map push failed: %s", describeErr(e)), nil
		}
		return tools.SuccessResult(response), nil
	}})
	params := []mcp.ToolOption{}
	for _, key := range []string{"repository", "provider", "workspace", "source_kind", "hash"} {
		params = append(params, mcp.WithString(key, mcp.Required(), mcp.Description("Exact receipt scope field; hash is 64 lowercase hexadecimal characters")))
	}
	register(toolDef{name: "cloudsec_code_iac_map_status", description: "Read one exact sanitized-map receipt. Requires cloudsec.set (despite being a read), and enabled provenance. processing means staging; published means generation visible; retryable means resubmit the same document; superseded means newer evidence replaced it. None proves deployment.", readOnly: true, params: params, handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
		b, e := boundedCodeFields(args, []string{"repository", "provider", "workspace", "source_kind", "hash"}, "repository", "provider", "workspace", "source_kind", "hash")
		if e != nil {
			return tools.ErrorResult(e.Error()), nil
		}
		for _, v := range b {
			if len(v.(string)) > 512 {
				return tools.ErrorResult("receipt scope fields must be at most 512 bytes"), nil
			}
		}
		if _, ok := normalizedRepoKey(argString(args, "repository")); !ok || !contains([]string{"github", "gitlab", "bitbucket"}, argString(args, "provider")) || !contains([]string{"state_identity", "plan_desired"}, argString(args, "source_kind")) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(argString(args, "hash")) {
			return tools.ErrorResult("invalid exact map receipt scope/hash"), nil
		}
		org, e := tools.GetOrganization(ctx)
		if e != nil {
			return tools.ErrorResult("organization authentication required"), nil
		}
		q := url.Values{}
		for k, v := range b {
			q.Set(k, v.(string))
		}
		return rawJSON(ctx, org, http.MethodGet, "code/iac-map/status", q)
	}})
	params = []mcp.ToolOption{mcp.WithString("input", mcp.Required(), mcp.Description("Absolute LOCAL terraform show -json file; raw content never leaves this machine")), mcp.WithString("repository", mcp.Required()), mcp.WithString("commit", mcp.Required(), mcp.Description("Full lowercase hexadecimal commit")), mcp.WithString("source_kind", mcp.Required(), mcp.Description("state_identity or plan_desired")), mcp.WithString("workspace", mcp.Description("default when omitted")), mcp.WithString("provider", mcp.Description("github (default), gitlab, bitbucket")), mcp.WithString("tool", mcp.Description("terraform (default), opentofu")), mcp.WithString("observed_at", mcp.Description("RFC3339; extraction time if omitted"))}
	register(toolDef{name: "cloudsec_code_iac_map_extract", description: "OFFLINE stdio-only extraction of sanitized IaC identity/allowlisted desired booleans from a local Terraform show-json file. Runs operator-installed iac-map-extract (explicit LC_IAC_MAP_EXTRACTOR operator opt-in) with no auth environment and never returns raw input or extractor stderr. Returns sanitized metadata only; upload is a SEPARATE explicit cloudsec_code_iac_map_push. No organization credential is required. A partial result is incomplete evidence, never absence.", readOnly: true, noOID: true, params: params, handler: handleIaCExtract})
}

// Refuse arbitrary fields locally before any authenticated transport. This closed
// wire allowlist mirrors the public CLI preflight; the gateway independently validates.
func mapShape(raw interface{}, required, optional []string) (map[string]interface{}, error) {
	v, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid sanitized map object")
	}
	for _, k := range required {
		if _, present := v[k]; !present {
			return nil, fmt.Errorf("invalid sanitized map: missing %s", k)
		}
	}
	for k := range v {
		if !contains(required, k) && !contains(optional, k) {
			return nil, fmt.Errorf("invalid sanitized map: unexpected field; run local IaC extraction")
		}
	}
	return v, nil
}
func safeMapString(raw interface{}, nonempty bool) bool {
	v, ok := raw.(string)
	if !ok || len(v) > 4096 || !utf8.ValidString(v) || nonempty && v == "" {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) || r == unicode.ReplacementChar {
			return false
		}
	}
	return true
}
func validateSanitizedMap(raw interface{}) ([]byte, error) {
	invalid := fmt.Errorf("invalid sanitized IaC map; run cloudsec_code_iac_map_extract locally first (never upload raw Terraform)")
	doc, e := mapShape(raw, []string{"schema", "repository", "tool", "workspace", "source_kind", "observed_at", "complete", "successful", "resources"}, nil)
	if e != nil {
		return nil, invalid
	}
	if doc["schema"] != "lc-iac-map/v1" || !contains([]string{"terraform", "opentofu"}, stringValue(doc["tool"])) || !contains([]string{"state_identity", "plan_desired"}, stringValue(doc["source_kind"])) || !safeMapString(doc["workspace"], true) {
		return nil, invalid
	}
	if _, ok := doc["complete"].(bool); !ok {
		return nil, invalid
	}
	if _, ok := doc["successful"].(bool); !ok {
		return nil, invalid
	}
	if _, e := time.Parse(time.RFC3339, stringValue(doc["observed_at"])); e != nil {
		return nil, invalid
	}
	repo, e := mapShape(doc["repository"], []string{"provider", "name", "commit"}, []string{"ref"})
	if e != nil {
		return nil, invalid
	}
	if !contains([]string{"github", "gitlab", "bitbucket"}, stringValue(repo["provider"])) || !commitRe.MatchString(stringValue(repo["commit"])) || !safeMapString(repo["name"], true) {
		return nil, invalid
	}
	if _, ok := normalizedRepoKey(stringValue(repo["name"])); !ok {
		return nil, invalid
	}
	if ref, ok := repo["ref"]; ok && !safeMapString(ref, false) {
		return nil, invalid
	}
	rows, ok := doc["resources"].([]interface{})
	if !ok || len(rows) > 100000 {
		return nil, invalid
	}
	seen := map[string]bool{}
	for _, raw := range rows {
		r, e := mapShape(raw, []string{"address", "type", "provider", "scope", "identity"}, []string{"desired", "file", "line"})
		if e != nil {
			return nil, invalid
		}
		for _, k := range []string{"address", "type", "provider"} {
			if !safeMapString(r[k], true) {
				return nil, invalid
			}
		}
		address := r["address"].(string)
		if seen[address] {
			return nil, invalid
		}
		seen[address] = true
		spec, known := iacMapTypes[stringValue(r["type"])]
		if !known || r["provider"] != spec.provider {
			return nil, invalid
		}
		scope, e := mapShape(r["scope"], nil, []string{"project", "account", "subscription", "region"})
		if e != nil {
			return nil, invalid
		}
		identity, e := mapShape(r["identity"], nil, []string{"native_id", "name"})
		if e != nil || len(identity) == 0 {
			return nil, invalid
		}
		for _, obj := range []map[string]interface{}{scope, identity} {
			for _, v := range obj {
				if !safeMapString(v, false) {
					return nil, invalid
				}
			}
		}
		if file, present := r["file"]; present && !safeMapString(file, false) {
			return nil, invalid
		}
		if line, present := r["line"]; present {
			n, ok := line.(float64)
			if !ok {
				if i, yes := line.(int); yes {
					n = float64(i)
					ok = true
				}
			}
			if !ok || n < 0 || n > 2147483647 || n != float64(int(n)) {
				return nil, invalid
			}
		}
		if desired, present := r["desired"]; present {
			values, e := mapShape(desired, nil, spec.desired)
			if e != nil || doc["source_kind"] == "state_identity" && len(values) > 0 {
				return nil, invalid
			}
			for _, v := range values {
				if _, ok := v.(bool); !ok {
					return nil, invalid
				}
			}
		}
	}
	b, e := json.Marshal(doc)
	if e != nil || len(b) > maxIaCMapBytes {
		return nil, invalid
	}
	return b, nil
}
func stringValue(raw interface{}) string { v, _ := raw.(string); return v }

func handleIaCExtract(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	if refusal := requireStdio(); refusal != nil {
		return refusal, nil
	}
	b, e := boundedCodeFields(args, []string{"input", "repository", "commit", "source_kind"}, "input", "repository", "commit", "source_kind", "workspace", "provider", "tool", "observed_at")
	if e != nil {
		return tools.ErrorResult(e.Error()), nil
	}
	path := argString(args, "input")
	if !filepath.IsAbs(path) || !commitRe.MatchString(argString(args, "commit")) || !contains([]string{"state_identity", "plan_desired"}, argString(args, "source_kind")) {
		return tools.ErrorResult("input must be an absolute local file, commit a full lowercase hex commit, and source_kind state_identity or plan_desired"), nil
	}
	binary := os.Getenv("LC_IAC_MAP_EXTRACTOR")
	if binary == "" {
		return tools.ErrorResult("operator must explicitly configure LC_IAC_MAP_EXTRACTOR to opt in to local extraction"), nil
	}
	binary, e = exec.LookPath(binary)
	if e != nil {
		return tools.ErrorResult("operator-configured LC_IAC_MAP_EXTRACTOR was not found"), nil
	}
	output, e := os.CreateTemp("", "lc-mcp-iac-map-")
	if e != nil {
		return tools.ErrorResult("could not create extraction output"), nil
	}
	defer os.Remove(output.Name())
	defer output.Close()
	argv := []string{}
	for _, key := range []string{"input", "repository", "commit", "source_kind", "workspace", "provider", "tool", "observed_at"} {
		if v, present := b[key]; present {
			argv = append(argv, "--"+strings.ReplaceAll(key, "_", "-"), v.(string))
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, binary, argv...)
	cmd.WaitDelay = time.Second
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	cmd.Stdout = &boundedExtractionWriter{writer: output, remaining: maxIaCMapBytes, stop: cancel}
	if e := cmd.Run(); e != nil {
		return tools.ErrorResult("local extractor refused input or timed out; raw input and error output were not returned"), nil
	}
	if _, e = output.Seek(0, 0); e != nil {
		return tools.ErrorResult("could not read extraction output"), nil
	}
	raw, e := io.ReadAll(io.LimitReader(output, maxIaCMapBytes+1))
	if e != nil || len(raw) > maxIaCMapBytes {
		return tools.ErrorResult("sanitized extraction exceeded 20 MiB"), nil
	}
	var doc map[string]interface{}
	if json.Unmarshal(raw, &doc) != nil {
		return tools.ErrorResult("extractor returned invalid sanitized JSON"), nil
	}
	if _, e = validateSanitizedMap(doc); e != nil {
		return tools.ErrorResult(e.Error()), nil
	}
	return tools.SuccessResult(map[string]interface{}{"uploaded": false, "document": doc, "next": "Review sanitized metadata and explicitly push with cloudsec_code_iac_map_push; raw Terraform was not uploaded."}), nil
}

// lc-iac-map/v1 extraction allowlist shared with the public CLI.
var iacMapTypes = map[string]struct {
	provider string
	desired  []string
}{
	"aws_db_instance":                    {"aws", []string{"publicly_accessible", "storage_encrypted", "deletion_protection"}},
	"aws_dynamodb_table":                 {"aws", []string{"deletion_protection_enabled"}},
	"aws_instance":                       {"aws", []string{"associate_public_ip_address"}},
	"aws_rds_cluster":                    {"aws", []string{"storage_encrypted", "deletion_protection"}},
	"aws_redshift_cluster":               {"aws", []string{"publicly_accessible", "encrypted"}},
	"aws_s3_bucket":                      {"aws", []string{"force_destroy"}},
	"azurerm_cosmosdb_account":           {"azure", []string{"public_network_access_enabled"}},
	"azurerm_key_vault":                  {"azure", []string{"public_network_access_enabled", "purge_protection_enabled"}},
	"azurerm_linux_virtual_machine":      {"azure", []string{}},
	"azurerm_mssql_server":               {"azure", []string{"public_network_access_enabled"}},
	"azurerm_mysql_flexible_server":      {"azure", []string{"public_network_access_enabled"}},
	"azurerm_postgresql_flexible_server": {"azure", []string{"public_network_access_enabled"}},
	"azurerm_redis_cache":                {"azure", []string{"public_network_access_enabled", "non_ssl_port_enabled"}},
	"azurerm_storage_account":            {"azure", []string{"https_traffic_only_enabled", "public_network_access_enabled", "allow_nested_items_to_be_public"}},
	"azurerm_virtual_machine":            {"azure", []string{}},
	"azurerm_windows_virtual_machine":    {"azure", []string{}},
	"google_bigquery_dataset":            {"gcp", []string{}},
	"google_compute_instance":            {"gcp", []string{"deletion_protection", "can_ip_forward"}},
	"google_pubsub_subscription":         {"gcp", []string{}},
	"google_pubsub_topic":                {"gcp", []string{}},
	"google_sql_database_instance":       {"gcp", []string{"deletion_protection"}},
	"google_storage_bucket":              {"gcp", []string{"uniform_bucket_level_access", "force_destroy"}},
}

// Bound disk usage while the extractor runs, not merely while reading its output.
// Cancelling the command on excess kills a producer that ignores a broken pipe.
type boundedExtractionWriter struct {
	writer    io.Writer
	remaining int
	stop      context.CancelFunc
}

func (w *boundedExtractionWriter) Write(data []byte) (int, error) {
	if len(data) > w.remaining {
		allowed := w.remaining
		n, err := w.writer.Write(data[:allowed])
		w.remaining -= n
		w.stop()
		if err != nil {
			return n, err
		}
		return n, fmt.Errorf("sanitized extraction output exceeded bound")
	}
	n, err := w.writer.Write(data)
	w.remaining -= n
	return n, err
}
