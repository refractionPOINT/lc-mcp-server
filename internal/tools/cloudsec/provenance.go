package cloudsec

import (
	"context"
	"encoding/json"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func registerProvenance() {
	register(toolDef{name: "cloudsec_code_provenance", description: "Read normalized build attestations by repository URN, commit or OCI sha256 digest. Conflicting or stale claims remain unknown even when filters hide a conflicting claim; paginate with result.next_cursor.", readOnly: true, params: []mcp.ToolOption{mcp.WithString("repo_urn"), mcp.WithString("commit"), mcp.WithString("digest"), mcp.WithString("cursor")}, handler: readProvenance})
	register(toolDef{name: "cloudsec_code_provenance_push", description: "Push a metadata-only LC/SLSA provenance document or offline Sigstore bundle (1 MiB maximum). Requires cloudsec.set; server assigns tenant and trust. Do not supply source, snippets, credentials, environment variables or build output. A failed signature is refused, never downgraded.", destructive: false, params: []mcp.ToolOption{mcp.WithString("document", mcp.Required(), mcp.Description("Exact JSON document bytes as a string; no file path or URL is fetched."))}, handler: pushProvenance})
}
func pushProvenance(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	raw, ok := args["document"].(string)
	if !ok || len(raw) == 0 || len(raw) > 1<<20 || !json.Valid([]byte(raw)) {
		return tools.ErrorResult("document must be valid JSON at most 1 MiB"), nil
	}
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResult("organization authentication required"), nil
	}
	response, err := rawRequest(ctx, org, http.MethodPost, orgPath(org, "code/provenance"), nil, []byte(raw), 15*time.Second, 1<<20)
	if err != nil {
		return tools.ErrorResultf("provenance push failed: %s", describeErr(err)), nil
	}
	if len(response) > 1<<20 {
		return tools.ErrorResult("provenance response exceeded bound"), nil
	}
	var decoded map[string]interface{}
	if json.Unmarshal(response, &decoded) != nil {
		return tools.ErrorResult("invalid provenance response"), nil
	}
	return tools.SuccessResult(decoded), nil
}

func readProvenance(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	query := url.Values{}
	for key, max := range map[string]int{"repo_urn": 4096, "commit": 64, "digest": 71, "cursor": 2048} {
		if value, present := args[key]; present {
			str, ok := value.(string)
			if !ok || len(str) > max || strings.ContainsAny(str, "\r\n\x00") {
				return tools.ErrorResult("invalid provenance selector"), nil
			}
			query.Set(key, str)
		}
	}
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return tools.ErrorResult("organization authentication required"), nil
	}
	if repo := query.Get("repo_urn"); repo != "" && !strings.HasPrefix(repo, "lcrn:1:"+org.GetOID()+":") {
		return tools.ErrorResult("repository must belong to this organization"), nil
	}
	response, err := rawRequest(ctx, org, http.MethodGet, orgPath(org, "code/provenance"), query, nil, 15*time.Second, 8<<20)
	if err != nil {
		return tools.ErrorResult("provenance read failed"), nil
	}
	if len(response) > 8<<20 {
		return tools.ErrorResult("provenance response exceeded bound"), nil
	}
	var decoded map[string]interface{}
	if json.Unmarshal(response, &decoded) != nil {
		return tools.ErrorResult("invalid provenance response"), nil
	}
	return tools.SuccessResult(decoded), nil
}
