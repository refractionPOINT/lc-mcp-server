package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

// lcAPIRoot is the LimaCharlie REST API root for this process: whatever
// auth.APIRoot() resolved (the production gateway unless the operator set
// LC_API_URL), plus the API version.
//
// It is READ, not hardcoded, because it is the same value the SDK client is
// constructed with. A hardcoded root here meant that pointing the server at a
// staging gateway moved every other call and left this one talking to production
// with the same credential — one route silently answering from a different estate
// is worse than no override at all.
func lcAPIRoot() string {
	return auth.APIRoot() + "/v1/"
}

// jsonPostTimeout bounds a single PostJSON attempt.
const jsonPostTimeout = 2 * time.Minute

var jsonPostClient = &http.Client{Timeout: jsonPostTimeout}

// PostJSON issues a POST with an application/json request body against the
// LimaCharlie REST API and decodes the JSON response into out (which may be
// nil to discard it). path is relative to the /v1/ API root, e.g.
// "orgs/<oid>/investigation/expand".
//
// The SDK's Organization.GenericPOSTRequest form-encodes its payload, which
// gateway routes that read the raw body with json.Unmarshal reject (the
// gateway's own form parsing drains the body first, so the handler sees
// "missing request body"). Those routes need this helper instead. The SDK's
// equivalent internal path is withRawBody, which Generic*Request cannot reach.
//
// A 401 is retried once after asking the SDK to mint a fresh JWT; when the
// client has no API key to refresh with, the 401 is returned as-is.
func PostJSON(ctx context.Context, org *lc.Organization, path string, body interface{}, out interface{}) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	fullURL := lcAPIRoot() + strings.TrimPrefix(path, "/")

	status, respBody, err := postJSONOnce(ctx, org.GetCurrentJWT(), fullURL, raw)
	if err != nil {
		return err
	}
	if status == http.StatusUnauthorized {
		// RefreshJWT needs an API key; with a bare JWT it returns "" and the
		// 401 stands.
		if jwt := org.RefreshJWT(0); jwt != "" {
			status, respBody, err = postJSONOnce(ctx, jwt, fullURL, raw)
			if err != nil {
				return err
			}
		}
	}
	if status < 200 || status > 299 {
		return fmt.Errorf("POST %s failed with status %d: %s", path, status, strings.TrimSpace(string(respBody)))
	}

	if out == nil {
		return nil
	}
	if len(bytes.TrimSpace(respBody)) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("failed to decode response from %s: %w", path, err)
	}
	return nil
}

func postJSONOnce(ctx context.Context, jwt string, url string, raw []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "limacharlie-mcp")
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}

	resp, err := jsonPostClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return resp.StatusCode, respBody, nil
}
