package mailsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

var httpClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

const maxResponseBytes = 32 << 20
const maxRequestBytes = 1 << 20

// The parser accepts up to 100 MiB raw MIME. Base64 adds a third, so a
// privileged original-byte download needs more room than ordinary JSON reads.
const maxEMLResponseBytes = 160 << 20

// JSON POSTs cannot use GenericPOSTRequest, which encodes form fields. All
// requests share the authenticated organization's API root, context and token.
// We never retry an ambiguous transport failure or a server refusal; a timeout
// does not prove that a provider action or an irreversible purge did not happen.
func request(ctx context.Context, method, suffix string, query url.Values, body map[string]interface{}) (map[string]interface{}, error) {
	var encoded []byte
	var err error
	if method == http.MethodPost {
		encoded, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("cannot encode JSON: %w", err)
		}
		if len(encoded) > maxRequestBytes {
			return nil, fmt.Errorf("JSON body exceeds the API's 1 MiB limit")
		}
	}
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot get organization: %w", err)
	}
	target := strings.TrimRight(auth.APIRoot(), "/") + "/v1/mailsec/" + url.PathEscape(org.GetOID()) + "/" + suffix
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	timeout := 45 * time.Second
	if strings.HasSuffix(suffix, "/actions") || strings.HasSuffix(suffix, "/test") || method == http.MethodDelete {
		timeout = 150 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if org.GetCurrentJWT() == "" {
		org.RefreshJWT(0)
	}
	for attempt := 0; attempt < 2; attempt++ {
		r, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(encoded))
		if err != nil {
			return nil, err
		}
		r.Header.Set("Authorization", "bearer "+org.GetCurrentJWT())
		r.Header.Set("User-Agent", "lc-mcp-server")
		if method == http.MethodPost {
			r.Header.Set("Content-Type", "application/json")
		}
		response, err := httpClient.Do(r)
		if err != nil {
			return nil, fmt.Errorf("%s request did not return an outcome; inspect the action audit or bulk handle before retrying: %w", method, err)
		}
		responseLimit := maxResponseBytes
		if method == http.MethodGet && strings.HasSuffix(suffix, "/eml") {
			responseLimit = maxEMLResponseBytes
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, int64(responseLimit)+1))
		response.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("could not read the outcome; a write may already have completed: %w", readErr)
		}
		if len(raw) > responseLimit {
			return nil, fmt.Errorf("response exceeded %d bytes", responseLimit)
		}
		// Authentication is checked before any action. Only an explicit 401 can
		// refresh once; 429/5xx/timeouts never cause a second write.
		if response.StatusCode == http.StatusUnauthorized && attempt == 0 && org.RefreshJWT(0) != "" {
			continue
		}
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(raw)))
		}
		var out map[string]interface{}
		if err := json.Unmarshal(raw, &out); err != nil || out == nil {
			return nil, fmt.Errorf("server did not return a JSON object")
		}
		return out, nil
	}
	return nil, fmt.Errorf("authentication refresh failed")
}
