package investigation

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

// httpClient talks to the LimaCharlie gateway's /v1/investigate/{oid}/... routes. It never follows a
// redirect: a redirect would carry the caller's token somewhere the gateway did not name.
var httpClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// maxResponseBytes bounds a gateway answer. The authoring kit is about 100 KB; nothing the engine sends
// legitimately comes near this.
const maxResponseBytes = 16 << 20

// maxRequestBytes bounds a request body. A plan template is a few KB to a few tens of KB.
const maxRequestBytes = 1 << 20

// requestTimeout is the longest one gateway call may take. The slowest route is a long poll: wait (at most 10
// seconds) plus the gateway's margin.
const requestTimeout = 45 * time.Second

// engineCall is one call to the Investigation Engine through the gateway.
type engineCall struct {
	method string
	// suffix is the route under /v1/investigate/{oid}/, already path-escaped where it carries an id.
	suffix string
	query  url.Values
	body   map[string]interface{}
}

// call sends the request as the authenticated caller and decodes the JSON object the engine answered. A
// non-2xx answer is an error carrying the gateway's message, which is the engine's own words
// ({"error": "..."}).
func call(ctx context.Context, c engineCall) (map[string]interface{}, error) {
	var encoded []byte
	if c.method == http.MethodPost {
		var err error
		if encoded, err = json.Marshal(c.body); err != nil {
			return nil, fmt.Errorf("cannot encode JSON: %w", err)
		}
		if len(encoded) > maxRequestBytes {
			return nil, fmt.Errorf("request body is %d bytes, over this tool's %d byte limit", len(encoded), maxRequestBytes)
		}
	}
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot get organization: %w", err)
	}
	target := strings.TrimRight(auth.APIRoot(), "/") + "/v1/investigate/" + url.PathEscape(org.GetOID()) + "/" + c.suffix
	if len(c.query) > 0 {
		target += "?" + c.query.Encode()
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	if org.GetCurrentJWT() == "" {
		org.RefreshJWT(0)
	}
	for attempt := 0; attempt < 2; attempt++ {
		r, err := http.NewRequestWithContext(ctx, c.method, target, bytes.NewReader(encoded))
		if err != nil {
			return nil, err
		}
		r.Header.Set("Authorization", "bearer "+org.GetCurrentJWT())
		r.Header.Set("User-Agent", "lc-mcp-server")
		if c.method == http.MethodPost {
			r.Header.Set("Content-Type", "application/json")
		}
		response, err := httpClient.Do(r)
		if err != nil {
			return nil, fmt.Errorf("request to the investigation engine failed: %w", err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
		response.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("could not read the engine's answer: %w", readErr)
		}
		if len(raw) > maxResponseBytes {
			return nil, fmt.Errorf("the engine's answer exceeded %d bytes", maxResponseBytes)
		}
		// Authentication is checked before anything runs, so an explicit 401 is the only status that is
		// safe to repeat after a token refresh.
		if response.StatusCode == http.StatusUnauthorized && attempt == 0 && org.RefreshJWT(0) != "" {
			continue
		}
		if response.StatusCode < 200 || response.StatusCode > 299 {
			return nil, fmt.Errorf("HTTP %d: %s", response.StatusCode, errorMessage(raw))
		}
		var out map[string]interface{}
		if err := json.Unmarshal(raw, &out); err != nil || out == nil {
			return nil, fmt.Errorf("the engine did not answer with a JSON object")
		}
		return out, nil
	}
	return nil, fmt.Errorf("authentication refresh failed")
}

// errorMessage is the engine's "error" field when the body has one, else the trimmed body.
func errorMessage(raw []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error != "" {
		return e.Error
	}
	return strings.TrimSpace(string(raw))
}
