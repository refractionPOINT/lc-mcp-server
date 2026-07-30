package cloudsec

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

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

const (
	// defaultAPIRoot mirrors the SDK's own rootURL/currentAPIVersion (client.go:22-23).
	// The MCP never overrides ClientOptions.URL, so the SDK reads and the raw requests
	// below always talk to the same gateway.
	defaultAPIRoot = "https://api.limacharlie.io"
	apiVersion     = "v1"

	// defaultTimeout covers the gateway's own 20s cloudsec RPC budget plus transport.
	defaultTimeout = 45 * time.Second
	// providerTestTimeout must clear the gateway's 60s provider-preflight budget
	// (cloudSecTestTimeout, endpoint_cloudsec.go:45) or a legitimately slow probe
	// looks like a client failure.
	providerTestTimeout = 120 * time.Second
	// ingestTimeout covers the CAASM ingest's 60s server-side reconcile
	// (caasmIngestTimeout, endpoint_cloudsec_caasm.go:37).
	ingestTimeout = 120 * time.Second
	// csvTimeout covers a full server-side export walk (up to 100k rows).
	csvTimeout = 300 * time.Second
)

// extGateNote is appended to every tool description: the whole /cloudsec/* surface
// sits behind the extension subscription gate (requireCloudSecEnabled,
// endpoint_cloudsec.go:95-106) and a 403 has a one-step remedy.
const extGateNote = `Requires the "ext-cloud-security" extension: a 403 saying cloud security is not enabled means the org is not subscribed — call subscribe_to_extension("ext-cloud-security") and retry.`

// hiveNote points at the hives that hold cloudsec configuration. Those records are
// not part of the /cloudsec/* API surface, so an agent reading only these tools has
// no other way to discover them.
const hiveNote = `Provider/policy/query CONFIGURATION lives in the "cloudsec_provider", "cloudsec_policy" and "cloudsec_query" hives — read/write it with the generic hive tools (list_rules / get_rule / set_rule / delete_rule with hive_name), not through this tool.`

// apiRoot returns the gateway base URL. It is deliberately not overridable: the
// package's GET reads go through the SDK (which resolves its own hardcoded root),
// so an override here would split reads and writes across two gateways.
func apiRoot() string {
	return defaultAPIRoot
}

// httpClient is shared; each call carries its own context deadline.
var httpClient = &http.Client{}

// orgPath builds the oid-scoped path suffix every per-org cloudsec route shares.
func orgPath(org *lc.Organization, suffix string) string {
	return fmt.Sprintf("cloudsec/%s/%s", org.GetOID(), suffix)
}

// apiError carries a non-200 gateway response so the caller can render the
// gateway's own error text (the enable-gate 403 in particular) rather than a
// generic transport failure.
type apiError struct {
	Status int
	Body   string
}

func (e *apiError) Error() string {
	body := strings.TrimSpace(e.Body)
	if body == "" {
		return fmt.Sprintf("HTTP %d", e.Status)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, body)
}

// describeErr renders an error for a tool result, appending the extension-gate
// remedy when the failure looks like the cloud-security enable gate refusing the
// call. The gateway answers that case with a 403 whose body names the extension.
func describeErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if strings.Contains(s, "cloud security is not enabled") {
		return s + ` — subscribe the organization to the "ext-cloud-security" extension (subscribe_to_extension) and retry.`
	}
	return s
}

// rawRequest performs a single cloudsec HTTP call against the gateway and returns
// the response body verbatim.
//
// Two reasons this exists instead of the SDK's Generic*Request helpers:
//   - every cloudsec POST route reads the raw body and json.Unmarshals it
//     (cloudSecReadBody, endpoint_cloudsec.go:212-223), while
//     GenericPOSTRequest sends application/x-www-form-urlencoded — which those
//     routes answer with 400 {"error":"request body must be a JSON object"}.
//   - the ?format=csv exports answer text/csv, which the SDK's JSON response
//     decoding cannot represent.
//
// On a 401 the JWT is refreshed once and the call retried, mirroring what the SDK's
// own reliableRequest does (client.go, reliableRequest).
// readLimit bounds how much of the response body is read into memory, so a 100k-row
// export cannot balloon the process. A JSON caller passes maxJSONResponseBytes and
// treats hitting it as an error; the CSV caller passes its own byte budget and cuts
// the document at a row boundary.
func rawRequest(ctx context.Context, org *lc.Organization, method, path string, query url.Values, body []byte, timeout time.Duration, readLimit int64) ([]byte, error) {
	target := fmt.Sprintf("%s/%s/%s", apiRoot(), apiVersion, path)
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	// In API-key mode the cached client may not have minted a JWT yet (the SDK primes
	// it lazily on its first request), so prime it rather than spending a 401.
	if org.GetCurrentJWT() == "" {
		org.RefreshJWT(0)
	}

	for attempt := 0; attempt < 2; attempt++ {
		respBody, status, err := doRequest(ctx, org, method, target, body, timeout, readLimit)
		if err != nil {
			return nil, err
		}
		if status == http.StatusOK {
			return respBody, nil
		}
		// A 401 usually means the cached JWT aged out. Refresh once and retry;
		// RefreshJWT needs an API key, so in a bearer-token deployment it returns
		// "" and the original error stands. The expiry argument is 0 (the gateway's
		// default lifetime) because the SDK does not export the configured
		// JWTExpiryTime it would use itself; a shorter-lived JWT only means the SDK
		// refreshes it again on its own next 401.
		if status == http.StatusUnauthorized && attempt == 0 {
			if refreshed := org.RefreshJWT(0); refreshed != "" {
				continue
			}
		}
		return nil, &apiError{Status: status, Body: string(respBody)}
	}
	return nil, &apiError{Status: http.StatusUnauthorized, Body: "authorization refresh did not resolve the request"}
}

// doRequest issues one HTTP attempt and returns the body (read up to readLimit
// bytes) and status.
func doRequest(ctx context.Context, org *lc.Organization, method, target string, body []byte, timeout time.Duration, readLimit int64) ([]byte, int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(reqCtx, method, target, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "lc-mcp-server")
	req.Header.Set("Authorization", "bearer "+org.GetCurrentJWT())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	// One byte past the budget, so the caller can tell "exactly at the limit" from
	// "there was more".
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, readLimit+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return respBody, resp.StatusCode, nil
}

// maxJSONResponseBytes bounds a JSON cloudsec response. The paged reads are bounded
// server-side well below this, so hitting it means something is wrong rather than
// large.
const maxJSONResponseBytes = 32 << 20 // 32 MiB

// postJSON sends a JSON body to a cloudsec route and returns the (unwrapped) JSON
// response. The gateway writes the backend RPC's Data dict directly
// (request.respond, service/server.go), so the payload arrives as-is.
func postJSON(ctx context.Context, org *lc.Organization, path string, body map[string]interface{}, timeout time.Duration) (map[string]interface{}, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("could not encode request body: %w", err)
	}
	respBody, err := rawRequest(ctx, org, http.MethodPost, path, nil, encoded, timeout, maxJSONResponseBytes)
	if err != nil {
		return nil, err
	}
	if len(respBody) > maxJSONResponseBytes {
		return nil, fmt.Errorf("response exceeded %d bytes", maxJSONResponseBytes)
	}
	out := map[string]interface{}{}
	if len(bytes.TrimSpace(respBody)) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("could not decode response: %w", err)
	}
	return out, nil
}
