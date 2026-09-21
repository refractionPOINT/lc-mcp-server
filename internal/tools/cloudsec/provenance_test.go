package cloudsec

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestProvenancePushBoundsBeforeAuthentication(t *testing.T) {
	for _, document := range []any{nil, 123, "", strings.Repeat("x", (1<<20)+1), "not JSON"} {
		result, err := pushProvenance(context.Background(), map[string]interface{}{"document": document})
		if err != nil || result == nil || !result.IsError {
			t.Fatal("invalid document accepted")
		}
	}
}

func TestProvenanceReadBoundsBeforeAuthentication(t *testing.T) {
	for _, args := range []map[string]interface{}{{"digest": strings.Repeat("a", 72)}, {"commit": "a\n"}, {"cursor": "a\x00"}, {"repo_urn": 42}} {
		r, e := readProvenance(context.Background(), args)
		if e != nil || r == nil || !r.IsError {
			t.Fatal("invalid selector accepted")
		}
	}
}

type provenanceTransport func(*http.Request) (*http.Response, error)

func (f provenanceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestProvenanceTransportScopesIdentityAndPreservesBytes(t *testing.T) {
	cache := auth.NewSDKCache(time.Minute, nil)
	defer cache.Close()
	old := httpClient
	t.Cleanup(func() { httpClient = old })
	calls := 0
	httpClient = &http.Client{Transport: provenanceTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "api.limacharlie.io" {
			t.Fatal("customer host followed")
		}
		if _, ok := r.Context().Deadline(); !ok {
			t.Fatal("missing deadline")
		}
		if !strings.Contains(r.URL.Path, "/cloudsec/"+oidForProvenanceTest+"/code/provenance") {
			t.Fatal("tenant path changed")
		}
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			if string(b) != `{ "schema": "fixture" }` {
				t.Fatal("signed bytes rewritten")
			}
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"result":{"provenance":[]}}`)), Header: http.Header{}}, nil
	})}
	ctx := auth.WithSDKCache(context.Background(), cache)
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Hour).Unix())))
	ctx = auth.WithAuthContext(ctx, &auth.AuthContext{Mode: auth.AuthModeNormal, OID: oidForProvenanceTest, JWTToken: "eyJhbGciOiJIUzI1NiJ9." + payload + ".synthetic"})
	r, e := pushProvenance(ctx, map[string]interface{}{"document": `{ "schema": "fixture" }`, "oid": "foreign", "url": "https://untrusted.invalid"})
	if e != nil || r.IsError || calls != 1 {
		t.Fatal("push failed", r, e, calls)
	}
	r, e = readProvenance(ctx, map[string]interface{}{"digest": "sha256:" + strings.Repeat("a", 64)})
	if e != nil || r.IsError || calls != 2 {
		t.Fatal("read failed", r, e)
	}
	r, e = readProvenance(ctx, map[string]interface{}{"repo_urn": "lcrn:1:11111111-1111-4111-8111-111111111111:github:repo"})
	if e != nil || !r.IsError || calls != 2 {
		t.Fatal("foreign tenant forwarded")
	}
}

const oidForProvenanceTest = "b85fd2bd-ae21-4c1f-8a42-b90b51aeddeb"
