package testutil

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

// FakeAPI is a local stand-in for the LimaCharlie REST gateway, so a tool handler can be
// driven end to end through the real SDK (SDK cache, organization client, request
// building) without any network. It records every request so a test can assert exactly
// which organization and partition a call reached.
type FakeAPI struct {
	Server *httptest.Server

	mu       sync.Mutex
	requests []RecordedRequest
	handler  http.HandlerFunc
}

// RecordedRequest is one request the fake gateway received.
type RecordedRequest struct {
	Method string
	// Path is the escaped request path as it went on the wire.
	Path string
	Body []byte
}

// InstallFakeAPI starts the fake gateway and points this process at it via LC_API_URL.
//
// auth.APIRoot resolves that variable once per process, so this must be called from
// TestMain, before any test touches the SDK. The returned stop function shuts it down.
func InstallFakeAPI() (*FakeAPI, func()) {
	f := &FakeAPI{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.requests = append(f.requests, RecordedRequest{Method: r.Method, Path: r.URL.EscapedPath(), Body: body})
		h := f.handler
		f.mu.Unlock()
		// Handlers read the body again, so give it back.
		r.Body = io.NopCloser(bytes.NewReader(body))
		if h == nil {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
			return
		}
		h(w, r)
	}))
	os.Setenv("LC_API_URL", f.Server.URL)
	return f, f.Server.Close
}

// Handle replaces the gateway's behaviour for the rest of the test (nil restores the
// default empty-JSON answer) and clears the request log.
func (f *FakeAPI) Handle(t *testing.T, h http.HandlerFunc) {
	f.mu.Lock()
	f.handler = h
	f.requests = nil
	f.mu.Unlock()
	t.Cleanup(func() {
		f.mu.Lock()
		f.handler = nil
		f.mu.Unlock()
	})
}

// Requests returns a copy of the request log.
func (f *FakeAPI) Requests() []RecordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]RecordedRequest(nil), f.requests...)
}

// Context builds a request context the way the HTTP transport does for an
// authenticated caller whose effective organization is oid: auth context (with a
// non-expired synthetic JWT, so the SDK never tries to mint one) and an SDK cache. It
// carries no local-filesystem marker, exactly like an HTTP request.
func (f *FakeAPI) Context(t *testing.T, mode auth.AuthMode, oid string) context.Context {
	t.Helper()
	cache := auth.NewSDKCache(time.Minute, nil)
	t.Cleanup(cache.Close)
	claims := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Hour).Unix())))
	a := &auth.AuthContext{
		Mode:     mode,
		OID:      oid,
		UID:      "uid-test",
		JWTToken: "eyJhbGciOiJIUzI1NiJ9." + claims + ".synthetic",
	}
	return auth.WithAuthContext(auth.WithSDKCache(context.Background(), cache), a)
}

// DotSegmentRequests returns the recorded requests whose path has a "." or ".."
// segment: what anything between this server and the API that resolves dot
// segments would turn into a different route.
func (f *FakeAPI) DotSegmentRequests() []RecordedRequest {
	var out []RecordedRequest
	for _, r := range f.Requests() {
		for _, seg := range strings.Split(r.Path, "/") {
			if seg == "." || seg == ".." {
				out = append(out, r)
				break
			}
		}
	}
	return out
}
