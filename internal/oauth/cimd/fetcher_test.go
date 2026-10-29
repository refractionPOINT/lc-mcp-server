package cimd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/refractionpoint/lc-mcp-go/internal/crypto"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/refractionpoint/lc-mcp-go/internal/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// testEnv is a TLS "client host" plus a fetcher wired to Redis (miniredis).
type testEnv struct {
	srv     *httptest.Server
	fetcher *Fetcher
	mr      *miniredis.Miniredis
	hits    *atomic.Int64
}

// docHandler serves a metadata document for the request path; mutate may alter
// the document or the response.
type docFunc func(w http.ResponseWriter, r *http.Request, selfURL string)

func newTestEnv(t *testing.T, serve docFunc) *testEnv {
	t.Helper()
	mr := miniredis.RunT(t)
	rc, err := redis.New(&redis.Config{URL: "redis://" + mr.Addr()}, testLogger())
	require.NoError(t, err)

	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	t.Setenv("REDIS_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(key))
	enc, err := crypto.NewTokenEncryption(testLogger())
	require.NoError(t, err)
	store := state.NewManager(rc, enc, testLogger())

	hits := &atomic.Int64{}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		serve(w, r, srv.URL+r.URL.Path)
	}))
	t.Cleanup(srv.Close)

	return &testEnv{
		srv:     srv,
		fetcher: NewFetcherForTesting(store, testLogger(), srv.Client().Transport),
		mr:      mr,
		hits:    hits,
	}
}

func (e *testEnv) url(path string) string { return e.srv.URL + path }

func writeDoc(w http.ResponseWriter, selfURL string, mutate func(m map[string]any)) {
	doc := map[string]any{
		"client_id":                  selfURL,
		"client_name":                "Example MCP Client",
		"redirect_uris":              []string{"https://app.example.com/callback", "http://localhost:3000/callback"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	if mutate != nil {
		mutate(doc)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func okDoc(w http.ResponseWriter, _ *http.Request, self string) { writeDoc(w, self, nil) }

func kindOf(t *testing.T, err error) ErrorKind {
	t.Helper()
	require.Error(t, err)
	ce, ok := err.(*Error)
	require.True(t, ok, "want *Error, got %T: %v", err, err)
	return ce.Kind
}

func TestResolve_ValidDocument(t *testing.T) {
	var gotHeaders http.Header
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request, self string) {
		gotHeaders = r.Header.Clone()
		writeDoc(w, self, nil)
	})
	id := env.url("/oauth/client.json")

	doc, err := env.fetcher.Resolve(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, id, doc.ClientID)
	assert.Equal(t, "Example MCP Client", doc.ClientName)
	assert.Equal(t, []string{"https://app.example.com/callback", "http://localhost:3000/callback"}, doc.RedirectURIs)
	assert.True(t, doc.HasRedirectURI("https://app.example.com/callback"))
	assert.False(t, doc.HasRedirectURI("https://app.example.com/callback/"), "exact match only")
	assert.False(t, doc.HasRedirectURI("https://APP.example.com/callback"), "exact match only")

	assert.Equal(t, "application/json", gotHeaders.Get("Accept"))
	assert.Empty(t, gotHeaders.Get("Cookie"))
	assert.Empty(t, gotHeaders.Get("Authorization"))
}

func TestResolve_ClientIDMismatch(t *testing.T) {
	cases := map[string]func(self string) string{
		"different url":    func(self string) string { return "https://other.example.com/client.json" },
		"trailing slash":   func(self string) string { return self + "/" },
		"path case change": func(self string) string { return "https://" + strings.ToUpper(self[len("https://"):]) },
		"empty":            func(self string) string { return "" },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
				writeDoc(w, self, func(m map[string]any) { m["client_id"] = mk(self) })
			})
			_, err := env.fetcher.Resolve(context.Background(), env.url("/client.json"))
			assert.Equal(t, KindInvalidDocument, kindOf(t, err))
		})
	}

	t.Run("scheme case differs", func(t *testing.T) {
		env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
			writeDoc(w, self, func(m map[string]any) {
				m["client_id"] = strings.ToUpper(self[:8]) + self[8:] // scheme case
			})
		})
		_, err := env.fetcher.Resolve(context.Background(), env.url("/client.json"))
		assert.Equal(t, KindInvalidDocument, kindOf(t, err))
	})

	t.Run("not a string", func(t *testing.T) {
		env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
			writeDoc(w, self, func(m map[string]any) { m["client_id"] = 42 })
		})
		_, err := env.fetcher.Resolve(context.Background(), env.url("/client.json"))
		assert.Equal(t, KindInvalidDocument, kindOf(t, err))
	})
}

func TestResolve_InvalidDocuments(t *testing.T) {
	cases := map[string]func(m map[string]any){
		"missing client_name":       func(m map[string]any) { delete(m, "client_name") },
		"empty client_name":         func(m map[string]any) { m["client_name"] = "  " },
		"client_name not string":    func(m map[string]any) { m["client_name"] = []string{"x"} },
		"client_name too long":      func(m map[string]any) { m["client_name"] = strings.Repeat("x", 101) },
		"client_name control char":  func(m map[string]any) { m["client_name"] = "Evil\nClient" },
		"client_name bidi override": func(m map[string]any) { m["client_name"] = "Good‮Client" },
		"missing redirect_uris":     func(m map[string]any) { delete(m, "redirect_uris") },
		"empty redirect_uris":       func(m map[string]any) { m["redirect_uris"] = []string{} },
		"null redirect_uris":        func(m map[string]any) { m["redirect_uris"] = nil },
		"redirect_uris not array":   func(m map[string]any) { m["redirect_uris"] = "https://app.example.com/cb" },
		"redirect_uris wrong elem":  func(m map[string]any) { m["redirect_uris"] = []int{1} },
		"http non-localhost redirect": func(m map[string]any) {
			m["redirect_uris"] = []string{"https://app.example.com/cb", "http://app.example.com/cb"}
		},
		"custom scheme redirect": func(m map[string]any) { m["redirect_uris"] = []string{"myapp://cb"} },
		"redirect with fragment": func(m map[string]any) { m["redirect_uris"] = []string{"https://app.example.com/cb#x"} },
		"redirect with userinfo": func(m map[string]any) { m["redirect_uris"] = []string{"https://u@app.example.com/cb"} },
		"too many redirects": func(m map[string]any) {
			var uris []string
			for i := 0; i < 21; i++ {
				uris = append(uris, fmt.Sprintf("https://app.example.com/cb%d", i))
			}
			m["redirect_uris"] = uris
		},
		"grant_types lacks authorization_code": func(m map[string]any) { m["grant_types"] = []string{"client_credentials"} },
		"response_types lacks code":            func(m map[string]any) { m["response_types"] = []string{"token"} },
		"client_secret present":                func(m map[string]any) { m["client_secret"] = "s3cret" },
		"client_secret empty":                  func(m map[string]any) { m["client_secret"] = "" },
		"client_secret_expires_at":             func(m map[string]any) { m["client_secret_expires_at"] = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) { writeDoc(w, self, mutate) })
			_, err := env.fetcher.Resolve(context.Background(), env.url("/client.json"))
			assert.Equal(t, KindInvalidDocument, kindOf(t, err))
		})
	}
}

func TestResolve_UnsupportedAuthMethods(t *testing.T) {
	for _, method := range []string{"private_key_jwt", "client_secret_basic", "client_secret_post", "client_secret_jwt", "tls_client_auth", ""} {
		t.Run(method, func(t *testing.T) {
			env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
				writeDoc(w, self, func(m map[string]any) {
					m["token_endpoint_auth_method"] = method
					m["jwks_uri"] = "https://app.example.com/jwks.json"
				})
			})
			_, err := env.fetcher.Resolve(context.Background(), env.url("/client.json"))
			assert.Equal(t, KindUnsupported, kindOf(t, err))
		})
	}

	t.Run("none or absent is fine", func(t *testing.T) {
		env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
			writeDoc(w, self, func(m map[string]any) { delete(m, "token_endpoint_auth_method") })
		})
		_, err := env.fetcher.Resolve(context.Background(), env.url("/client.json"))
		require.NoError(t, err)
	})
}

func TestResolve_BadBodies(t *testing.T) {
	raw := func(ct, body string) docFunc {
		return func(w http.ResponseWriter, _ *http.Request, _ string) {
			if ct != "" {
				w.Header().Set("Content-Type", ct)
			}
			_, _ = io.WriteString(w, body)
		}
	}
	cases := map[string]docFunc{
		"invalid json":     raw("application/json", `{"client_id": `),
		"not an object":    raw("application/json", `["a"]`),
		"json null":        raw("application/json", `null`),
		"empty body":       raw("application/json", ``),
		"trailing garbage": raw("application/json", `{"client_id":"x"} {"a":1}`),
		"html content type": func(w http.ResponseWriter, _ *http.Request, s string) {
			w.Header().Set("Content-Type", "text/html")
			_ = json.NewEncoder(w).Encode(map[string]any{"client_id": s, "client_name": "x", "redirect_uris": []string{"https://a.example/cb"}})
		},
		"no content type": raw("", `{}`),
		"text/plain":      raw("text/plain", `{}`),
		"oversized":       raw("application/json", `{"client_name":"`+strings.Repeat("a", 70<<10)+`"}`),
		"oversized no length": func(w http.ResponseWriter, _ *http.Request, _ string) {
			w.Header().Set("Content-Type", "application/json")
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, strings.Repeat(" ", 70<<10))
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			env := newTestEnv(t, h)
			_, err := env.fetcher.Resolve(context.Background(), env.url("/client.json"))
			require.Error(t, err)
			assert.NotEqual(t, KindBusy, kindOf(t, err))
		})
	}

	t.Run("vendor json content type is accepted", func(t *testing.T) {
		env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request, self string) {
			w.Header().Set("Content-Type", "application/oauth-client+json; charset=utf-8")
			_ = json.NewEncoder(w).Encode(map[string]any{"client_id": self, "client_name": "x", "redirect_uris": []string{"https://a.example/cb"}})
		})
		_, err := env.fetcher.Resolve(context.Background(), env.url("/client.json"))
		require.NoError(t, err)
	})

	t.Run("document just under the cap", func(t *testing.T) {
		env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
			writeDoc(w, self, func(m map[string]any) { m["extra"] = strings.Repeat("a", 60<<10) })
		})
		_, err := env.fetcher.Resolve(context.Background(), env.url("/client.json"))
		require.NoError(t, err)
	})
}

func TestResolve_StatusAndRedirects(t *testing.T) {
	for _, code := range []int{201, 204, 301, 302, 307, 308, 400, 401, 403, 404, 429, 500, 503} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var target atomic.Int64
			other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target.Add(1)
				writeDoc(w, "https://"+r.Host+r.URL.Path, nil)
			}))
			t.Cleanup(other.Close)
			env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request, self string) {
				if code >= 300 && code < 400 {
					w.Header().Set("Location", other.URL+"/client.json")
				}
				w.WriteHeader(code)
			})
			_, err := env.fetcher.Resolve(context.Background(), env.url("/client.json"))
			assert.Equal(t, KindFetch, kindOf(t, err))
			assert.Zero(t, target.Load(), "a redirect must never be followed")
		})
	}
}

func TestResolve_SlowServerTimesOut(t *testing.T) {
	release := make(chan struct{})
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request, self string) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		writeDoc(w, self, nil)
	})
	t.Cleanup(func() { close(release) })
	env.fetcher.client.Timeout = 300 * time.Millisecond

	start := time.Now()
	_, err := env.fetcher.Resolve(context.Background(), env.url("/client.json"))
	assert.Equal(t, KindFetch, kindOf(t, err))
	assert.Less(t, time.Since(start), 3*time.Second)
}

func TestResolve_SlowBodyTimesOut(t *testing.T) {
	release := make(chan struct{})
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request, self string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, `{"client_id":`)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	t.Cleanup(func() { close(release) })
	env.fetcher.client.Timeout = 300 * time.Millisecond

	_, err := env.fetcher.Resolve(context.Background(), env.url("/client.json"))
	assert.Equal(t, KindFetch, kindOf(t, err))
}

func TestResolve_RejectsBadClientIDsWithoutFetching(t *testing.T) {
	env := newTestEnv(t, okDoc)
	// A production-policy fetcher (no relaxed URL rules) pointed at the test store.
	prod := newFetcher(env.fetcher.store, testLogger(), env.fetcher.client, urlPolicy{})

	for _, id := range []string{
		strings.Replace(env.url("/client.json"), "https://", "http://", 1), // http
		"https://example.com",                     // no path
		"https://example.com/",                    // root path
		"https://user:pw@example.com/client.json", // userinfo
		"https://example.com/client.json#frag",    // fragment
		env.url("/client.json"),                   // IP literal + non-default port
		"https://example.com:8443/client.json",    // non-default port
		"https://localhost/client.json",
		"mcp_registered_client",
	} {
		_, err := prod.Resolve(context.Background(), id)
		assert.Equal(t, KindInvalidClientID, kindOf(t, err), id)
	}
	assert.Zero(t, env.hits.Load(), "no request may be made for rejected client_ids")

	// The relaxed test fetcher still refuses non-https and malformed URLs.
	for _, id := range []string{
		strings.Replace(env.url("/client.json"), "https://", "http://", 1),
		"https://example.com",
		"https://user:pw@example.com/client.json",
		env.url("/client.json#frag"),
	} {
		_, err := env.fetcher.Resolve(context.Background(), id)
		assert.Equal(t, KindInvalidClientID, kindOf(t, err), id)
	}
	assert.Zero(t, env.hits.Load())
}

// ===== caching =====

func (e *testEnv) docTTL(id string) time.Duration { return e.mr.TTL(DocPrefix + cacheKey(id)) }
func (e *testEnv) hasDoc(id string) bool          { return e.mr.Exists(DocPrefix + cacheKey(id)) }

func TestCache_HonoursMaxAgeWithinBounds(t *testing.T) {
	cases := []struct {
		name         string
		cacheControl string
		want         time.Duration
	}{
		{"within bounds", "public, max-age=1800", 30 * time.Minute},
		{"below floor is raised", "max-age=10", 5 * time.Minute},
		{"zero is raised to floor", "max-age=0", 5 * time.Minute},
		{"above ceiling is lowered", "max-age=999999999", 24 * time.Hour},
		{"absent uses default", "", time.Hour},
		{"unparseable uses default", "max-age=soon", time.Hour},
		{"negative uses default", "max-age=-5", time.Hour},
		{"s-maxage wins for a shared cache", "max-age=600, s-maxage=7200", 2 * time.Hour},
		{"case insensitive", "Max-Age=900", 15 * time.Minute},
		{"quoted value", `max-age="1200"`, 20 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
				if tc.cacheControl != "" {
					w.Header().Set("Cache-Control", tc.cacheControl)
				}
				writeDoc(w, self, nil)
			})
			id := env.url("/client.json")
			_, err := env.fetcher.Resolve(context.Background(), id)
			require.NoError(t, err)
			assert.Equal(t, tc.want, env.docTTL(id))
		})
	}
}

func TestCache_HitAvoidsRefetchAndExpiryRefetches(t *testing.T) {
	env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
		w.Header().Set("Cache-Control", "max-age=600")
		writeDoc(w, self, nil)
	})
	id := env.url("/client.json")
	for i := 0; i < 3; i++ {
		_, err := env.fetcher.Resolve(context.Background(), id)
		require.NoError(t, err)
	}
	assert.EqualValues(t, 1, env.hits.Load())

	env.mr.FastForward(601 * time.Second)
	_, err := env.fetcher.Resolve(context.Background(), id)
	require.NoError(t, err)
	assert.EqualValues(t, 2, env.hits.Load())
}

func TestCache_NoStoreIsNotCached(t *testing.T) {
	for _, cc := range []string{"no-store", "No-Store, max-age=600", "no-cache", "private, max-age=600"} {
		t.Run(cc, func(t *testing.T) {
			env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
				w.Header().Set("Cache-Control", cc)
				writeDoc(w, self, nil)
			})
			id := env.url("/client.json")
			for i := 0; i < 2; i++ {
				_, err := env.fetcher.Resolve(context.Background(), id)
				require.NoError(t, err)
			}
			assert.False(t, env.hasDoc(id))
			assert.EqualValues(t, 2, env.hits.Load())
		})
	}
}

func TestCache_InvalidDocumentsAreNotCached(t *testing.T) {
	// draft-ietf-oauth-client-id-metadata-document 4.4: the AS MUST NOT cache
	// invalid or malformed documents.
	env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
		writeDoc(w, self, func(m map[string]any) { delete(m, "client_name") })
	})
	id := env.url("/client.json")

	_, err1 := env.fetcher.Resolve(context.Background(), id)
	assert.Equal(t, KindInvalidDocument, kindOf(t, err1))
	_, err2 := env.fetcher.Resolve(context.Background(), id)
	assert.Equal(t, KindInvalidDocument, kindOf(t, err2))
	assert.EqualValues(t, 2, env.hits.Load(), "a failure must not be served from cache")
	assert.False(t, env.hasDoc(id))
	for _, k := range env.mr.Keys() {
		assert.NotContains(t, k, "oauth:cimd:doc:", "nothing about the failing document may be cached")
	}
}

func TestCache_FetchErrorsAreNotCachedAndRecoverImmediately(t *testing.T) {
	// draft-ietf-oauth-client-id-metadata-document 4.4: the AS MUST NOT cache
	// error responses. A fixed document is picked up on the next request.
	var healthy atomic.Bool
	env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeDoc(w, self, nil)
	})
	id := env.url("/client.json")

	_, err := env.fetcher.Resolve(context.Background(), id)
	assert.Equal(t, KindFetch, kindOf(t, err))
	healthy.Store(true)
	_, err = env.fetcher.Resolve(context.Background(), id)
	require.NoError(t, err)
	assert.EqualValues(t, 2, env.hits.Load())
}

func TestCache_KeyedPerExactURL(t *testing.T) {
	env := newTestEnv(t, okDoc)
	_, err := env.fetcher.Resolve(context.Background(), env.url("/a.json"))
	require.NoError(t, err)
	_, err = env.fetcher.Resolve(context.Background(), env.url("/b.json"))
	require.NoError(t, err)
	assert.EqualValues(t, 2, env.hits.Load())
}

// A poisoned or stale cache entry for one URL must not satisfy another.
func TestCache_EntryForDifferentClientIDIsNotReturned(t *testing.T) {
	env := newTestEnv(t, okDoc)
	a, b := env.url("/a.json"), env.url("/b.json")
	_, err := env.fetcher.Resolve(context.Background(), a)
	require.NoError(t, err)
	doc, err := env.fetcher.Resolve(context.Background(), b)
	require.NoError(t, err)
	assert.Equal(t, b, doc.ClientID)
}

func TestSingleFlight_ConcurrentRequestsShareOneFetch(t *testing.T) {
	env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
		time.Sleep(300 * time.Millisecond)
		writeDoc(w, self, nil)
	})
	id := env.url("/client.json")

	const n = 25
	var wg sync.WaitGroup
	errs := make([]error, n)
	docs := make([]*Document, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			docs[i], errs[i] = env.fetcher.Resolve(context.Background(), id)
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < n; i++ {
		require.NoError(t, errs[i])
		assert.Equal(t, id, docs[i].ClientID)
	}
	assert.EqualValues(t, 1, env.hits.Load())
}

func TestSingleFlight_CancelledCallerDoesNotFailOthers(t *testing.T) {
	env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
		time.Sleep(300 * time.Millisecond)
		writeDoc(w, self, nil)
	})
	id := env.url("/client.json")

	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := env.fetcher.Resolve(ctx, id); first <- err }()
	time.Sleep(50 * time.Millisecond)
	second := make(chan error, 1)
	go func() { _, err := env.fetcher.Resolve(context.Background(), id); second <- err }()
	time.Sleep(50 * time.Millisecond)
	cancel()

	assert.Error(t, <-first)
	assert.NoError(t, <-second)
	assert.EqualValues(t, 1, env.hits.Load())
}

// ===== abuse limits =====

func TestLimits_GlobalRateShedsLoadWithoutCaching(t *testing.T) {
	env := newTestEnv(t, okDoc)
	env.fetcher.limiter = rate.NewLimiter(0, 0)

	id := env.url("/client.json")
	_, err := env.fetcher.Resolve(context.Background(), id)
	assert.Equal(t, KindBusy, kindOf(t, err))
	assert.Zero(t, env.hits.Load())
	for _, k := range env.mr.Keys() {
		assert.NotContains(t, k, "oauth:cimd:doc:", "load shedding must not cache anything")
	}

	env.fetcher.limiter = rate.NewLimiter(rate.Inf, 1)
	_, err = env.fetcher.Resolve(context.Background(), id)
	require.NoError(t, err)
}

func TestLimits_PerHostCapBoundsFetchesAcrossURLs(t *testing.T) {
	env := newTestEnv(t, okDoc)
	env.fetcher.limiter = rate.NewLimiter(rate.Inf, 1)

	var busy int
	for i := 0; i < perHostFetchesPerMin+5; i++ {
		_, err := env.fetcher.Resolve(context.Background(), env.url(fmt.Sprintf("/c%d.json", i)))
		if err != nil && kindOf(t, err) == KindBusy {
			busy++
		}
	}
	assert.Equal(t, 5, busy)
	assert.EqualValues(t, perHostFetchesPerMin, env.hits.Load())

	// Cached documents are served even when the host is over its fetch budget.
	_, err := env.fetcher.Resolve(context.Background(), env.url("/c0.json"))
	require.NoError(t, err)

	// The window resets.
	env.mr.FastForward(61 * time.Second)
	_, err = env.fetcher.Resolve(context.Background(), env.url("/fresh.json"))
	require.NoError(t, err)
}

func TestLimits_ConcurrencyCapQueuesFetches(t *testing.T) {
	var inflight, peak atomic.Int64
	env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
		n := inflight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		inflight.Add(-1)
		writeDoc(w, self, nil)
	})
	env.fetcher.limiter = rate.NewLimiter(rate.Inf, 1)
	env.fetcher.sem = make(chan struct{}, 2)

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := env.fetcher.Resolve(context.Background(), env.url(fmt.Sprintf("/c%d.json", i)))
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()
	assert.LessOrEqual(t, peak.Load(), int64(2))
}

func TestCacheTTLParsing(t *testing.T) {
	assert.Equal(t, time.Hour, cacheTTL(""))
	assert.Equal(t, time.Duration(0), cacheTTL("no-store"))
	assert.Equal(t, 10*time.Minute, cacheTTL("max-age=600"))
}
