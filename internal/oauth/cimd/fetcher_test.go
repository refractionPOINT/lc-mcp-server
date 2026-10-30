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

// setLimiters sets both process rate limiters (unknown and known URLs) to l's
// rate and burst.
func (e *testEnv) setLimiters(l *rate.Limiter) {
	e.fetcher.limiter = l
	e.fetcher.knownLimiter = rate.NewLimiter(l.Limit(), l.Burst())
}

func (e *testEnv) hasDoc(id string) bool { return e.mr.Exists(DocPrefix + cacheKey(id)) }

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
	env.setLimiters(rate.NewLimiter(0, 0))

	id := env.url("/client.json")
	_, err := env.fetcher.Resolve(context.Background(), id)
	assert.Equal(t, KindBusy, kindOf(t, err))
	assert.Zero(t, env.hits.Load())
	for _, k := range env.mr.Keys() {
		assert.NotContains(t, k, "oauth:cimd:doc:", "load shedding must not cache anything")
	}

	env.setLimiters(rate.NewLimiter(rate.Inf, 1))
	_, err = env.fetcher.Resolve(context.Background(), id)
	require.NoError(t, err)
}

func TestLimits_PerHostCapBoundsFetchesAcrossURLs(t *testing.T) {
	env := newTestEnv(t, okDoc)
	env.setLimiters(rate.NewLimiter(rate.Inf, 1))

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
	env.setLimiters(rate.NewLimiter(rate.Inf, 1))
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

// ===== load shedding fails closed =====

func (e *testEnv) hasKnown(id string) bool { return e.mr.Exists(KnownPrefix + cacheKey(id)) }

// resolveThenExpire resolves id (a 5 minute document) and lets the cached copy
// expire.
func resolveThenExpire(t *testing.T, env *testEnv, id string) {
	t.Helper()
	_, err := env.fetcher.Resolve(context.Background(), id)
	require.NoError(t, err)
	require.True(t, env.hasKnown(id))
	env.mr.FastForward(minCacheTTL + time.Second)
	require.False(t, env.hasDoc(id))
}

// requireNoDocumentCopies fails if anything in Redis under the CIMD prefixes could hold a
// document other than the Cache-Control bounded cache.
func requireNoDocumentCopies(t *testing.T, env *testEnv) {
	t.Helper()
	for _, k := range env.mr.Keys() {
		if !strings.HasPrefix(k, "oauth:cimd:") {
			continue
		}
		v, _ := env.mr.Get(k)
		assert.NotContains(t, v, "client_name", "key %s holds a document copy", k)
	}
}

func TestShed_BudgetBurntByJunkPathsDoesNotLockOutKnownClient(t *testing.T) {
	// Resolve the real document, expire it, make perHostFetchesPerMin junk
	// lookups on the same host, resolve the real one again.
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request, self string) {
		if strings.HasPrefix(r.URL.Path, "/junk") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "max-age=300")
		writeDoc(w, self, nil)
	})
	env.setLimiters(rate.NewLimiter(rate.Inf, 1))
	id := env.url("/client.json")
	resolveThenExpire(t, env, id)

	for i := 0; i < perHostFetchesPerMin+5; i++ {
		_, _ = env.fetcher.Resolve(context.Background(), env.url(fmt.Sprintf("/junk%d", i)))
	}
	// The host budget is spent: a different new URL on the host is shed...
	_, err := env.fetcher.Resolve(context.Background(), env.url("/another-new.json"))
	assert.Equal(t, KindBusy, kindOf(t, err))

	// ...but the known client still resolves (refreshing from the network:
	// known URLs are budgeted per URL, not against the host).
	before := env.hits.Load()
	doc, err := env.fetcher.Resolve(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, id, doc.ClientID)
	assert.EqualValues(t, before+1, env.hits.Load())
}

func TestShed_FailsClosedOnceTheCacheHasExpired(t *testing.T) {
	var changed atomic.Bool
	env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
		w.Header().Set("Cache-Control", "max-age=300")
		writeDoc(w, self, func(m map[string]any) {
			if changed.Load() {
				m["client_name"] = "Changed"
			}
		})
	})
	id := env.url("/client.json")
	resolveThenExpire(t, env, id)
	changed.Store(true)
	hits := env.hits.Load()

	t.Run("global rate limit", func(t *testing.T) {
		env.setLimiters(rate.NewLimiter(0, 0))
		_, err := env.fetcher.Resolve(context.Background(), id)
		assert.Equal(t, KindBusy, kindOf(t, err))
		assert.Equal(t, hits, env.hits.Load(), "no fetch")
		assert.False(t, env.hasDoc(id))
	})

	t.Run("per-URL budget", func(t *testing.T) {
		env.setLimiters(rate.NewLimiter(rate.Inf, 1))
		// The previous subtest's lookup spent a unit of this URL's budget
		// before the limiter shed it (the counter runs first).
		env.mr.Del(URLPrefix + cacheKey(id))
		var shed, fetched int
		for i := 0; i < perURLFetchesPerMin+3; i++ {
			before := env.hits.Load()
			doc, err := env.fetcher.Resolve(context.Background(), id)
			if env.hits.Load() == before && !env.hasDoc(id) {
				shed++
				assert.Equal(t, KindBusy, kindOf(t, err))
			} else {
				fetched++
				require.NoError(t, err)
				assert.Equal(t, "Changed", doc.ClientName)
			}
			env.mr.Del(DocPrefix + cacheKey(id)) // keep forcing refreshes (FastForward would also reset the counter)
		}
		assert.Equal(t, perURLFetchesPerMin, fetched)
		assert.Equal(t, 3, shed)
	})
	requireNoDocumentCopies(t, env)
}

func TestShed_NotServedForUnknownURLs(t *testing.T) {
	env := newTestEnv(t, okDoc)
	env.setLimiters(rate.NewLimiter(0, 0))
	_, err := env.fetcher.Resolve(context.Background(), env.url("/never-seen.json"))
	assert.Equal(t, KindBusy, kindOf(t, err))
}

func TestShed_DeletedDocumentIsNotResurrected(t *testing.T) {
	// Review repro: the client withdraws its document (410), lookups see that,
	// then a throttled lookup must not bring the old document back.
	var gone atomic.Bool
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request, self string) {
		if gone.Load() {
			w.WriteHeader(http.StatusGone)
			return
		}
		w.Header().Set("Cache-Control", "max-age=300")
		writeDoc(w, self, nil)
	})
	env.setLimiters(rate.NewLimiter(rate.Inf, 1))
	id := env.url("/client.json")
	resolveThenExpire(t, env, id)
	gone.Store(true)

	for i := 0; i < 6; i++ {
		_, err := env.fetcher.Resolve(context.Background(), id)
		assert.Equal(t, KindFetch, kindOf(t, err))
	}
	assert.False(t, env.hasDoc(id))
	assert.False(t, env.hasKnown(id), "a withdrawn document is no longer known")

	env.setLimiters(rate.NewLimiter(0, 0))
	_, err := env.fetcher.Resolve(context.Background(), id)
	assert.Equal(t, KindBusy, kindOf(t, err), "throttled lookup fails closed")
	requireNoDocumentCopies(t, env)
}

func TestShed_RemovedRedirectURIIsNotReauthorized(t *testing.T) {
	// Review repro: six valid no-store replacements drop an old redirect URI,
	// then a throttled lookup must not make the old one authorized again.
	const oldURI = "https://old.example.com/callback"
	var replaced atomic.Bool
	env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
		if replaced.Load() {
			w.Header().Set("Cache-Control", "no-store")
			writeDoc(w, self, nil)
			return
		}
		w.Header().Set("Cache-Control", "max-age=300")
		writeDoc(w, self, func(m map[string]any) {
			m["redirect_uris"] = []string{"https://app.example.com/callback", oldURI}
		})
	})
	env.setLimiters(rate.NewLimiter(rate.Inf, 1))
	id := env.url("/client.json")
	resolveThenExpire(t, env, id)
	replaced.Store(true)

	for i := 0; i < 6; i++ {
		doc, err := env.fetcher.Resolve(context.Background(), id)
		require.NoError(t, err)
		assert.NotContains(t, doc.RedirectURIs, oldURI)
	}

	env.setLimiters(rate.NewLimiter(0, 0))
	doc, err := env.fetcher.Resolve(context.Background(), id)
	if err == nil {
		assert.NotContains(t, doc.RedirectURIs, oldURI, "the old redirect must never be authorized again")
	}
	assert.Equal(t, KindBusy, kindOf(t, err))
	requireNoDocumentCopies(t, env)
}

// hidingStore hides the first n reads of cached documents from the fetcher
// while leaving them in Redis, modelling another replica writing the entry
// between this replica's cache check and its fetch.
type hidingStore struct {
	Store
	n atomic.Int64
}

func (h *hidingStore) GetEphemeral(ctx context.Context, key string) (string, error) {
	if strings.HasPrefix(key, DocPrefix) && h.n.Add(-1) >= 0 {
		return "", nil
	}
	return h.Store.GetEphemeral(ctx, key)
}

func TestCache_EntryIsInvalidatedByDefinitiveAnswers(t *testing.T) {
	cases := map[string]struct {
		serve       func(w http.ResponseWriter, r *http.Request, self string)
		wantInvalid bool
		// keepKnown: a valid answer that just isn't cacheable replaces the
		// cached document but keeps the known marker (it authorizes nothing and
		// only selects the fetch budget).
		keepKnown bool
	}{
		"http 404": {func(w http.ResponseWriter, r *http.Request, _ string) { http.NotFound(w, r) }, true, false},
		"http 410": {func(w http.ResponseWriter, _ *http.Request, _ string) { w.WriteHeader(http.StatusGone) }, true, false},
		"invalid document": {func(w http.ResponseWriter, _ *http.Request, self string) {
			writeDoc(w, self, func(m map[string]any) { delete(m, "client_name") })
		}, true, false},
		"now a confidential client": {func(w http.ResponseWriter, _ *http.Request, self string) {
			writeDoc(w, self, func(m map[string]any) { m["token_endpoint_auth_method"] = "client_secret_basic" })
		}, true, false},
		"no-store replacement": {func(w http.ResponseWriter, _ *http.Request, self string) {
			w.Header().Set("Cache-Control", "no-store")
			writeDoc(w, self, func(m map[string]any) { m["client_name"] = "Replaced" })
		}, true, true},
		"no-cache replacement": {func(w http.ResponseWriter, _ *http.Request, self string) {
			w.Header().Set("Cache-Control", "no-cache")
			writeDoc(w, self, nil)
		}, true, true},
		// A transient failure says nothing about the document.
		"http 500": {func(w http.ResponseWriter, _ *http.Request, _ string) { w.WriteHeader(500) }, false, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var healthy atomic.Bool
			healthy.Store(true)
			env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request, self string) {
				if healthy.Load() {
					w.Header().Set("Cache-Control", "max-age=300")
					writeDoc(w, self, nil)
					return
				}
				tc.serve(w, r, self)
			})
			env.setLimiters(rate.NewLimiter(rate.Inf, 1))
			id := env.url("/client.json")
			_, err := env.fetcher.Resolve(context.Background(), id)
			require.NoError(t, err)
			require.True(t, env.hasDoc(id))
			healthy.Store(false)

			// Force a fetch although the entry is live (Resolve and
			// fetchAndCache each read the cache once).
			hs := &hidingStore{Store: env.fetcher.store}
			hs.n.Store(2)
			env.fetcher.store = hs
			_, _ = env.fetcher.Resolve(context.Background(), id)
			require.EqualValues(t, 2, env.hits.Load(), "the refresh must have reached the network")

			assert.Equal(t, !tc.wantInvalid, env.hasDoc(id))
			assert.Equal(t, !tc.wantInvalid || tc.keepKnown, env.hasKnown(id))
		})
	}
}

func TestShed_NeverServedWhenTheFetchHappenedAndFailed(t *testing.T) {
	// The draft: the AS MUST NOT cache error responses or invalid documents.
	// A fetch that fails, or returns something invalid, must surface as that
	// error even though the document validated before.
	cases := map[string]struct {
		serve    func(w http.ResponseWriter, r *http.Request, self string)
		wantKind ErrorKind
	}{
		"http 500": {func(w http.ResponseWriter, _ *http.Request, _ string) { w.WriteHeader(500) }, KindFetch},
		"http 404": {func(w http.ResponseWriter, r *http.Request, _ string) { http.NotFound(w, r) }, KindFetch},
		"invalid document": {func(w http.ResponseWriter, _ *http.Request, self string) {
			writeDoc(w, self, func(m map[string]any) { delete(m, "client_name") })
		}, KindInvalidDocument},
		"redirect uris now invalid": {func(w http.ResponseWriter, _ *http.Request, self string) {
			writeDoc(w, self, func(m map[string]any) { m["redirect_uris"] = []string{"http://evil.example.com/cb"} })
		}, KindInvalidDocument},
		"now a confidential client": {func(w http.ResponseWriter, _ *http.Request, self string) {
			writeDoc(w, self, func(m map[string]any) { m["token_endpoint_auth_method"] = "client_secret_basic" })
		}, KindUnsupported},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var healthy atomic.Bool
			healthy.Store(true)
			env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request, self string) {
				if healthy.Load() {
					w.Header().Set("Cache-Control", "max-age=300")
					writeDoc(w, self, nil)
					return
				}
				tc.serve(w, r, self)
			})
			env.setLimiters(rate.NewLimiter(rate.Inf, 1))
			id := env.url("/client.json")
			resolveThenExpire(t, env, id)
			healthy.Store(false)

			_, err := env.fetcher.Resolve(context.Background(), id)
			assert.Equal(t, tc.wantKind, kindOf(t, err))
			assert.False(t, env.hasDoc(id), "errors are not cached")

			// Even a shed fetch cannot bring the old document back.
			env.setLimiters(rate.NewLimiter(0, 0))
			_, err = env.fetcher.Resolve(context.Background(), id)
			assert.Equal(t, KindBusy, kindOf(t, err))
			requireNoDocumentCopies(t, env)
		})
	}
}

func TestShed_KnownMarkerIsRefreshedByEachSuccessfulFetch(t *testing.T) {
	env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
		w.Header().Set("Cache-Control", "max-age=300")
		writeDoc(w, self, nil)
	})
	id := env.url("/client.json")
	_, err := env.fetcher.Resolve(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, knownTTL, env.mr.TTL(KnownPrefix+cacheKey(id)))
	env.mr.FastForward(knownTTL - time.Hour)
	_, err = env.fetcher.Resolve(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, knownTTL, env.mr.TTL(KnownPrefix+cacheKey(id)))

	env.mr.FastForward(knownTTL + time.Second)
	assert.False(t, env.hasKnown(id), "the marker expires")
}

func TestShed_NotMarkedKnownWhenNotCacheable(t *testing.T) {
	env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
		w.Header().Set("Cache-Control", "no-store")
		writeDoc(w, self, nil)
	})
	id := env.url("/client.json")
	_, err := env.fetcher.Resolve(context.Background(), id)
	require.NoError(t, err)
	assert.False(t, env.hasDoc(id))
	assert.False(t, env.hasKnown(id))
}

// ===== bounds on what the cache can hold =====

func TestCacheBounds_OversizedDocumentServedButNotCached(t *testing.T) {
	env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
		writeDoc(w, self, func(m map[string]any) {
			var uris []string
			for i := 0; i < maxRedirectURIs; i++ {
				uris = append(uris, fmt.Sprintf("https://app.example.com/%d/%s", i, strings.Repeat("x", 1000)))
			}
			m["redirect_uris"] = uris
		})
	})
	id := env.url("/big.json")
	for i := 0; i < 2; i++ {
		doc, err := env.fetcher.Resolve(context.Background(), id)
		require.NoError(t, err, "a valid large document still works")
		assert.Len(t, doc.RedirectURIs, maxRedirectURIs)
	}
	assert.EqualValues(t, 2, env.hits.Load())
	assert.False(t, env.hasDoc(id))
	assert.False(t, env.hasKnown(id))
}

// briefOnly asserts a document is cached for at most minCacheTTL and not
// marked known: what happens to a valid document beyond the new-document
// budgets.
func (e *testEnv) briefOnly(t *testing.T, id string) {
	t.Helper()
	assert.False(t, e.hasKnown(id), "beyond the budgets a document is never marked known")
	if e.hasDoc(id) {
		assert.LessOrEqual(t, e.mr.TTL(DocPrefix+cacheKey(id)), minCacheTTL)
	}
}

func TestCacheBounds_PerDomainDailyCapOnNewDocuments(t *testing.T) {
	env := newTestEnv(t, okDoc)
	env.setLimiters(rate.NewLimiter(rate.Inf, 1))
	// Spread the fetches over time so the per-minute host budget is not what limits us.
	var ids []string
	for i := 0; i < newDocsPerDomainPerDay+5; i++ {
		id := env.url(fmt.Sprintf("/c%d.json", i))
		ids = append(ids, id)
		_, err := env.fetcher.Resolve(context.Background(), id)
		require.NoError(t, err, "every document is served")
		env.mr.FastForward(61 * time.Second)
		// FastForward also ages cache entries; the per-day window is 24h, so stay below it.
	}
	known := 0
	for _, id := range ids {
		if env.hasKnown(id) {
			known++
		}
	}
	assert.Equal(t, newDocsPerDomainPerDay, known, "beyond the daily cap documents are only cached briefly")
	for _, id := range ids[newDocsPerDomainPerDay:] {
		env.briefOnly(t, id)
	}

	// A day later the domain can cache new documents again.
	env.mr.FastForward(24 * time.Hour)
	id := env.url("/next-day.json")
	_, err := env.fetcher.Resolve(context.Background(), id)
	require.NoError(t, err)
	assert.True(t, env.hasKnown(id))
}

func TestRegistrableDomain(t *testing.T) {
	for host, want := range map[string]string{
		"a.b.evil.example.com": "example.com",
		"EVIL.example.co.uk.":  "example.co.uk",
		"tenant1.example":      "tenant1.example",
		"x.tenant1.example":    "tenant1.example",
		"localhost":            "localhost",
		"app.github.io":        "app.github.io", // github.io is a public suffix
		"x.app.github.io":      "app.github.io",
		"127.0.0.1":            "127.0.0.1",
		"one.two.three.test":   "three.test",
	} {
		assert.Equal(t, want, registrableDomain(host), host)
	}
}

func TestCacheBounds_SubdomainsShareTheDomainBudget(t *testing.T) {
	env := newTestEnv(t, okDoc)
	ctx := context.Background()
	for i := 0; i < newDocsPerDomainPerDay; i++ {
		require.True(t, env.fetcher.mayCacheNewDoc(ctx, fmt.Sprintf("x%d.evil.example", i)))
	}
	assert.False(t, env.fetcher.mayCacheNewDoc(ctx, "another-sub.evil.example"), "wildcard subdomains don't get fresh budgets")
	assert.True(t, env.fetcher.mayCacheNewDoc(ctx, "client.unrelated.example"), "other domains are unaffected")
}

func TestCacheBounds_SpentBudgetsDontStopANewClient(t *testing.T) {
	// Anyone can spend the new-document budgets (/authorize is
	// unauthenticated). A new client that turns up afterwards must still be
	// served from cache, not refetched on every use until its host's
	// per-minute fetch budget refuses it.
	env := newTestEnv(t, okDoc)
	ctx := context.Background()
	for i := 0; i < newDocsPerHour; i++ {
		env.fetcher.mayCacheNewDoc(ctx, fmt.Sprintf("tenant%d.example", i))
	}
	require.False(t, env.fetcher.mayCacheNewDoc(ctx, "probe.example"), "global budget spent")

	id := env.url("/client.json")
	for i := 0; i < perHostFetchesPerMin*2; i++ {
		_, err := env.fetcher.Resolve(ctx, id)
		require.NoError(t, err, "resolve %d", i)
	}
	assert.EqualValues(t, 1, env.hits.Load(), "served from the brief cache after the first fetch")
	env.briefOnly(t, id)
}

func TestCacheBounds_RefreshOfKnownDocumentIsNotCountedAsNew(t *testing.T) {
	env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
		w.Header().Set("Cache-Control", "max-age=300")
		writeDoc(w, self, nil)
	})
	env.setLimiters(rate.NewLimiter(rate.Inf, 1))
	id := env.url("/client.json")
	// More refreshes than the daily cap, one document.
	for i := 0; i < newDocsPerDomainPerDay*3; i++ {
		_, err := env.fetcher.Resolve(context.Background(), id)
		require.NoError(t, err)
		require.True(t, env.hasDoc(id), "refresh %d must still be cached", i)
		env.mr.FastForward(minCacheTTL + time.Second)
	}
}

func TestCacheBounds_GlobalHourlyCapAcrossDomains(t *testing.T) {
	// Registrable domains cost money but are still plentiful, so the
	// per-domain cap alone does not bound the cache: the cluster-wide counter
	// does. Model many domains by pre-spending budget under distinct ones.
	env := newTestEnv(t, okDoc)
	env.setLimiters(rate.NewLimiter(rate.Inf, 1))
	ctx := context.Background()
	for i := 0; i < newDocsPerHour; i++ {
		require.True(t, env.fetcher.mayCacheNewDoc(ctx, fmt.Sprintf("tenant%d.example", i)))
	}
	assert.False(t, env.fetcher.mayCacheNewDoc(ctx, "one-more.example"))

	id := env.url("/client.json")
	_, err := env.fetcher.Resolve(ctx, id)
	require.NoError(t, err)
	env.briefOnly(t, id)

	env.mr.FastForward(time.Hour + time.Second)
	_, err = env.fetcher.Resolve(ctx, env.url("/client2.json"))
	require.NoError(t, err)
	assert.True(t, env.hasKnown(env.url("/client2.json")))
}

func TestCacheBounds_FailsClosedWhenCountersUnavailable(t *testing.T) {
	env := newTestEnv(t, okDoc)
	env.setLimiters(rate.NewLimiter(rate.Inf, 1))
	env.fetcher.store = failingIncrStore{env.fetcher.store}
	id := env.url("/client.json")
	_, err := env.fetcher.Resolve(context.Background(), id)
	require.NoError(t, err, "the document is still served")
	// When the budget can't be checked the document is only cached briefly.
	env.briefOnly(t, id)
}

type failingIncrStore struct{ Store }

func (failingIncrStore) IncrEphemeral(context.Context, string, time.Duration) (int64, error) {
	return 0, fmt.Errorf("redis down")
}

// ===== unknown client_ids can't starve known clients =====

func TestShed_UnknownLookupsDontStarveKnownClients(t *testing.T) {
	// Review repro: junk client_ids (cheap: /authorize is unauthenticated)
	// empty the process rate limiter; a known client whose cached document
	// expired must still refresh.
	env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
		w.Header().Set("Cache-Control", "max-age=300")
		writeDoc(w, self, nil)
	})
	id := env.url("/client.json")
	resolveThenExpire(t, env, id)
	require.True(t, env.hasKnown(id))

	env.fetcher.limiter = rate.NewLimiter(0, 0) // drained by junk
	_, err := env.fetcher.Resolve(context.Background(), env.url("/junk.json"))
	assert.Equal(t, KindBusy, kindOf(t, err), "unknown URLs are shed")

	doc, err := env.fetcher.Resolve(context.Background(), id)
	require.NoError(t, err, "the known client refreshes from its own pool")
	assert.Equal(t, "Example MCP Client", doc.ClientName)
}

func TestShed_DomainCounterRunsBeforeTheProcessLimiter(t *testing.T) {
	// Junk on one domain is shed by that domain's counter without spending
	// the process-wide tokens other domains need.
	env := newTestEnv(t, okDoc)
	env.fetcher.limiter = rate.NewLimiter(0, perHostFetchesPerMin) // exactly the tokens one domain's budget can spend
	for i := 0; i < perHostFetchesPerMin*3; i++ {
		_, _ = env.fetcher.Resolve(context.Background(), env.url(fmt.Sprintf("/junk-%d.json", i)))
	}
	assert.EqualValues(t, perHostFetchesPerMin, env.hits.Load(), "only the domain budget's worth reached the network")
	// The shed lookups beyond the budget took no tokens: a limiter with one
	// more token than the budget would still have it.
	env2 := newTestEnv(t, okDoc)
	env2.fetcher.limiter = rate.NewLimiter(0, perHostFetchesPerMin+1)
	for i := 0; i < perHostFetchesPerMin*3; i++ {
		_, _ = env2.fetcher.Resolve(context.Background(), env2.url(fmt.Sprintf("/junk-%d.json", i)))
	}
	assert.InDelta(t, 1.0, env2.fetcher.limiter.Tokens(), 0.01)
}

func TestKnownPool_OneDomainHoldsAtMostItsShare(t *testing.T) {
	// Review: a domain that controls several known URLs could make their
	// refreshes hang and hold every slot of the known pool.
	release := make(chan struct{})
	var hang atomic.Bool
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request, self string) {
		if hang.Load() && strings.HasPrefix(r.URL.Path, "/hang") {
			<-release
		}
		w.Header().Set("Cache-Control", "max-age=300")
		writeDoc(w, self, nil)
	})
	t.Cleanup(func() { close(release) })
	var ids []string
	for i := 0; i < maxKnownFetchesPerDomain+1; i++ {
		id := env.url(fmt.Sprintf("/hang-%d.json", i))
		ids = append(ids, id)
		resolveThenExpire(t, env, id)
	}
	hang.Store(true)

	var wg sync.WaitGroup
	for _, id := range ids[:maxKnownFetchesPerDomain] {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, _ = env.fetcher.Resolve(ctx, id)
		}(id)
	}
	require.Eventually(t, func() bool {
		env.fetcher.knownMu.Lock()
		defer env.fetcher.knownMu.Unlock()
		return env.fetcher.knownByDomain[registrableDomain(hostOf(ids[0]))] == maxKnownFetchesPerDomain
	}, 2*time.Second, 10*time.Millisecond)

	tokensBefore := env.fetcher.knownLimiter.Tokens()
	for i := 0; i < 5; i++ {
		_, err := env.fetcher.Resolve(context.Background(), ids[maxKnownFetchesPerDomain])
		assert.Equal(t, KindBusy, kindOf(t, err), "a third hanging refresh from the same domain is shed")
		env.mr.Del(URLPrefix + cacheKey(ids[maxKnownFetchesPerDomain])) // stay under the per-URL budget
	}
	assert.GreaterOrEqual(t, env.fetcher.knownLimiter.Tokens(), tokensBefore, "refreshes shed by the domain cap spend no shared tokens")
	assert.Less(t, len(env.fetcher.knownSem), cap(env.fetcher.knownSem), "the rest of the known pool stays free for other domains")
	wg.Wait()
}

func TestKnownPool_DomainAccounting(t *testing.T) {
	env := newTestEnv(t, okDoc)
	f := env.fetcher
	for i := 0; i < maxKnownFetchesPerDomain; i++ {
		require.True(t, f.acquireKnownDomain("evil.example"))
	}
	assert.False(t, f.acquireKnownDomain("evil.example"))
	assert.True(t, f.acquireKnownDomain("client.example"), "other domains are unaffected")
	f.releaseKnownDomain("evil.example")
	assert.True(t, f.acquireKnownDomain("evil.example"), "a slot frees up on release")
	for i := 0; i < maxKnownFetchesPerDomain; i++ {
		f.releaseKnownDomain("evil.example")
	}
	f.releaseKnownDomain("client.example")
	assert.Empty(t, f.knownByDomain, "no entries leak")
}
