package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/ratelimit"
	"github.com/refractionpoint/lc-mcp-go/internal/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func reqWithXFF(remote string, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name string
		req  *http.Request
		hops int
		want string
	}{
		{"spoofed left-most is ignored, trusted hop used", reqWithXFF("10.0.0.1:1", "1.2.3.4, 203.0.113.9"), 1, "203.0.113.9"},
		{"many spoofed entries", reqWithXFF("10.0.0.1:1", "1.1.1.1, 2.2.2.2, 3.3.3.3, 203.0.113.9"), 1, "203.0.113.9"},
		{"two hops: client is second from the end", reqWithXFF("10.0.0.1:1", "1.2.3.4, 203.0.113.9, 35.1.1.1"), 2, "203.0.113.9"},
		{"entries counted across header lines, last line wins", reqWithXFF("10.0.0.1:1", "1.2.3.4", "203.0.113.9"), 1, "203.0.113.9"},
		{"header absent: RemoteAddr", reqWithXFF("192.0.2.1:12345"), 1, "192.0.2.1"},
		{"header shorter than hops: RemoteAddr", reqWithXFF("192.0.2.1:12345", "203.0.113.9"), 2, "192.0.2.1"},
		{"selected entry is not an IP: RemoteAddr, never the caller string", reqWithXFF("192.0.2.1:12345", "1.2.3.4, not-an-ip"), 1, "192.0.2.1"},
		{"X-Real-IP is caller-controlled and ignored", func() *http.Request {
			r := reqWithXFF("192.0.2.1:12345")
			r.Header.Set("X-Real-IP", "6.6.6.6")
			return r
		}(), 1, "192.0.2.1"},
		{"ipv6 is keyed on its /64", reqWithXFF("10.0.0.1:1", "2001:db8:1:2:aaaa:bbbb:cccc:dddd"), 1, "2001:db8:1:2::/64"},
		{"ipv6 in another /64 of the same host block differs", reqWithXFF("10.0.0.1:1", "2001:db8:1:3::1"), 1, "2001:db8:1:3::/64"},
		{"ip:port entry", reqWithXFF("10.0.0.1:1", "203.0.113.9:4444"), 1, "203.0.113.9"},
		{"unparsable RemoteAddr", reqWithXFF("garbage"), 1, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, clientIP(tc.req, tc.hops))
		})
	}
}

func TestGetClientIPUsesConfiguredHops(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxyHops(DefaultTrustedProxyHops) })
	r := reqWithXFF("10.0.0.1:1", "1.2.3.4, 203.0.113.9, 35.1.1.1")
	assert.Equal(t, "35.1.1.1", getClientIP(r), "default is one trusted hop")
	require.True(t, SetTrustedProxyHops(2))
	assert.Equal(t, "203.0.113.9", getClientIP(r))
	assert.False(t, SetTrustedProxyHops(0))
	assert.False(t, SetTrustedProxyHops(99))
	assert.Equal(t, "203.0.113.9", getClientIP(r), "invalid values leave the setting unchanged")
}

func TestConfigureTrustedProxyHops(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxyHops(DefaultTrustedProxyHops) })
	t.Setenv("TRUSTED_PROXY_HOPS", "2")
	n, err := configureTrustedProxyHops()
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	t.Setenv("TRUSTED_PROXY_HOPS", "zero")
	_, err = configureTrustedProxyHops()
	assert.Error(t, err)
}

// newLimitedServer returns a Server whose rate limiter is backed by miniredis.
func newLimitedServer(t *testing.T) *Server {
	t.Helper()
	s := createTestServer(t)
	mr := miniredis.RunT(t)
	rc, err := redis.New(&redis.Config{URL: "redis://" + mr.Addr()}, s.logger)
	require.NoError(t, err)
	s.rateLimiter = ratelimit.NewLimiter(rc, s.logger)
	return s
}

func setLimit(t *testing.T, endpoint string, max int) {
	t.Helper()
	old := ratelimit.DefaultConfigs[endpoint]
	cfg := old
	cfg.MaxRequests = max
	ratelimit.DefaultConfigs[endpoint] = cfg
	t.Cleanup(func() { ratelimit.DefaultConfigs[endpoint] = old })
}

func hit(h http.Handler, path, remote string, xff ...string) int {
	r := reqWithXFF(remote, xff...)
	r.URL.Path = path
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestRateLimitNotBypassedByRotatingXFF(t *testing.T) {
	setLimit(t, "default", 3)
	s := newLimitedServer(t)
	h := s.rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	// Same real client (the trusted hop's entry), a fresh spoofed left-most
	// entry on every request: must still hit the limit.
	var codes []int
	for i := 0; i < 5; i++ {
		codes = append(codes, hit(h, "/register", "10.0.0.1:1", fmt.Sprintf("9.9.9.%d, 203.0.113.9", i)))
	}
	assert.Equal(t, []int{200, 200, 200, 429, 429}, codes)

	// A different real client (different trusted-hop entry) is unaffected.
	assert.Equal(t, http.StatusOK, hit(h, "/register", "10.0.0.1:1", "9.9.9.0, 203.0.113.77"))
}

func TestRateLimitFallsBackToRemoteAddr(t *testing.T) {
	setLimit(t, "default", 2)
	s := newLimitedServer(t)
	h := s.rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	assert.Equal(t, 200, hit(h, "/register", "192.0.2.1:1000"))
	assert.Equal(t, 200, hit(h, "/register", "192.0.2.1:2000"), "the port is not part of the key")
	assert.Equal(t, 429, hit(h, "/register", "192.0.2.1:3000"))
	assert.Equal(t, 200, hit(h, "/register", "192.0.2.2:1000"))
}

func TestIdentityKey(t *testing.T) {
	assert.Equal(t, "", identityKey(nil))
	assert.Equal(t, "", identityKey(&resolvedAuth{authCtx: &auth.AuthContext{Mode: auth.AuthModeNormal, OID: "o", APIKey: "server-key-00000000"}, serverWide: true}), "server-wide credentials are shared: no identity")
	assert.Equal(t, "uid:u1", identityKey(&resolvedAuth{authCtx: &auth.AuthContext{Mode: auth.AuthModeUIDOAuth, UID: "u1", JWTToken: "j"}}))
	assert.Equal(t, "oid:o1", identityKey(&resolvedAuth{authCtx: &auth.AuthContext{Mode: auth.AuthModeNormal, OID: "o1", JWTToken: "j"}}))

	k1 := identityKey(&resolvedAuth{authCtx: &auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: "victim", APIKey: "attacker-key-0000000"}})
	k2 := identityKey(&resolvedAuth{authCtx: &auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: "someone-else", APIKey: "attacker-key-0000000"}})
	assert.Equal(t, k1, k2, "keyed on the secret, not on the claimed uid")
	assert.NotContains(t, k1, "attacker-key", "the key itself never reaches Redis")
	assert.NotEqual(t, k1, identityKey(&resolvedAuth{authCtx: &auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: "victim", APIKey: "another-key-000000"}}))
}

// An authenticated caller that rotates its source address (here: every request
// comes from a fresh trusted-hop IP) still hits its own limit.
func TestAuthenticatedCallerLimitedAcrossAddresses(t *testing.T) {
	setLimit(t, "mcp_request", 3)
	s := newLimitedServer(t)
	h := s.withMiddleware(s.mux)

	call := func(i int, key string) *httptest.ResponseRecorder {
		body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{}}}`)
		r := httptest.NewRequest(http.MethodPost, "/mcp", bytesReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-LC-OID", "00000000-0000-0000-0000-000000000001")
		r.Header.Set("X-LC-API-KEY", key)
		r.RemoteAddr = "10.0.0.1:1"
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i+1)) // fresh client address each time
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	var codes []int
	for i := 0; i < 5; i++ {
		codes = append(codes, call(i, "key-aaaaaaaaaaaaaaaa").Code)
	}
	assert.NotEqual(t, http.StatusTooManyRequests, codes[0])
	assert.Equal(t, http.StatusTooManyRequests, codes[3])
	assert.Equal(t, http.StatusTooManyRequests, codes[4])

	// A different credential from yet another address is not affected.
	assert.NotEqual(t, http.StatusTooManyRequests, call(10, "key-bbbbbbbbbbbbbbbb").Code)
}

func bytesReader(b []byte) *strings.Reader { return strings.NewReader(string(b)) }

// Callers without a credential run as the server's own identity; they must keep
// their per-address buckets rather than share one.
func TestServerWideCredentialsAreNotAnIdentity(t *testing.T) {
	s := newLimitedServer(t)
	s.serverAuthCtx = &auth.AuthContext{Mode: auth.AuthModeNormal, OID: "00000000-0000-0000-0000-000000000001", APIKey: "server-key-0000000000"}
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	resolved, failure := s.resolveRequestAuth(r, "req")
	require.Nil(t, failure)
	assert.Equal(t, "", identityKey(resolved))
}
