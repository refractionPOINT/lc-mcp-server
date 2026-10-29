package endpoints

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/firebase"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testIssuer = "https://test.example.com"

// ===== buildAuthorizationResponseURL / AuthorizationSuccessURL =====

func TestAuthorizationSuccessURL(t *testing.T) {
	tests := []struct {
		name        string
		redirectURI string
		state       string
		wantScheme  string
		wantHost    string
		wantPath    string
		wantQuery   map[string]string
	}{
		{
			name:        "plain https redirect",
			redirectURI: "https://app.example.com/callback",
			state:       "st-1",
			wantScheme:  "https", wantHost: "app.example.com", wantPath: "/callback",
			wantQuery: map[string]string{"code": "the-code", "state": "st-1", "iss": testIssuer},
		},
		{
			name:        "existing query is preserved",
			redirectURI: "http://localhost:1234/cb?x=1&y=two",
			state:       "st-2",
			wantScheme:  "http", wantHost: "localhost:1234", wantPath: "/cb",
			wantQuery: map[string]string{"x": "1", "y": "two", "code": "the-code", "state": "st-2", "iss": testIssuer},
		},
		{
			name:        "state needing escaping round-trips",
			redirectURI: "https://app.example.com/callback",
			state:       "a b&c=d/+",
			wantScheme:  "https", wantHost: "app.example.com", wantPath: "/callback",
			wantQuery: map[string]string{"code": "the-code", "state": "a b&c=d/+", "iss": testIssuer},
		},
		{
			name:        "empty state is omitted",
			redirectURI: "https://app.example.com/callback",
			state:       "",
			wantScheme:  "https", wantHost: "app.example.com", wantPath: "/callback",
			wantQuery: map[string]string{"code": "the-code", "iss": testIssuer},
		},
		{
			name:        "loopback with port",
			redirectURI: "http://127.0.0.1:54321/callback",
			state:       "st-3",
			wantScheme:  "http", wantHost: "127.0.0.1:54321", wantPath: "/callback",
			wantQuery: map[string]string{"code": "the-code", "state": "st-3", "iss": testIssuer},
		},
		{
			name:        "custom scheme",
			redirectURI: "cursor://anysphere.cursor-retrieval/oauth/user-mcp/callback",
			state:       "st-4",
			wantScheme:  "cursor", wantHost: "anysphere.cursor-retrieval", wantPath: "/oauth/user-mcp/callback",
			wantQuery: map[string]string{"code": "the-code", "state": "st-4", "iss": testIssuer},
		},
		{
			name:        "registered uri cannot shadow protocol params",
			redirectURI: "https://app.example.com/callback?code=evil&iss=https://evil.example.com&state=evil",
			state:       "st-5",
			wantScheme:  "https", wantHost: "app.example.com", wantPath: "/callback",
			wantQuery: map[string]string{"code": "the-code", "state": "st-5", "iss": testIssuer},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AuthorizationSuccessURL(testIssuer, tt.redirectURI, tt.state, "the-code")
			require.NoError(t, err)

			u, err := url.Parse(got)
			require.NoError(t, err)
			assert.Equal(t, tt.wantScheme, u.Scheme)
			assert.Equal(t, tt.wantHost, u.Host)
			assert.Equal(t, tt.wantPath, u.Path)

			q := u.Query()
			assert.Len(t, q, len(tt.wantQuery), "unexpected query parameters: %s", u.RawQuery)
			for k, v := range tt.wantQuery {
				assert.Equal(t, []string{v}, q[k], "param %q", k)
			}
			// Exactly one '?': the old concatenation produced "?x=1?code=..."
			assert.Equal(t, 1, strings.Count(got, "?"))
		})
	}
}

func TestBuildAuthorizationResponseURL_InvalidRedirectURI(t *testing.T) {
	for _, bad := range []string{"", "no-scheme/callback", "http://[::1/callback", "%zz"} {
		_, err := buildAuthorizationResponseURL(bad, url.Values{"code": {"c"}})
		assert.Error(t, err, "redirect URI %q must be rejected", bad)
	}
}

// ===== WriteOAuthErrorRedirect =====

func TestWriteOAuthErrorRedirect_IncludesIss(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback", nil)
	w := httptest.NewRecorder()

	WriteOAuthErrorRedirect(w, req, testIssuer, "http://localhost:1234/cb?x=1", "a b&c", ErrServerError, "Authentication failed")

	require.Equal(t, http.StatusFound, w.Code)
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "localhost:1234", loc.Host)
	q := loc.Query()
	assert.Equal(t, "server_error", q.Get("error"))
	assert.Equal(t, "Authentication failed", q.Get("error_description"))
	assert.Equal(t, "a b&c", q.Get("state"))
	assert.Equal(t, "1", q.Get("x"))
	assert.Equal(t, testIssuer, q.Get("iss"))
}

func TestWriteOAuthErrorRedirect_FailsClosedOnBadRedirectURI(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback", nil)
	w := httptest.NewRecorder()

	WriteOAuthErrorRedirect(w, req, testIssuer, "http://[::1/callback", "s", ErrServerError, "x")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, w.Header().Get("Location"))
}

// ===== Handler paths =====

// storeCallbackFixtures prepares OAuth state and the Firebase state mappings the
// callback handler consumes, returning the firebase state to put in the callback URL.
func storeCallbackFixtures(t *testing.T, sm *state.Manager, oauthStateParam, redirectURI string) string {
	t.Helper()
	ctx := context.Background()
	oauthState := state.NewOAuthState(oauthStateParam, "challenge", "S256", redirectURI, "test-client", "openid", "", "google.com")
	require.NoError(t, sm.StoreOAuthState(ctx, oauthState))

	fbState := "fb-" + oauthStateParam
	sessionID := "session-" + oauthStateParam
	sm.StoreSelectionSession(ctx, "oauth:session:"+oauthStateParam, map[string]string{"firebase_state": fbState})
	sm.StoreSelectionSession(ctx, "oauth:state:"+fbState, map[string]string{"oauth_state": oauthStateParam})
	sm.StoreSelectionSession(ctx, "oauth:fbsession:"+fbState, map[string]string{"session_id": sessionID})
	return fbState
}

func metadataIssuer(t *testing.T, h *Handlers) string {
	t.Helper()
	w := httptest.NewRecorder()
	h.HandleAuthorizationServerMetadata(w, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	require.Equal(t, http.StatusOK, w.Code)
	var md map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&md))
	issuer, ok := md["issuer"].(string)
	require.True(t, ok)
	return issuer
}

func TestHandleCallback_SuccessRedirectCarriesIss(t *testing.T) {
	// Custom schemes and state needing escaping must round-trip as well.
	cases := []struct{ name, redirectURI, state string }{
		{"https", "https://app.example.com/callback", "client-state-123"},
		{"loopback with query and escaped state", "http://localhost:3000/callback?x=1", "a b&c=d/+"},
		{"custom scheme", "cursor://anysphere.cursor-retrieval/oauth/user-mcp/callback", "st"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handlers, sm, mockFB, _ := testHandlers(t)
			fbState := storeCallbackFixtures(t, sm, tc.state, tc.redirectURI)
			mockFB.signInWithIdpFunc = func(ctx context.Context, requestURI, postBody, sid, providerId string) (*firebase.SignInWithIdpResponse, error) {
				return &firebase.SignInWithIdpResponse{LocalID: "uid-1", IDToken: "id", RefreshToken: "rt", ExpiresIn: "3600"}, nil
			}

			req := httptest.NewRequest(http.MethodGet, "/oauth/callback?state="+url.QueryEscape(fbState)+"&code=test", nil)
			w := httptest.NewRecorder()
			handlers.HandleCallback(w, req)

			require.Equal(t, http.StatusFound, w.Code)
			loc, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err)
			want, _ := url.Parse(tc.redirectURI)
			assert.Equal(t, want.Scheme, loc.Scheme)
			assert.Equal(t, want.Host, loc.Host)
			assert.Equal(t, want.Path, loc.Path)
			q := loc.Query()
			assert.NotEmpty(t, q.Get("code"))
			assert.Equal(t, tc.state, q.Get("state"))
			assert.Equal(t, metadataIssuer(t, handlers), q.Get("iss"), "iss must equal metadata issuer")
			assert.Equal(t, testIssuer, q.Get("iss"))
			if want.RawQuery != "" {
				assert.Equal(t, want.Query().Get("x"), q.Get("x"))
			}
		})
	}
}

func TestHandleCallback_ErrorRedirectCarriesIss(t *testing.T) {
	handlers, sm, mockFB, _ := testHandlers(t)
	fbState := storeCallbackFixtures(t, sm, "oauth-err", "https://app.example.com/callback")
	mockFB.signInWithIdpFunc = func(ctx context.Context, requestURI, postBody, sid, providerId string) (*firebase.SignInWithIdpResponse, error) {
		return nil, assert.AnError
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?state="+fbState+"&code=test", nil)
	w := httptest.NewRecorder()
	handlers.HandleCallback(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	q := loc.Query()
	assert.Equal(t, "server_error", q.Get("error"))
	assert.Equal(t, "oauth-err", q.Get("state"))
	assert.Equal(t, metadataIssuer(t, handlers), q.Get("iss"), "error responses must carry iss too")
	assert.Empty(t, q.Get("code"))
}

func TestHandleMFAVerify_RedirectURLCarriesIss(t *testing.T) {
	handlers, sm, mockFB, _ := testHandlers(t)
	ctx := context.Background()

	oauthState := state.NewOAuthState("mfa st/+", generatePKCEChallenge("v-123456789012345678901234567890123"), "S256",
		"http://localhost:3000/callback?x=1", "test-client", "openid", "", "google.com")
	require.NoError(t, sm.StoreOAuthState(ctx, oauthState))

	mfaSession := state.NewMFASession("pending", "enroll", "mfa st/+", "Test User", "test-uid-123", "user@example.com", nil)
	sessionID, _ := sm.GenerateMFASessionID()
	require.NoError(t, sm.StoreMFASession(ctx, sessionID, mfaSession))

	mockFB.finalizeMFASignInFunc = func(ctx context.Context, pending, enrollment, code string) (*firebase.FinalizeMFAResponse, error) {
		return &firebase.FinalizeMFAResponse{LocalID: "test-uid-123", IDToken: "mfa-id-token", RefreshToken: "rt", ExpiresIn: "3600"}, nil
	}

	w := httptest.NewRecorder()
	handlers.HandleMFAVerify(w, httptest.NewRequest(http.MethodPost, "/oauth/mfa-verify", nil), sessionID, "123456")
	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.Equal(t, true, resp["success"])
	loc, err := url.Parse(resp["redirect_url"].(string))
	require.NoError(t, err)
	assert.Equal(t, "localhost:3000", loc.Host)
	q := loc.Query()
	assert.NotEmpty(t, q.Get("code"))
	assert.Equal(t, "mfa st/+", q.Get("state"))
	assert.Equal(t, "1", q.Get("x"))
	assert.Equal(t, metadataIssuer(t, handlers), q.Get("iss"))
}
