package endpoints

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The test handlers' server URL is https://test.example.com (testIssuer).
const (
	audOrigin  = testIssuer
	audMCP     = testIssuer + "/mcp"
	audProfile = testIssuer + "/mcp/all"
	audVerif   = "test-verifier-123456789012345678901234567890"
)

func audAuthorize(t *testing.T, h *Handlers, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", "test-client")
	params.Set("redirect_uri", "https://app.example.com/callback")
	params.Set("state", "client-state-123")
	params.Set("code_challenge", generatePKCEChallenge(audVerif))
	params.Set("code_challenge_method", "S256")
	params.Set("provider", "google")
	for k, vs := range extra {
		params[k] = vs
	}
	if params.Get("provider") != "" {
		return browserAuthorize(t, h, params)
	}
	return authorizeRequest(h, params)
}

func audPostToken(t *testing.T, h *Handlers, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.HandleToken(w, req)
	return w
}

func audDecode(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&m))
	return m
}

// audStoreCode stores an authorization code bound to resource.
func audStoreCode(t *testing.T, sm *state.Manager, code, resource string) {
	t.Helper()
	challenge := generatePKCEChallenge(audVerif)
	authCode := state.NewAuthorizationCode(code, "client-state", "test-uid", "fb-id-token", "fb-refresh-token",
		time.Now().Unix()+3600, "https://app.example.com/callback", "test-client", "openid profile", &challenge, stringPtr("S256"))
	authCode.Resource = resource
	require.NoError(t, sm.StoreAuthorizationCode(context.Background(), authCode))
}

func audCodeForm(code string, resource ...string) url.Values {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example.com/callback")
	form.Set("client_id", "test-client")
	form.Set("code_verifier", audVerif)
	for _, r := range resource {
		form.Add("resource", r)
	}
	return form
}

// audStoreRefresh stores an access/refresh token pair bound to resource.
func audStoreRefresh(t *testing.T, sm *state.Manager, refresh, resource string) {
	t.Helper()
	ctx := context.Background()
	at := state.NewAccessTokenData("old-at-"+refresh, "test-uid", "fb-id-token", "fb-refresh-token", time.Now().Unix()+3600, "openid", 3600)
	at.Resource = resource
	require.NoError(t, sm.StoreAccessToken(ctx, at))
	rt := state.NewRefreshTokenData(refresh, at.AccessToken, "test-uid", "fb-refresh-token", "openid")
	rt.Resource = resource
	require.NoError(t, sm.StoreRefreshToken(ctx, rt))
}

func audRefreshForm(refresh string, resource ...string) url.Values {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refresh)
	form.Set("client_id", "test-client") // public clients identify themselves on refresh
	for _, r := range resource {
		form.Add("resource", r)
	}
	return form
}

// ===== /authorize =====

func TestAuthorize_InvalidResourceIsInvalidTarget(t *testing.T) {
	for _, resource := range []string{
		"https://evil.example.com/mcp",
		"http://test.example.com/mcp",
		testIssuer + "/mcp#frag",
		testIssuer + "/mcp?x=1",
		testIssuer + "/mcp/no_such_profile",
		testIssuer + "/mcp/%2e%2e/mcp",
		testIssuer + "/other",
		"not-a-uri",
	} {
		t.Run(resource, func(t *testing.T) {
			handlers, sm, _, mr := testHandlers(t)
			w := audAuthorize(t, handlers, url.Values{"resource": {resource}})

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Empty(t, w.Header().Get("Location"), "the error is returned locally, not by redirect")
			assert.Equal(t, ErrInvalidTarget, audDecode(t, w)["error"])
			assert.Empty(t, storedTxs(t, sm, mr), "nothing is stored for a rejected request")
		})
	}
}

func TestAuthorize_MultipleResourcesAreRefused(t *testing.T) {
	handlers, _, _, _ := testHandlers(t)
	w := audAuthorize(t, handlers, url.Values{"resource": {audMCP, audProfile}})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, ErrInvalidTarget, audDecode(t, w)["error"])
}

func TestAuthorize_StoresCanonicalResource(t *testing.T) {
	cases := map[string]string{
		testIssuer + "/mcp":             audMCP,
		"HTTPS://Test.Example.com/mcp/": audMCP,
		testIssuer + "/mcp/v1":          audMCP,
		testIssuer + "/mcp/v1/all":      audProfile,
		testIssuer + "/mcp/all":         audProfile,
		testIssuer:                      audOrigin,
		testIssuer + "/":                audOrigin,
		"":                              audOrigin, // none named: the whole server, as before
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			handlers, sm, _, mr := testHandlers(t)
			extra := url.Values{}
			if in != "" {
				extra.Set("resource", in)
			}
			w := audAuthorize(t, handlers, extra)
			require.Equal(t, http.StatusFound, w.Code)

			_, stored := onlyTx(t, sm, mr)
			assert.Equal(t, want, stored.Resource)
		})
	}
}

func TestAuthorize_ProviderSelectionCarriesCanonicalResource(t *testing.T) {
	handlers, sm, _, mr := testHandlers(t)
	w := audAuthorize(t, handlers, url.Values{"provider": {""}, "resource": {testIssuer + "/mcp/v1/all/"}})
	require.Equal(t, http.StatusFound, w.Code)

	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "/oauth/select-provider", loc.Path)
	session := loc.Query().Get("session")
	params, err := sm.GetSelectionSession(context.Background(), session)
	require.NoError(t, err)
	assert.Equal(t, audProfile, params["resource"])

	// The selection page sends these on to /authorize with the provider.
	picked := completeSelection(t, handlers, session, "google")
	require.Equal(t, http.StatusFound, picked.Code)
	back, err := url.Parse(picked.Header().Get("Location"))
	require.NoError(t, err)
	w2 := authorizeRequest(handlers, back.Query(), picked.Result().Cookies()...)
	require.Equal(t, http.StatusFound, w2.Code)
	_, stored := onlyTx(t, sm, mr)
	assert.Equal(t, audProfile, stored.Resource)
}

func TestAuthorize_InvalidResourceIsRejectedBeforeProviderSelection(t *testing.T) {
	handlers, _, _, _ := testHandlers(t)
	w := audAuthorize(t, handlers, url.Values{"provider": {""}, "resource": {"https://evil.example.com/mcp"}})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, ErrInvalidTarget, audDecode(t, w)["error"])
}

// ===== authorize -> callback -> token -> refresh -> introspect =====

func TestResourceFlow_AuthorizeToTokenToRefresh(t *testing.T) {
	handlers, sm, _, _ := testHandlers(t)
	ctx := context.Background()

	w := audAuthorize(t, handlers, url.Values{"resource": {testIssuer + "/mcp/v1/all"}})
	require.Equal(t, http.StatusFound, w.Code)

	// Provider callback (the mock Firebase client uses state "firebase-state-123"),
	// in the browser that started the flow.
	cookies := w.Result().Cookies()
	w = httptest.NewRecorder()
	handlers.HandleCallback(w, withCookies(httptest.NewRequest(http.MethodGet, "/oauth/callback?state=firebase-state-123&code=x", nil), cookies...))
	require.Equal(t, http.StatusFound, w.Code)
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code)

	// Token request without a resource: the tokens get the authorized one.
	w = audPostToken(t, handlers, audCodeForm(code))
	require.Equal(t, http.StatusOK, w.Code)
	resp := audDecode(t, w)
	at, err := sm.GetAccessTokenData(ctx, resp["access_token"].(string))
	require.NoError(t, err)
	require.NotNil(t, at)
	assert.Equal(t, audProfile, at.Resource)
	rt, err := sm.GetRefreshTokenData(ctx, resp["refresh_token"].(string))
	require.NoError(t, err)
	require.NotNil(t, rt)
	assert.Equal(t, audProfile, rt.Resource)

	// Refresh without a resource keeps it, through rotation.
	w = audPostToken(t, handlers, audRefreshForm(resp["refresh_token"].(string)))
	require.Equal(t, http.StatusOK, w.Code)
	resp2 := audDecode(t, w)
	at2, _ := sm.GetAccessTokenData(ctx, resp2["access_token"].(string))
	rt2, _ := sm.GetRefreshTokenData(ctx, resp2["refresh_token"].(string))
	require.NotNil(t, at2)
	require.NotNil(t, rt2)
	assert.Equal(t, audProfile, at2.Resource)
	assert.Equal(t, audProfile, rt2.Resource)

	// And again, with the same resource spelled as an alias.
	w = audPostToken(t, handlers, audRefreshForm(resp2["refresh_token"].(string), testIssuer+"/mcp/v1/all/"))
	require.Equal(t, http.StatusOK, w.Code)
	resp3 := audDecode(t, w)
	at3, _ := sm.GetAccessTokenData(ctx, resp3["access_token"].(string))
	require.NotNil(t, at3)
	assert.Equal(t, audProfile, at3.Resource)
}

// ===== /token, authorization_code grant =====

func TestTokenCodeGrant_Resource(t *testing.T) {
	tests := []struct {
		name       string
		authorized string
		requested  []string
		want       string // resource of the issued tokens
		wantErr    bool
	}{
		{"none requested keeps the authorized resource", audMCP, nil, audMCP, false},
		{"same resource", audMCP, []string{audMCP}, audMCP, false},
		{"alias of the same resource", audMCP, []string{testIssuer + "/mcp/v1"}, audMCP, false},
		{"narrow mcp to a profile", audMCP, []string{audProfile}, audProfile, false},
		{"narrow the whole server to mcp", audOrigin, []string{audMCP}, audMCP, false},
		{"narrow the whole server to a profile", audOrigin, []string{audProfile}, audProfile, false},
		{"widen a profile to mcp", audProfile, []string{audMCP}, "", true},
		{"widen a profile to the whole server", audProfile, []string{audOrigin}, "", true},
		{"widen mcp to the whole server", audMCP, []string{audOrigin}, "", true},
		{"sideways to another profile", audProfile, []string{testIssuer + "/mcp/api_access"}, "", true},
		{"foreign resource", audOrigin, []string{"https://evil.example.com/mcp"}, "", true},
		{"unknown profile", audOrigin, []string{testIssuer + "/mcp/no_such_profile"}, "", true},
		{"fragment", audOrigin, []string{audMCP + "#x"}, "", true},
		{"multiple resources", audOrigin, []string{audMCP, audProfile}, "", true},
		{"code without a resource is for the whole server", "", []string{audProfile}, audProfile, false},
		{"code without a resource cannot reach another origin", "", []string{"https://evil.example.com/mcp"}, "", true},
		{"code without a resource gets the whole server", "", nil, audOrigin, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handlers, sm, _, _ := testHandlers(t)
			audStoreCode(t, sm, "code-1", tc.authorized)

			w := audPostToken(t, handlers, audCodeForm("code-1", tc.requested...))
			if tc.wantErr {
				assert.Equal(t, http.StatusBadRequest, w.Code)
				assert.Equal(t, ErrInvalidTarget, audDecode(t, w)["error"])
				return
			}
			require.Equal(t, http.StatusOK, w.Code)
			resp := audDecode(t, w)
			at, err := sm.GetAccessTokenData(context.Background(), resp["access_token"].(string))
			require.NoError(t, err)
			require.NotNil(t, at)
			assert.Equal(t, tc.want, at.Resource)
			rt, err := sm.GetRefreshTokenData(context.Background(), resp["refresh_token"].(string))
			require.NoError(t, err)
			require.NotNil(t, rt)
			assert.Equal(t, tc.want, rt.Resource)
		})
	}
}

func TestTokenCodeGrant_RejectedResourceIssuesNoTokens(t *testing.T) {
	handlers, sm, _, mr := testHandlers(t)
	audStoreCode(t, sm, "code-1", audProfile)

	w := audPostToken(t, handlers, audCodeForm("code-1", audOrigin))
	require.Equal(t, http.StatusBadRequest, w.Code)

	// No token was written.
	for _, k := range mr.Keys() {
		assert.False(t, strings.HasPrefix(k, state.TokenPrefix), "unexpected token %s", k)
	}
}

// ===== /token, refresh_token grant =====

func TestTokenRefreshGrant_Resource(t *testing.T) {
	tests := []struct {
		name       string
		authorized string
		requested  []string
		want       string
		wantErr    bool
	}{
		{"none requested keeps the resource", audMCP, nil, audMCP, false},
		{"same resource", audMCP, []string{audMCP}, audMCP, false},
		{"narrow to a profile", audMCP, []string{audProfile}, audProfile, false},
		{"narrow the whole server to mcp", audOrigin, []string{audMCP}, audMCP, false},
		{"widen", audProfile, []string{audMCP}, "", true},
		{"widen to the whole server", audMCP, []string{audOrigin}, "", true},
		{"sideways", audProfile, []string{testIssuer + "/mcp/api_access"}, "", true},
		{"foreign", audMCP, []string{"https://evil.example.com/mcp"}, "", true},
		{"multiple", audMCP, []string{audMCP, audProfile}, "", true},
		{"invalid", audMCP, []string{"nope"}, "", true},
		// A refresh token from before resource binding stays unbound whatever
		// the client names, so nobody who is signed in is locked out.
		{"legacy, none requested", "", nil, "", false},
		{"legacy, valid resource", "", []string{audProfile}, "", false},
		{"legacy, resource of another origin", "", []string{"https://evil.example.com/mcp"}, "", false},
		{"legacy, garbage resource", "", []string{"%%"}, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handlers, sm, _, _ := testHandlers(t)
			audStoreRefresh(t, sm, "rt-1", tc.authorized)

			w := audPostToken(t, handlers, audRefreshForm("rt-1", tc.requested...))
			if tc.wantErr {
				assert.Equal(t, http.StatusBadRequest, w.Code)
				assert.Equal(t, ErrInvalidTarget, audDecode(t, w)["error"])
				// A refused refresh does not burn the refresh token.
				still, err := sm.GetRefreshTokenData(context.Background(), "rt-1")
				require.NoError(t, err)
				assert.NotNil(t, still)
				return
			}
			require.Equal(t, http.StatusOK, w.Code)
			resp := audDecode(t, w)
			at, err := sm.GetAccessTokenData(context.Background(), resp["access_token"].(string))
			require.NoError(t, err)
			require.NotNil(t, at)
			assert.Equal(t, tc.want, at.Resource)
			rt, err := sm.GetRefreshTokenData(context.Background(), resp["refresh_token"].(string))
			require.NoError(t, err)
			require.NotNil(t, rt)
			assert.Equal(t, tc.want, rt.Resource)
		})
	}
}

func TestTokenRefreshGrant_NarrowedResourceSticks(t *testing.T) {
	handlers, sm, _, _ := testHandlers(t)
	audStoreRefresh(t, sm, "rt-1", audMCP)

	w := audPostToken(t, handlers, audRefreshForm("rt-1", audProfile))
	require.Equal(t, http.StatusOK, w.Code)
	next := audDecode(t, w)["refresh_token"].(string)

	// Narrowed once, it cannot be widened back on the next rotation.
	w = audPostToken(t, handlers, audRefreshForm(next, audMCP))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, ErrInvalidTarget, audDecode(t, w)["error"])

	w = audPostToken(t, handlers, audRefreshForm(next))
	require.Equal(t, http.StatusOK, w.Code)
	at, _ := sm.GetAccessTokenData(context.Background(), audDecode(t, w)["access_token"].(string))
	require.NotNil(t, at)
	assert.Equal(t, audProfile, at.Resource)
}

// ===== callback with a stored state =====

func TestCallback_StateResource(t *testing.T) {
	tests := []struct {
		name  string
		state string
		want  string
		fails bool
	}{
		{"canonical", audProfile, audProfile, false},
		{"empty means the whole server", "", audOrigin, false},
		{"state from another server URL fails closed", "https://old.example.com/mcp", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handlers, sm, _, _ := testHandlers(t)
			ctx := context.Background()
			oauthState := state.NewOAuthState("st-1", "challenge", "S256", "https://app.example.com/callback", "test-client", "openid", tc.state, "google.com")
			txID := mustCreateTx(t, sm, oauthState)
			seedMappings(t, sm, "fb-st-1", txID, "sess-1")

			w := httptest.NewRecorder()
			handlers.HandleCallback(w, withBrowser(handlers, httptest.NewRequest(http.MethodGet, "/oauth/callback?state=fb-st-1&code=x", nil)))
			require.Equal(t, http.StatusFound, w.Code)
			loc, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err)
			if tc.fails {
				assert.Equal(t, ErrInvalidTarget, loc.Query().Get("error"))
				assert.Empty(t, loc.Query().Get("code"))
				return
			}
			code := loc.Query().Get("code")
			require.NotEmpty(t, code)
			stored, err := sm.ConsumeAuthorizationCode(ctx, code)
			require.NoError(t, err)
			require.NotNil(t, stored)
			assert.Equal(t, tc.want, stored.Resource)
		})
	}
}

// ===== /introspect =====

func TestIntrospect_ShowsAudience(t *testing.T) {
	handlers, sm, _, _ := testHandlers(t)
	ctx := context.Background()

	bound := state.NewAccessTokenData("bound-at", "uid", "id", "refresh", time.Now().Unix()+3600, "openid", 3600)
	bound.Resource = audProfile
	require.NoError(t, sm.StoreAccessToken(ctx, bound))
	legacy := state.NewAccessTokenData("legacy-at", "uid", "id", "refresh", time.Now().Unix()+3600, "openid", 3600)
	require.NoError(t, sm.StoreAccessToken(ctx, legacy))

	introspect := func(token string) map[string]interface{} {
		form := url.Values{"token": {token}}
		req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handlers.HandleIntrospect(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		return audDecode(t, w)
	}

	resp := introspect("bound-at")
	assert.Equal(t, true, resp["active"])
	assert.Equal(t, audProfile, resp["aud"])

	resp = introspect("legacy-at")
	assert.Equal(t, true, resp["active"])
	_, hasAud := resp["aud"]
	assert.False(t, hasAud, "aud is omitted when the token has no resource binding")
}

// ===== MFA completion =====

func TestMFAVerify_CodeCarriesResource(t *testing.T) {
	for _, tc := range []struct{ name, stored, want string }{
		{"bound", audProfile, audProfile},
		{"state without a resource is for the whole server", "", audOrigin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handlers, sm, _, _ := testHandlers(t)
			ctx := context.Background()
			oauthState := state.NewOAuthState("st-mfa", "challenge", "S256", "https://app.example.com/callback", "test-client", "openid", tc.stored, "google.com")
			txID := mustCreateTx(t, sm, oauthState)
			mfaSession := state.NewMFASession("pending", "enrollment", txID, "User", "test-uid-123", "user@test.com", nil)
			sessionID, err := sm.GenerateMFASessionID()
			require.NoError(t, err)
			require.NoError(t, sm.StoreMFASession(ctx, sessionID, mfaSession))

			w := httptest.NewRecorder()
			handlers.HandleMFAVerify(w, withBrowser(handlers, httptest.NewRequest(http.MethodPost, "/oauth/mfa-verify", nil)), sessionID, "123456")
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())

			resp := audDecode(t, w)
			redirect, err := url.Parse(resp["redirect_url"].(string))
			require.NoError(t, err)
			stored, err := sm.ConsumeAuthorizationCode(ctx, redirect.Query().Get("code"))
			require.NoError(t, err)
			require.NotNil(t, stored)
			assert.Equal(t, tc.want, stored.Resource)
		})
	}
}
