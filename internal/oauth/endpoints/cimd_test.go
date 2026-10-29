package endpoints

import (
	"context"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/cimd"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	cimdRedirect   = "https://app.example.com/callback"
	cimdLocalhost  = "http://localhost:3000/callback"
	cimdTestVerif  = "cimd-verifier-123456789012345678901234567890"
	cimdTestStateP = "client-state-cimd"
)

// cimdEnv is a Handlers wired to a CIMD fetcher that talks to a local TLS
// server hosting the client's metadata document.
type cimdEnv struct {
	h        *Handlers
	sm       *state.Manager
	clientID string
	fetches  *atomic.Int64
	doc      *map[string]any
	mr       *miniredis.Miniredis
}

func newCIMDEnv(t *testing.T) *cimdEnv {
	t.Helper()
	h, sm, _, mr := testHandlers(t)

	tmpl, err := template.ParseGlob("../../../templates/*.html")
	require.NoError(t, err)
	h.templates = tmpl

	fetches := &atomic.Int64{}
	doc := map[string]any{
		"client_name":                "Example MCP Client",
		"redirect_uris":              []string{cimdRedirect, cimdLocalhost},
		"token_endpoint_auth_method": "none",
	}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		d := map[string]any{"client_id": srv.URL + r.URL.Path}
		for k, v := range doc {
			d[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(d)
	}))
	t.Cleanup(srv.Close)

	f := cimd.NewFetcherForTesting(sm, testLogger(), srv.Client().Transport)
	h.cimd = f
	return &cimdEnv{h: h, sm: sm, clientID: srv.URL + "/oauth/client.json", fetches: fetches, doc: &doc, mr: mr}
}

func (e *cimdEnv) authorizeQuery(clientID, redirect, provider string) url.Values {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirect)
	q.Set("state", cimdTestStateP)
	q.Set("code_challenge", generatePKCEChallenge(cimdTestVerif))
	q.Set("code_challenge_method", "S256")
	q.Set("scope", "limacharlie:read")
	if provider != "" {
		q.Set("provider", provider)
	}
	return q
}

func (e *cimdEnv) authorize(q url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.h.HandleAuthorize(w, req)
	return w
}

func oauthErrorOf(t *testing.T, w *httptest.ResponseRecorder) OAuthError {
	t.Helper()
	var e OAuthError
	require.NoError(t, json.NewDecoder(w.Body).Decode(&e))
	return e
}

func sessionFromLocation(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	require.Equal(t, http.StatusFound, w.Code)
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/oauth/select-provider", loc.Path)
	return loc.Query().Get("session")
}

func (e *cimdEnv) selectionPage(t *testing.T, session string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oauth/select-provider?session="+session, nil)
	w := httptest.NewRecorder()
	e.h.HandleProviderSelection(w, req, session)
	return w
}

// clickProvider performs the selection page's provider choice and returns the
// /authorize request the browser is redirected to (with the cookies it was given).
func (e *cimdEnv) clickProvider(t *testing.T, session, provider string) (url.Values, []*http.Cookie) {
	t.Helper()
	form := url.Values{"provider": {provider}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/select-provider?session="+session, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	e.h.HandleProviderSelection(w, req, session)
	require.Equal(t, http.StatusFound, w.Code)
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/authorize", loc.Path)
	return loc.Query(), w.Result().Cookies()
}

// ===== /authorize =====

func TestCIMDAuthorize_MatchingRedirectGoesToSelectionPage(t *testing.T) {
	e := newCIMDEnv(t)
	w := e.authorize(e.authorizeQuery(e.clientID, cimdRedirect, ""))
	session := sessionFromLocation(t, w)

	params, err := e.sm.GetSelectionSession(context.Background(), session)
	require.NoError(t, err)
	assert.Equal(t, e.clientID, params["client_id"])
	assert.Equal(t, cimdRedirect, params["redirect_uri"])
	assert.NotContains(t, params, "provider")
}

func TestCIMDAuthorize_RedirectURIMustMatchDocumentExactly(t *testing.T) {
	e := newCIMDEnv(t)
	for _, redirect := range []string{
		"https://app.example.com/callback/",
		"https://app.example.com/callback?x=1",
		"https://APP.example.com/callback",
		"https://app.example.com/other",
		"https://evil.example.com/callback",
		"http://localhost:3001/callback",
		"http://127.0.0.1:3000/callback",
		// allowed by the global allow-list but not listed in the document
		"https://app.example.com/oauth/callback",
		"http://127.0.0.1:3000/callback ",
	} {
		w := e.authorize(e.authorizeQuery(e.clientID, redirect, ""))
		assert.Equal(t, http.StatusBadRequest, w.Code, redirect)
		assert.Equal(t, ErrInvalidRequest, oauthErrorOf(t, w).Error, redirect)
	}
}

func TestCIMDAuthorize_DocumentProblemsRejectTheRequest(t *testing.T) {
	cases := map[string]map[string]any{
		"private_key_jwt": {"token_endpoint_auth_method": "private_key_jwt"},
		"client_secret":   {"client_secret": "x"},
		"no client_name":  {"client_name": nil},
		"no redirects":    {"redirect_uris": []string{}},
		"bad redirect":    {"redirect_uris": []string{"http://app.example.com/cb"}},
	}
	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			e := newCIMDEnv(t)
			for k, v := range override {
				if v == nil {
					delete(*e.doc, k)
				} else {
					(*e.doc)[k] = v
				}
			}
			w := e.authorize(e.authorizeQuery(e.clientID, cimdRedirect, ""))
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Equal(t, ErrInvalidClient, oauthErrorOf(t, w).Error)
		})
	}
}

func TestCIMDAuthorize_DocumentClientIDMismatchRejected(t *testing.T) {
	e := newCIMDEnv(t)
	// A host serving a document that claims a different client_id (here,
	// someone else's) must not be accepted for the URL it was fetched from.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id": "https://victim.example.com/client.json", "client_name": "Victim",
			"redirect_uris": []string{cimdRedirect},
		})
	}))
	t.Cleanup(srv.Close)
	e.h.cimd = cimd.NewFetcherForTesting(e.sm, testLogger(), srv.Client().Transport)

	w := e.authorize(e.authorizeQuery(srv.URL+"/client.json", cimdRedirect, ""))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, ErrInvalidClient, oauthErrorOf(t, w).Error)
}

func TestCIMDAuthorize_URLClientIDsNeverFallBackToOtherAuthorities(t *testing.T) {
	e := newCIMDEnv(t)
	ctx := context.Background()

	// A URL client_id that is not a valid CIMD id is refused even though its
	// redirect URI is on the global allow-list.
	for _, id := range []string{
		"https://app.example.com",
		"https://app.example.com/",
		"http://app.example.com/client.json",
		"https://app.example.com/client.json#x",
		"https://user:pw@app.example.com/client.json",
		"ftp://app.example.com/client.json",
		"https://app.example.com:8443/client.json",
	} {
		w := e.authorize(e.authorizeQuery(id, cimdRedirect, ""))
		assert.Equal(t, http.StatusBadRequest, w.Code, id)
	}

	// A DCR record under a URL-shaped id is ignored: the document decides.
	require.NoError(t, e.sm.StoreClientRegistration(ctx, state.NewClientRegistration(
		e.clientID, "Registered", []string{"https://registered.example.com/cb"})))
	w := e.authorize(e.authorizeQuery(e.clientID, "https://registered.example.com/cb", ""))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.True(t, e.h.isValidRedirectURI(ctx, cimdRedirect, e.clientID))
	assert.False(t, e.h.isValidRedirectURI(ctx, "https://registered.example.com/cb", e.clientID))
	assert.False(t, e.h.isValidRedirectURI(ctx, "https://app.example.com/oauth/callback", e.clientID),
		"the global allow-list must not apply to CIMD clients")
}

func TestCIMDAuthorize_DisabledResolverFailsClosed(t *testing.T) {
	e := newCIMDEnv(t)
	e.h.cimd = nil
	w := e.authorize(e.authorizeQuery(e.clientID, cimdRedirect, ""))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.False(t, e.h.isValidRedirectURI(context.Background(), cimdRedirect, e.clientID))
}

type fakeResolver struct {
	doc *cimd.Document
	err error
}

func (f fakeResolver) Resolve(context.Context, string) (*cimd.Document, error) { return f.doc, f.err }

func TestCIMDAuthorize_BusyFetcherReturns503(t *testing.T) {
	e := newCIMDEnv(t)
	e.h.cimd = fakeResolver{err: &cimd.Error{Kind: cimd.KindBusy, Message: "try again"}}
	w := e.authorize(e.authorizeQuery(e.clientID, cimdRedirect, ""))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, ErrTemporarilyUnavailable, oauthErrorOf(t, w).Error)
}

func TestCIMDAuthorize_ErrorsDoNotLeakDocumentBodiesToLogsOrClients(t *testing.T) {
	e := newCIMDEnv(t)
	(*e.doc)["client_secret"] = "super-secret-value"
	w := e.authorize(e.authorizeQuery(e.clientID, cimdRedirect, ""))
	body := w.Body.String()
	assert.NotContains(t, body, "super-secret-value")
}

// ===== the selection page requirement =====

func TestCIMDAuthorize_DirectProviderStillShowsSelectionPage(t *testing.T) {
	e := newCIMDEnv(t)
	created := false
	mock := e.h.firebaseClient.(*mockFirebaseClient)
	mock.createAuthURIFunc = func(ctx context.Context, provider, continueURI string, scopes []string) (string, string, error) {
		created = true
		return "s", "https://firebase.example.com/auth?state=fb", nil
	}

	for name, mutate := range map[string]func(q url.Values){
		"no ack":              func(q url.Values) {},
		"forged ack":          func(q url.Values) { q.Set("selection_ack", "forged-token") },
		"empty ack":           func(q url.Values) { q.Set("selection_ack", "") },
		"provider google.com": func(q url.Values) { q.Set("provider", "google.com") },
	} {
		q := e.authorizeQuery(e.clientID, cimdRedirect, "google")
		mutate(q)
		w := e.authorize(q, &http.Cookie{Name: selectionAckCookie, Value: "whatever"})
		_ = sessionFromLocation(t, w) // routed to the selection page, not to the IdP
		assert.False(t, created, name)
	}
	st, _ := e.sm.GetOAuthState(context.Background(), cimdTestStateP)
	assert.Nil(t, st, "no OAuth state may be created before the selection page")
}

func TestCIMDAuthorize_NonCIMDClientsCanSkipSelectionPage(t *testing.T) {
	e := newCIMDEnv(t)
	q := e.authorizeQuery("test-client", cimdRedirect, "google")
	w := e.authorize(q)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "firebase.example.com")
}

func TestCIMDSelectionAck_CookieAttributes(t *testing.T) {
	e := newCIMDEnv(t)
	session := sessionFromLocation(t, e.authorize(e.authorizeQuery(e.clientID, cimdRedirect, "")))
	q, cookies := e.clickProvider(t, session, "google")
	require.NotEmpty(t, q.Get("selection_ack"))
	require.Len(t, cookies, 1)
	ck := cookies[0]
	assert.Equal(t, selectionAckCookie, ck.Name)
	assert.True(t, ck.HttpOnly)
	assert.True(t, ck.Secure, "server URL is https")
	assert.Equal(t, "/authorize", ck.Path)
	assert.Equal(t, http.SameSiteLaxMode, ck.SameSite)
}

func TestCIMDSelectionAck_NotIssuedToOpaqueClients(t *testing.T) {
	e := newCIMDEnv(t)
	session := sessionFromLocation(t, e.authorize(e.authorizeQuery("test-client", cimdRedirect, "")))
	q, cookies := e.clickProvider(t, session, "google")
	assert.Empty(t, q.Get("selection_ack"))
	assert.Empty(t, cookies)
}

func TestCIMDSelectionAck_MissingCookieOrChangedRequestRejected(t *testing.T) {
	e := newCIMDEnv(t)

	// Another browser (no cookie) does not get to skip the page.
	session := sessionFromLocation(t, e.authorize(e.authorizeQuery(e.clientID, cimdRedirect, "")))
	q, _ := e.clickProvider(t, session, "google")
	_ = sessionFromLocation(t, e.authorize(q))

	// The ack is bound to the exact request parameters.
	for _, field := range []string{"state", "redirect_uri", "code_challenge", "client_id"} {
		session = sessionFromLocation(t, e.authorize(e.authorizeQuery(e.clientID, cimdRedirect, "")))
		q, cookies := e.clickProvider(t, session, "google")
		switch field {
		case "redirect_uri":
			q.Set(field, cimdLocalhost) // also in the document, so only the binding can catch it
		case "client_id":
			q.Set(field, e.clientID+"2")
		default:
			q.Set(field, q.Get(field)+"x")
		}
		_ = sessionFromLocation(t, e.authorize(q, cookies...))
	}
}

func TestCIMDSelectionAck_HappyPathReachesIdPOnce(t *testing.T) {
	e := newCIMDEnv(t)
	session := sessionFromLocation(t, e.authorize(e.authorizeQuery(e.clientID, cimdRedirect, "")))
	q, cookies := e.clickProvider(t, session, "google")

	w := e.authorize(q, cookies...)
	require.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "firebase.example.com")

	// Replaying the same ack does not skip the page a second time.
	w = e.authorize(q, cookies...)
	_ = sessionFromLocation(t, w)
}

func TestCIMDSelectionAck_WrongCookieValueRejected(t *testing.T) {
	e := newCIMDEnv(t)
	session := sessionFromLocation(t, e.authorize(e.authorizeQuery(e.clientID, cimdRedirect, "")))
	q, _ := e.clickProvider(t, session, "google")
	_ = sessionFromLocation(t, e.authorize(q, &http.Cookie{Name: selectionAckCookie, Value: "attacker-chosen"}))
}

func TestHandleProviderSelection_ExpiredSessionPOST(t *testing.T) {
	e := newCIMDEnv(t)
	form := url.Values{"provider": {"google"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/select-provider", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	e.h.HandleProviderSelection(w, req, "no-such-session")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ===== selection page rendering =====

func TestCIMDSelectionPage_ShowsClientNameAndRedirectHost(t *testing.T) {
	e := newCIMDEnv(t)
	session := sessionFromLocation(t, e.authorize(e.authorizeQuery(e.clientID, cimdRedirect, "")))
	w := e.selectionPage(t, session)
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()

	assert.Contains(t, body, "Example MCP Client")
	assert.Contains(t, body, "app.example.com", "redirect hostname must be shown")
	assert.Contains(t, body, "127.0.0.1", "client_id host must be shown")
	assert.NotContains(t, body, `role="alert"`, "no localhost warning for an https redirect")
	assert.Contains(t, body, "/oauth/select-provider/google?session=")
}

func TestCIMDSelectionPage_LocalhostRedirectShowsWarning(t *testing.T) {
	e := newCIMDEnv(t)
	session := sessionFromLocation(t, e.authorize(e.authorizeQuery(e.clientID, cimdLocalhost, "")))
	body := e.selectionPage(t, session).Body.String()

	assert.Contains(t, body, "localhost:3000")
	assert.Contains(t, body, `role="alert"`)
	assert.Contains(t, body, "your own computer")
}

func TestCIMDSelectionPage_EscapesMaliciousClientName(t *testing.T) {
	e := newCIMDEnv(t)
	for i, name := range []string{
		`<script>alert(1)</script>`,
		`"><img src=x onerror=alert(1)>`,
		`</style><script>alert(2)</script>`,
		`{{.SessionID}}`,
	} {
		(*e.doc)["client_name"] = name
		// distinct client_id per case so the document cache does not mask the change
		clientID := e.clientID + strconv.Itoa(i)
		session := sessionFromLocation(t, e.authorize(e.authorizeQuery(clientID, cimdRedirect, "")))
		body := e.selectionPage(t, session).Body.String()

		assert.NotContains(t, body, "<script>alert", name)
		assert.NotContains(t, body, "<img src=x", name)
		assert.Contains(t, body, template.HTMLEscapeString(name), name)
	}
}

func TestCIMDSelectionPage_FailsClosedWhenDocumentNoLongerValid(t *testing.T) {
	e := newCIMDEnv(t)
	session := sessionFromLocation(t, e.authorize(e.authorizeQuery(e.clientID, cimdRedirect, "")))

	// The document drops the redirect URI and the cached copy is gone.
	(*e.doc)["redirect_uris"] = []string{"https://other.example.com/cb"}
	for _, k := range e.mr.Keys() {
		if strings.HasPrefix(k, "oauth:cimd:") {
			e.mr.Del(k)
		}
	}

	w := e.selectionPage(t, session)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NotContains(t, w.Body.String(), "Sign in to LimaCharlie")
}

func TestSelectionPage_NonCIMDClientHasNoClientBlock(t *testing.T) {
	e := newCIMDEnv(t)
	w := e.authorize(e.authorizeQuery("test-client", cimdRedirect, ""))
	session := sessionFromLocation(t, w)
	body := e.selectionPage(t, session).Body.String()
	assert.NotContains(t, body, "client-info\"")
	assert.Contains(t, body, "Sign in to LimaCharlie MCP")
}

// ===== end to end with a URL client_id =====

func TestCIMD_EndToEndTokenExchange(t *testing.T) {
	e := newCIMDEnv(t)

	// /authorize -> selection page -> provider click -> /authorize -> IdP
	session := sessionFromLocation(t, e.authorize(e.authorizeQuery(e.clientID, cimdRedirect, "")))
	q, cookies := e.clickProvider(t, session, "google")
	w := e.authorize(q, cookies...)
	require.Equal(t, http.StatusFound, w.Code)
	require.Contains(t, w.Header().Get("Location"), "firebase.example.com")

	// IdP callback issues our authorization code
	cb := httptest.NewRecorder()
	e.h.HandleCallback(cb, httptest.NewRequest(http.MethodGet, "/oauth/callback?state=firebase-state-123&code=idp-code", nil))
	require.Equal(t, http.StatusFound, cb.Code)
	loc, err := url.Parse(cb.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "app.example.com", loc.Host)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code)
	assert.Equal(t, cimdTestStateP, loc.Query().Get("state"))

	token := func(clientID string) *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {cimdRedirect},
			"client_id":     {clientID},
			"code_verifier": {cimdTestVerif},
		}
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		e.h.HandleToken(w, req)
		return w
	}

	// A different client cannot redeem the code (and the code is single-use).
	bad := token("https://other.example.com/client.json")
	assert.Equal(t, http.StatusBadRequest, bad.Code)
	assert.Equal(t, ErrInvalidGrant, oauthErrorOf(t, bad).Error)

	// The code was consumed by the failed attempt; run the flow again for the success case.
	session = sessionFromLocation(t, e.authorize(e.authorizeQuery(e.clientID, cimdRedirect, "")))
	q, cookies = e.clickProvider(t, session, "google")
	require.Equal(t, http.StatusFound, e.authorize(q, cookies...).Code)
	cb = httptest.NewRecorder()
	e.h.HandleCallback(cb, httptest.NewRequest(http.MethodGet, "/oauth/callback?state=firebase-state-123&code=idp-code", nil))
	require.Equal(t, http.StatusFound, cb.Code)
	loc, _ = url.Parse(cb.Header().Get("Location"))
	code = loc.Query().Get("code")

	ok := token(e.clientID)
	require.Equal(t, http.StatusOK, ok.Code, ok.Body.String())
	var resp map[string]any
	require.NoError(t, json.NewDecoder(ok.Body).Decode(&resp))
	assert.NotEmpty(t, resp["access_token"])
}

// ===== existing client types are unchanged =====

func TestCIMD_DCRAndAllowListClientsUnchanged(t *testing.T) {
	e := newCIMDEnv(t)
	ctx := context.Background()

	require.NoError(t, e.sm.StoreClientRegistration(ctx, state.NewClientRegistration(
		"mcp_dcrclient", "DCR Client", []string{"https://dcr.example.com/cb"})))

	w := e.authorize(e.authorizeQuery("mcp_dcrclient", "https://dcr.example.com/cb", ""))
	_ = sessionFromLocation(t, w)

	// registered client, URI not registered
	w = e.authorize(e.authorizeQuery("mcp_dcrclient", cimdRedirect, ""))
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// unregistered opaque client id on the global allow-list
	w = e.authorize(e.authorizeQuery("some-client", cimdRedirect, ""))
	_ = sessionFromLocation(t, w)
	w = e.authorize(e.authorizeQuery("some-client", "https://evil.example.com/cb", ""))
	assert.Equal(t, http.StatusBadRequest, w.Code)

	assert.Zero(t, e.fetches.Load(), "non-URL client ids never trigger a fetch")

	// /register still works
	body := `{"client_name":"X","redirect_uris":["https://x.example.com/cb"]}`
	rw := httptest.NewRecorder()
	e.h.HandleRegister(rw, httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body)))
	assert.Equal(t, http.StatusCreated, rw.Code)
	b, _ := io.ReadAll(rw.Body)
	assert.Contains(t, string(b), `"token_endpoint_auth_method":"none"`)
}
