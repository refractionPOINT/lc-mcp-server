package endpoints

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/firebase"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/metadata"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The browser-binding tests drive the endpoints the way browsers do: each
// "browser" is only the set of cookies it carries.

// issuedCodes counts authorization codes in Redis.
func issuedCodes(mr *miniredis.Miniredis) int {
	n := 0
	for _, k := range mr.Keys() {
		if strings.HasPrefix(k, state.CodePrefix) {
			n++
		}
	}
	return n
}

// bindCookieOf is the browser-binding cookie a response set.
func bindCookieOf(t *testing.T, h *Handlers, cookies []*http.Cookie) *http.Cookie {
	t.Helper()
	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == h.browserBindCookieName() {
			require.Nil(t, found, "the cookie is set once")
			found = c
		}
	}
	require.NotNil(t, found, "/authorize sets the browser-binding cookie")
	return found
}

// countSignIns counts the identity-provider exchanges the callback performs: a
// refused callback must not get as far as redeeming the provider's code.
func countSignIns(mock *mockFirebaseClient) *atomic.Int64 {
	var n atomic.Int64
	inner := mock.signInWithIdpFunc
	mock.signInWithIdpFunc = func(ctx context.Context, requestURI, postBody, sessionID, providerID string) (*firebase.SignInWithIdpResponse, error) {
		n.Add(1)
		return inner(ctx, requestURI, postBody, sessionID, providerID)
	}
	return &n
}

// withMFA makes every sign-in require a TOTP code (123456 is accepted), and
// counts the finalize calls.
func withMFA(mock *mockFirebaseClient) *atomic.Int64 {
	var finalized atomic.Int64
	mock.signInWithIdpFunc = func(ctx context.Context, requestURI, postBody, sessionID, providerID string) (*firebase.SignInWithIdpResponse, error) {
		return nil, &firebase.MFARequiredError{
			MFAPendingCredential: "pending-" + sessionID, MFAEnrollmentID: "enroll", DisplayName: "User",
			LocalID: "uid-of-" + sessionID, Email: "user@example.com", PendingToken: "pt",
		}
	}
	mock.finalizeMFASignInFunc = func(ctx context.Context, pending, enrollment, code string) (*firebase.FinalizeMFAResponse, error) {
		finalized.Add(1)
		return &firebase.FinalizeMFAResponse{
			LocalID: "uid-of-" + strings.TrimPrefix(pending, "pending-"), IDToken: "id-token", RefreshToken: "rt", ExpiresIn: "3600",
		}, nil
	}
	return &finalized
}

func mfaVerifyIn(h *Handlers, session string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.HandleMFAVerify(w, withCookies(httptest.NewRequest(http.MethodPost, "/oauth/mfa-verify", nil), cookies...), session, "123456")
	return w
}

func mfaChallengeIn(h *Handlers, session string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.HandleMFAChallenge(w, withCookies(httptest.NewRequest(http.MethodGet, "/oauth/mfa-challenge?session="+session, nil), cookies...), session)
	return w
}

func mfaSessionOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/oauth/mfa-challenge", loc.Path)
	return loc.Query().Get("session")
}

// assertRefused checks a callback response that must have granted nothing: a
// local error page, never a redirect to anyone's redirect URI.
func assertRefused(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	assert.Empty(t, w.Header().Get("Location"), "no redirect: the client's redirect URI is never contacted")
	assert.Contains(t, w.Body.String(), "start the sign-in again")
	assert.NotContains(t, w.Body.String(), "code=")
}

// ===== the attack =====

// ATTACK: the attacker registers their own client with a redirect URI they
// control, goes through the selection page and /authorize in their own
// browser, and sends the resulting provider URL to a victim. The victim signs
// in at the provider and the provider returns the victim's browser to
// /oauth/callback. Before the binding, that callback issued the victim's
// authorization code and redirected it to the attacker's redirect URI, where
// the attacker redeemed it with their own PKCE verifier.
func TestCallback_ProviderURLSentToAVictimDoesNotIssueACode(t *testing.T) {
	h, sm, mockFB, mr := testHandlers(t)
	realisticFirebase(mockFB)
	registerAttacker(t, sm)
	signIns := countSignIns(mockFB)

	attacker := startSignIn(t, h, authQuery(attackerClient, attackerRedirect, "attacker-state", attackerVerifier))

	// A second sign-in the victim really has in this same server, to give the
	// victim's browser a binding cookie of its own.
	victimOwn := startSignIn(t, h, authQuery(victimClient, victimRedirect, "victim-state", victimVerifier))
	victimCookie := bindCookieOf(t, h, victimOwn.cookies)
	require.NotEqual(t, bindCookieOf(t, h, attacker.cookies).Value, victimCookie.Value)

	for name, cookies := range map[string][]*http.Cookie{
		"a victim browser with no binding cookie":             nil,
		"a victim browser with a binding cookie of its own":   {victimCookie},
		"a victim browser with an unrelated secret":           {{Name: h.browserBindCookieName(), Value: "x"}},
		"a victim browser with the selection cookies only":    {{Name: h.selectionBindCookieName(), Value: "x"}, {Name: h.selectionAckCookieName(), Value: "x"}},
		"the attacker's secret under the name used over http": {{Name: browserBindCookie, Value: bindCookieOf(t, h, attacker.cookies).Value}},
		"an empty binding cookie":                             {{Name: h.browserBindCookieName(), Value: ""}},
	} {
		t.Run(name, func(t *testing.T) {
			// Each case needs a fresh attacker transaction: a refused callback abandons it.
			a := startSignIn(t, h, authQuery(attackerClient, attackerRedirect, "attacker-state", attackerVerifier))
			w := callbackIn(h, a.fb, cookies...)
			assertRefused(t, w)
		})
	}

	assert.Zero(t, issuedCodes(mr), "no authorization code exists anywhere")
	assert.Zero(t, signIns.Load(), "the provider's code was never redeemed")

	// The refused transactions are gone, and the attacker cannot finish them in their own browser.
	w := callbackFor(h, attacker)
	require.Equal(t, http.StatusFound, w.Code, "the attacker's own, untouched, transaction still works for their own account")
	loc, _ := url.Parse(w.Header().Get("Location"))
	assert.Equal(t, "attacker.example.net", loc.Host)
}

// The same victim-side attack, with every other part of the flow genuine: the
// callback is refused and the transaction destroyed, so replaying it from the
// attacker's browser afterwards yields nothing either.
func TestCallback_RefusedCallbackAbandonsTheTransaction(t *testing.T) {
	h, sm, mockFB, mr := testHandlers(t)
	realisticFirebase(mockFB)
	registerAttacker(t, sm)
	attacker := startSignIn(t, h, authQuery(attackerClient, attackerRedirect, "s", attackerVerifier))

	assertRefused(t, callbackIn(h, attacker.fb)) // the victim's browser
	assert.Empty(t, storedTxs(t, sm, mr))

	w := callbackFor(h, attacker) // the attacker replays it
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, w.Header().Get("Location"))
	assert.Zero(t, issuedCodes(mr))
}

// ATTACK with MFA: the callback is refused in the victim's browser before an
// MFA challenge exists, so there is nothing to verify.
func TestCallback_ProviderURLSentToAVictimDoesNotStartMFA(t *testing.T) {
	h, sm, mockFB, mr := testHandlers(t)
	realisticFirebase(mockFB)
	registerAttacker(t, sm)
	finalized := withMFA(mockFB)

	attacker := startSignIn(t, h, authQuery(attackerClient, attackerRedirect, "s", attackerVerifier))
	assertRefused(t, callbackIn(h, attacker.fb))

	assert.Zero(t, finalized.Load())
	assert.Zero(t, issuedCodes(mr))
	for _, k := range mr.Keys() {
		assert.False(t, strings.HasPrefix(k, state.MFAPrefix), "no MFA session: %s", k)
	}
}

// ATTACK on the MFA steps themselves: the attacker's browser completed the
// callback (so an MFA session for the attacker's transaction exists) and the
// attacker gets the victim to finish the MFA step, in a browser that is not the
// one the transaction was started in.
func TestMFA_VerifyFromAnotherBrowserIssuesNoCode(t *testing.T) {
	h, sm, mockFB, mr := testHandlers(t)
	realisticFirebase(mockFB)
	registerAttacker(t, sm)
	finalized := withMFA(mockFB)

	victimBrowser := startSignIn(t, h, authQuery(victimClient, victimRedirect, "v", victimVerifier)).cookies
	for name, cookies := range map[string][]*http.Cookie{
		"no cookie":                nil,
		"another browser's cookie": victimBrowser,
		"a made up secret":         {{Name: h.browserBindCookieName(), Value: "made-up"}},
	} {
		t.Run(name, func(t *testing.T) {
			// A fresh MFA session each time: a refused step abandons the transaction.
			a := startSignIn(t, h, authQuery(attackerClient, attackerRedirect, "s", attackerVerifier))
			sess := mfaSessionOf(t, callbackFor(h, a))

			w := mfaVerifyIn(h, sess, cookies...)
			assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
			assert.Equal(t, "browser_mismatch", audDecode(t, w)["error"])
			assert.NotContains(t, w.Body.String(), "redirect_url")

			// The transaction and the MFA session are gone: not even the right browser can finish.
			w = mfaVerifyIn(h, sess, a.cookies...)
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.NotContains(t, w.Body.String(), "redirect_url")
		})
	}
	assert.Zero(t, finalized.Load(), "the provider was never asked to verify a code")
	assert.Zero(t, issuedCodes(mr))
}

func TestMFA_RefusedVerifyDoesNotBurnTheOwnersAttempts(t *testing.T) {
	h, _, mockFB, _ := testHandlers(t)
	realisticFirebase(mockFB)
	withMFA(mockFB)
	owner := startSignIn(t, h, authQuery(victimClient, victimRedirect, "s", victimVerifier))
	session := mfaSessionOf(t, callbackFor(h, owner))

	// Someone who only saw the session id hammers it from another browser: the
	// first refusal ends the transaction rather than counting down the attempts.
	for i := 0; i < 5; i++ {
		w := mfaVerifyIn(h, session)
		assert.NotEqual(t, http.StatusOK, w.Code)
		assert.NotContains(t, w.Body.String(), "redirect_url")
	}
	attempts, _ := h.stateManager.GetMFAAttemptCount(context.Background(), session)
	assert.Zero(t, attempts)
}

func TestMFA_ChallengePageFromAnotherBrowserIsRefused(t *testing.T) {
	h, sm, mockFB, mr := testHandlers(t)
	realisticFirebase(mockFB)
	withMFA(mockFB)
	owner := startSignIn(t, h, authQuery(victimClient, victimRedirect, "s", victimVerifier))
	session := mfaSessionOf(t, callbackFor(h, owner))

	w := mfaChallengeIn(h, session) // no cookie
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.NotContains(t, w.Body.String(), "user@example.com", "the account's email is not shown to a stranger")
	assert.Contains(t, w.Body.String(), "start the sign-in again")
	assert.Empty(t, storedTxs(t, sm, mr), "the transaction is abandoned")
	got, _ := sm.GetMFASession(context.Background(), session)
	assert.Nil(t, got)
}

// ===== legitimate flows =====

func TestBrowserBinding_SameBrowserCompletesWithoutMFA(t *testing.T) {
	h, sm, mockFB, mr := testHandlers(t)
	realisticFirebase(mockFB)

	s := startSignIn(t, h, authQuery(victimClient, victimRedirect, "my-state", victimVerifier))
	w := callbackFor(h, s)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "app.example.com", loc.Host)
	assert.Equal(t, "my-state", loc.Query().Get("state"))
	assert.Equal(t, 1, issuedCodes(mr))

	w = audPostToken(t, h, tokenForm(loc.Query().Get("code"), victimClient, victimRedirect, victimVerifier))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	at, err := sm.GetAccessTokenData(context.Background(), audDecode(t, w)["access_token"].(string))
	require.NoError(t, err)
	require.NotNil(t, at)
	assert.Equal(t, "uid-of-fb-session-1", at.UID)
}

func TestBrowserBinding_SameBrowserCompletesWithMFA(t *testing.T) {
	h, _, mockFB, _ := testHandlers(t)
	realisticFirebase(mockFB)
	withMFA(mockFB)

	s := startSignIn(t, h, authQuery(victimClient, victimRedirect, "mfa-state", victimVerifier))
	session := mfaSessionOf(t, callbackFor(h, s))

	page := mfaChallengeIn(h, session, s.cookies...)
	require.Equal(t, http.StatusOK, page.Code, page.Body.String())
	assert.Contains(t, page.Body.String(), "user@example.com")

	w := mfaVerifyIn(h, session, s.cookies...)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	redirect, err := url.Parse(audDecode(t, w)["redirect_url"].(string))
	require.NoError(t, err)
	assert.Equal(t, "app.example.com", redirect.Host)
	assert.Equal(t, "mfa-state", redirect.Query().Get("state"))

	w = audPostToken(t, h, tokenForm(redirect.Query().Get("code"), victimClient, victimRedirect, victimVerifier))
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// Several sign-ins in one browser (two tabs, two MCP clients) share the
// browser's secret: neither invalidates the other.
func TestBrowserBinding_ConcurrentSignInsInOneBrowserBothWork(t *testing.T) {
	h, sm, mockFB, mr := testHandlers(t)
	realisticFirebase(mockFB)
	registerAttacker(t, sm) // a second, unrelated client of the same user

	first := startSignIn(t, h, authQuery(victimClient, victimRedirect, "one", victimVerifier))
	secret := bindCookieOf(t, h, first.cookies)

	// The second tab: it already holds the cookie, which /authorize keeps and renews.
	q := authQuery(attackerClient, attackerRedirect, "two", attackerVerifier)
	provider := q.Get("provider")
	q.Del("provider")
	loc, _ := url.Parse(authorizeRequest(h, q).Header().Get("Location"))
	picked, held := completeSelection(t, h, loc.Query().Get("session"), provider, secret)
	require.Equal(t, http.StatusFound, picked.Code, picked.Body.String())
	back, _ := url.Parse(picked.Header().Get("Location"))
	w := authorizeRequest(h, back.Query(), held...)
	secondCookie := bindCookieOf(t, h, w.Result().Cookies())
	assert.Equal(t, secret.Value, secondCookie.Value, "the browser's secret is reused, not replaced")
	second := signIn{fb: firebaseStateOf(t, w), cookies: []*http.Cookie{secondCookie}}

	// The two flows complete in either order, each with the one cookie.
	w2 := callbackFor(h, second)
	require.Equal(t, http.StatusFound, w2.Code, w2.Body.String())
	l2, _ := url.Parse(w2.Header().Get("Location"))
	assert.Equal(t, "attacker.example.net", l2.Host)
	w1 := callbackFor(h, first)
	require.Equal(t, http.StatusFound, w1.Code, w1.Body.String())
	l1, _ := url.Parse(w1.Header().Get("Location"))
	assert.Equal(t, "app.example.com", l1.Host)
	assert.Equal(t, 2, issuedCodes(mr))
}

// Two browsers get two different secrets.
func TestBrowserBinding_EachBrowserGetsItsOwnSecret(t *testing.T) {
	h, sm, mockFB, mr := testHandlers(t)
	realisticFirebase(mockFB)
	a := startSignIn(t, h, authQuery(victimClient, victimRedirect, "a", victimVerifier))
	b := startSignIn(t, h, authQuery(victimClient, victimRedirect, "b", victimVerifier))
	ca, cb := bindCookieOf(t, h, a.cookies), bindCookieOf(t, h, b.cookies)
	assert.NotEqual(t, ca.Value, cb.Value)
	assert.GreaterOrEqual(t, len(ca.Value), 43, "256 bits of randomness")

	// The transaction keeps a hash of the secret, never the secret.
	for _, tx := range storedTxs(t, sm, mr) {
		assert.NotEmpty(t, tx.BrowserBinding)
		assert.NotContains(t, []string{ca.Value, cb.Value}, tx.BrowserBinding)
		assert.Equal(t, sha256Hex(ca.Value) == tx.BrowserBinding || sha256Hex(cb.Value) == tx.BrowserBinding, true)
	}

	// Each browser's callback works only with its own secret.
	assertRefused(t, callbackIn(h, a.fb, cb))
	w := callbackIn(h, b.fb, cb)
	assert.Equal(t, http.StatusFound, w.Code, w.Body.String())
}

// A cookie that is not one we issued (planted by another page, or garbage) is
// replaced, not adopted as the browser's secret.
func TestBrowserBinding_ForeignCookieValueIsNotAdopted(t *testing.T) {
	h, sm, mockFB, mr := testHandlers(t)
	realisticFirebase(mockFB)
	planted := &http.Cookie{Name: h.browserBindCookieName(), Value: "attacker-chosen-and-known"}

	q := authQuery(victimClient, victimRedirect, "s", victimVerifier)
	provider := q.Get("provider")
	q.Del("provider")
	loc, _ := url.Parse(authorizeRequest(h, q).Header().Get("Location"))
	picked, held := completeSelection(t, h, loc.Query().Get("session"), provider, planted)
	back, _ := url.Parse(picked.Header().Get("Location"))
	w := authorizeRequest(h, back.Query(), held...)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())

	issued := bindCookieOf(t, h, w.Result().Cookies())
	assert.NotEqual(t, planted.Value, issued.Value)
	_, tx := onlyTx(t, sm, mr)
	assert.Equal(t, sha256Hex(issued.Value), tx.BrowserBinding)
	assertRefused(t, callbackIn(h, firebaseStateOf(t, w), planted))
}

// ===== cookie attributes =====

func TestBrowserBinding_CookieAttributesOverHTTPS(t *testing.T) {
	h, _, mockFB, _ := testHandlers(t)
	realisticFirebase(mockFB)
	s := startSignIn(t, h, authQuery(victimClient, victimRedirect, "s", victimVerifier))
	c := bindCookieOf(t, h, s.cookies)

	assert.Equal(t, "__Host-lc_oauth_browser", c.Name, "__Host- stops a sibling subdomain from planting the secret")
	assert.True(t, c.HttpOnly, "page scripts never see the secret")
	assert.True(t, c.Secure)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite, "Strict would be withheld on the provider's cross-site redirect back to /oauth/callback")
	assert.Equal(t, "/", c.Path, "required by __Host-; covers /oauth/callback and the MFA paths")
	assert.Empty(t, c.Domain, "host-only")
	assert.Equal(t, state.StateTTL, c.MaxAge, "as long as the transaction lives")
	assert.True(t, strings.HasPrefix(c.Name, "__Host-"))
}

func TestBrowserBinding_CookieAttributesOverHTTP(t *testing.T) {
	h, _, mockFB, _ := testHandlers(t)
	realisticFirebase(mockFB)
	t.Setenv("MCP_SERVER_URL", "http://localhost:8080")
	h.metadataProvider = metadata.NewProvider(testLogger())
	require.Equal(t, "http://localhost:8080", h.metadataProvider.GetServerURL())

	s := startSignIn(t, h, authQuery(victimClient, victimRedirect, "s", victimVerifier))
	c := bindCookieOf(t, h, s.cookies)
	assert.Equal(t, "lc_oauth_browser", c.Name, "a __Host- cookie cannot exist without https")
	assert.True(t, c.HttpOnly)
	assert.False(t, c.Secure)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
	assert.Equal(t, "/oauth", c.Path)
	for _, p := range []string{"/oauth/callback", "/oauth/mfa-challenge", "/oauth/mfa-verify"} {
		assert.True(t, strings.HasPrefix(p, c.Path+"/"), "%s is covered", p)
	}
	assert.Equal(t, http.StatusFound, callbackFor(h, s).Code)
}

// The cookie must reach the callback: what a browser does with Set-Cookie is
// checked here against the rules that matter, the cookie's own attributes.
func TestBrowserBinding_CookieIsSentOnTheProvidersCrossSiteRedirect(t *testing.T) {
	h, _, mockFB, _ := testHandlers(t)
	realisticFirebase(mockFB)
	s := startSignIn(t, h, authQuery(victimClient, victimRedirect, "s", victimVerifier))
	c := bindCookieOf(t, h, s.cookies)
	// A top-level GET navigation from another site is sent SameSite=Lax cookies.
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
	callback := httptest.NewRequest(http.MethodGet, "/oauth/callback?state="+s.fb+"&code=x", nil)
	callback.Header.Set("Sec-Fetch-Site", "cross-site")
	callback.Header.Set("Sec-Fetch-Mode", "navigate")
	callback.AddCookie(c)
	w := httptest.NewRecorder()
	h.HandleCallback(w, callback)
	assert.Equal(t, http.StatusFound, w.Code, "a cross-site navigation carrying the cookie is accepted")
}

// ===== no other path to a code =====

// Whatever the callback does when the provider fails, it never reaches the
// client's redirect URI from a browser that is not bound.
func TestCallback_ProviderFailureFromAnotherBrowserDoesNotRedirectToTheClient(t *testing.T) {
	h, sm, mockFB, _ := testHandlers(t)
	realisticFirebase(mockFB)
	registerAttacker(t, sm)
	mockFB.signInWithIdpFunc = func(ctx context.Context, requestURI, postBody, sessionID, providerID string) (*firebase.SignInWithIdpResponse, error) {
		return nil, assert.AnError
	}
	attacker := startSignIn(t, h, authQuery(attackerClient, attackerRedirect, "s", attackerVerifier))
	assertRefused(t, callbackIn(h, attacker.fb))
}

func TestCallback_UnsupportedMFAFromAnotherBrowserIsRefusedToo(t *testing.T) {
	h, sm, mockFB, mr := testHandlers(t)
	realisticFirebase(mockFB)
	mockFB.signInWithIdpFunc = func(ctx context.Context, requestURI, postBody, sessionID, providerID string) (*firebase.SignInWithIdpResponse, error) {
		return nil, &firebase.MFAUnsupportedError{}
	}
	s := startSignIn(t, h, authQuery(victimClient, victimRedirect, "s", victimVerifier))
	assertRefused(t, callbackIn(h, s.fb))
	assert.Empty(t, storedTxs(t, sm, mr))
}

// ===== MFA steps fail closed when the transaction is gone =====

// expireTransactions removes every OAuth transaction, as their TTL would.
func expireTransactions(t *testing.T, sm *state.Manager, mr *miniredis.Miniredis) {
	t.Helper()
	for txID := range storedTxs(t, sm, mr) {
		_, err := sm.ConsumeOAuthState(context.Background(), txID)
		require.NoError(t, err)
	}
	require.Empty(t, storedTxs(t, sm, mr))
}

// With the transaction expired there is no browser to compare the request to,
// so the MFA challenge shows nothing about the account to anyone, with or
// without a cookie, and the MFA session is dropped.
func TestMFA_ChallengeAfterTheTransactionExpiredShowsNoIdentity(t *testing.T) {
	for name, withCookie := range map[string]bool{"no cookie": false, "the owner's cookie": true} {
		t.Run(name, func(t *testing.T) {
			h, sm, mockFB, mr := testHandlers(t)
			tmpl, err := template.ParseGlob("../../../templates/*.html")
			require.NoError(t, err)
			h.templates = tmpl
			realisticFirebase(mockFB)
			withMFA(mockFB)
			owner := startSignIn(t, h, authQuery(victimClient, victimRedirect, "s", victimVerifier))
			session := mfaSessionOf(t, callbackFor(h, owner))
			expireTransactions(t, sm, mr)

			var cookies []*http.Cookie
			if withCookie {
				cookies = owner.cookies
			}
			w := mfaChallengeIn(h, session, cookies...)
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.NotContains(t, w.Body.String(), "user@example.com", "the account's email is not shown")
			assert.NotContains(t, w.Body.String(), `name="code"`, "no challenge form")
			assert.Contains(t, w.Body.String(), "start the sign-in again")
			got, _ := sm.GetMFASession(context.Background(), session)
			assert.Nil(t, got, "the MFA session is cleaned up")
		})
	}
}

func TestMFA_ChallengeWithoutAnMFASessionShowsNoChallenge(t *testing.T) {
	h, _, _, _ := testHandlers(t)
	w := mfaChallengeIn(h, "no-such-session")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMFA_VerifyAfterTheTransactionExpiredDoesNothing(t *testing.T) {
	for name, withCookie := range map[string]bool{"no cookie": false, "the owner's cookie": true} {
		t.Run(name, func(t *testing.T) {
			h, sm, mockFB, mr := testHandlers(t)
			realisticFirebase(mockFB)
			finalized := withMFA(mockFB)
			owner := startSignIn(t, h, authQuery(victimClient, victimRedirect, "s", victimVerifier))
			session := mfaSessionOf(t, callbackFor(h, owner))
			expireTransactions(t, sm, mr)

			var cookies []*http.Cookie
			if withCookie {
				cookies = owner.cookies
			}
			w := mfaVerifyIn(h, session, cookies...)
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Equal(t, "invalid_request", audDecode(t, w)["error"])
			assert.NotContains(t, w.Body.String(), "redirect_url")
			assert.Zero(t, finalized.Load(), "the provider is never contacted")
			attempts, _ := sm.GetMFAAttemptCount(context.Background(), session)
			assert.Zero(t, attempts, "no attempt is counted")
			got, _ := sm.GetMFASession(context.Background(), session)
			assert.Nil(t, got, "the MFA session is cleaned up")
			assert.Zero(t, issuedCodes(mr))
		})
	}
}
