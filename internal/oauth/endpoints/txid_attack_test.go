package endpoints

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/firebase"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two clients of the transaction-collision attack. The victim uses the
// allow-listed first-party client; the attacker registers their own client with
// a redirect URI they control.
const (
	victimClient     = "test-client"
	victimRedirect   = "https://app.example.com/callback"
	victimVerifier   = "victim-verifier-1234567890123456789012345678901"
	attackerClient   = "mcp_attacker"
	attackerRedirect = "https://attacker.example.net/cb"
	attackerVerifier = "attacker-verifier-123456789012345678901234567"
)

// realisticFirebase makes the mock behave like Firebase: every auth URI carries
// a fresh state and session, and the sign-in result identifies the account that
// went through that session.
func realisticFirebase(mock *mockFirebaseClient) {
	var n atomic.Int64
	mock.createAuthURIFunc = func(ctx context.Context, provider, continueURI string, scopes []string) (string, string, error) {
		i := n.Add(1)
		return fmt.Sprintf("fb-session-%d", i), fmt.Sprintf("https://firebase.example.com/auth?state=fb-state-%d", i), nil
	}
	mock.signInWithIdpFunc = func(ctx context.Context, requestURI, postBody, sessionID, providerID string) (*firebase.SignInWithIdpResponse, error) {
		return &firebase.SignInWithIdpResponse{
			LocalID:      "uid-of-" + sessionID,
			IDToken:      "id-token-of-" + sessionID,
			RefreshToken: "refresh-token-of-" + sessionID,
			ExpiresIn:    "3600",
		}, nil
	}
}

func registerAttacker(t *testing.T, sm *state.Manager) {
	t.Helper()
	require.NoError(t, sm.StoreClientRegistration(context.Background(),
		state.NewClientRegistration(attackerClient, "Attacker App", []string{attackerRedirect})))
}

func authQuery(clientID, redirect, clientState, verifier string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"state":                 {clientState},
		"code_challenge":        {generatePKCEChallenge(verifier)},
		"code_challenge_method": {"S256"},
		"scope":                 {"limacharlie:read"},
		"provider":              {"google"},
	}
}

// firebaseStateOf is the state a browser sent to the identity provider.
func firebaseStateOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "firebase.example.com", loc.Host, "the browser is sent to the identity provider")
	return loc.Query().Get("state")
}

func callbackFor(h *Handlers, firebaseState string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.HandleCallback(w, httptest.NewRequest(http.MethodGet, "/oauth/callback?state="+url.QueryEscape(firebaseState)+"&code=idp-code", nil))
	return w
}

func tokenForm(code, clientID, redirect, verifier string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	}
}

// ATTACK: the victim starts /authorize (client A, state S); the attacker starts
// /authorize with the same state S for their own client B and PKCE verifier.
// Before the fix the transaction was keyed by S, so the second request replaced
// the first, the victim's sign-in completed against the attacker's transaction,
// the victim's authorization code went to the attacker's redirect URI, and the
// attacker redeemed it with their own verifier.
func TestAuthorize_SameClientStateDoesNotHijackAnotherTransaction(t *testing.T) {
	h, sm, mockFB, _ := testHandlers(t)
	realisticFirebase(mockFB)
	registerAttacker(t, sm)
	const sharedState = "S-the-same-for-both"

	victimFB := firebaseStateOf(t, browserAuthorize(t, h, authQuery(victimClient, victimRedirect, sharedState, victimVerifier)))
	attackerFB := firebaseStateOf(t, browserAuthorize(t, h, authQuery(attackerClient, attackerRedirect, sharedState, attackerVerifier)))
	require.NotEqual(t, victimFB, attackerFB)

	// The victim finishes signing in.
	w := callbackFor(h, victimFB)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "app.example.com", loc.Host, "the victim's code goes to the victim's client, never to the attacker's redirect")
	assert.Equal(t, sharedState, loc.Query().Get("state"), "the client's own state is echoed back")
	victimCode := loc.Query().Get("code")
	require.NotEmpty(t, victimCode)

	// The victim's client redeems it for the victim's account; nobody else can.
	w = audPostToken(t, h, tokenForm(victimCode, victimClient, victimRedirect, victimVerifier))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	at, err := sm.GetAccessTokenData(context.Background(), audDecode(t, w)["access_token"].(string))
	require.NoError(t, err)
	require.NotNil(t, at)
	assert.Equal(t, "uid-of-fb-session-1", at.UID, "the token is for the account that signed in")
	w = audPostToken(t, h, tokenForm(victimCode, attackerClient, attackerRedirect, attackerVerifier))
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// The attacker's own flow still works, for their own account.
	w = callbackFor(h, attackerFB)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err = url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "attacker.example.net", loc.Host)
}

// The same attack on the MFA path: the transaction is only consumed when the
// challenge is verified, which leaves a longer window.
func TestAuthorize_SameClientStateDoesNotHijackTheMFAPath(t *testing.T) {
	h, sm, mockFB, _ := testHandlers(t)
	realisticFirebase(mockFB)
	registerAttacker(t, sm)
	mockFB.signInWithIdpFunc = func(ctx context.Context, requestURI, postBody, sessionID, providerID string) (*firebase.SignInWithIdpResponse, error) {
		return nil, &firebase.MFARequiredError{
			MFAPendingCredential: "pending-" + sessionID, MFAEnrollmentID: "enroll", DisplayName: "User",
			LocalID: "uid-of-" + sessionID, Email: "user@example.com", PendingToken: "pt",
		}
	}
	mockFB.finalizeMFASignInFunc = func(ctx context.Context, pending, enrollment, code string) (*firebase.FinalizeMFAResponse, error) {
		return &firebase.FinalizeMFAResponse{
			LocalID: "uid-of-" + strings.TrimPrefix(pending, "pending-"), IDToken: "id-token", RefreshToken: "rt", ExpiresIn: "3600",
		}, nil
	}
	const sharedState = "S-mfa"

	victimFB := firebaseStateOf(t, browserAuthorize(t, h, authQuery(victimClient, victimRedirect, sharedState, victimVerifier)))
	w := callbackFor(h, victimFB)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	mfaURL, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/oauth/mfa-challenge", mfaURL.Path)
	mfaSession := mfaURL.Query().Get("session")

	// While the victim types the code, the attacker starts a flow with the same state.
	_ = firebaseStateOf(t, browserAuthorize(t, h, authQuery(attackerClient, attackerRedirect, sharedState, attackerVerifier)))

	vw := httptest.NewRecorder()
	h.HandleMFAVerify(vw, httptest.NewRequest(http.MethodPost, "/oauth/mfa-verify", nil), mfaSession, "123456")
	require.Equal(t, http.StatusOK, vw.Code, vw.Body.String())
	redirect, err := url.Parse(audDecode(t, vw)["redirect_url"].(string))
	require.NoError(t, err)
	assert.Equal(t, "app.example.com", redirect.Host)
	assert.Equal(t, sharedState, redirect.Query().Get("state"))

	w = audPostToken(t, h, tokenForm(redirect.Query().Get("code"), victimClient, victimRedirect, victimVerifier))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// The client's state is opaque data: whatever it holds, it comes back exactly
// as sent and decides nothing about where the transaction lives.
func TestAuthorize_ClientStateIsOpaqueData(t *testing.T) {
	states := map[string]string{
		"special characters":    `a b&c=d/+?#%20"'<>\;{}[]`,
		"unicode":               "état-日本語-🔐",
		"looks like a key":      "oauth:state:other",
		"looks like a firebase": "fb-state-1",
		"very long":             strings.Repeat("s", 4000),
	}
	for name, clientState := range states {
		t.Run(name, func(t *testing.T) {
			h, sm, mockFB, mr := testHandlers(t)
			realisticFirebase(mockFB)

			fb := firebaseStateOf(t, browserAuthorize(t, h, authQuery(victimClient, victimRedirect, clientState, victimVerifier)))
			txID, tx := onlyTx(t, sm, mr)
			assert.Equal(t, clientState, tx.State)
			assert.NotEqual(t, clientState, txID)
			assert.NotContains(t, txID, "oauth", "the id is random, not derived from the state")

			w := callbackFor(h, fb)
			require.Equal(t, http.StatusFound, w.Code, w.Body.String())
			loc, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, clientState, loc.Query().Get("state"), "echoed unchanged")
		})
	}
}

func TestAuthorize_SameStateForDifferentClientsIsFine(t *testing.T) {
	h, sm, mockFB, mr := testHandlers(t)
	realisticFirebase(mockFB)
	registerAttacker(t, sm)

	a := firebaseStateOf(t, browserAuthorize(t, h, authQuery(victimClient, victimRedirect, "same", victimVerifier)))
	b := firebaseStateOf(t, browserAuthorize(t, h, authQuery(attackerClient, attackerRedirect, "same", attackerVerifier)))
	// The same client reusing a state (a retry, a buggy client) is just another transaction.
	c := firebaseStateOf(t, browserAuthorize(t, h, authQuery(victimClient, victimRedirect, "same", victimVerifier)))

	txs := storedTxs(t, sm, mr)
	assert.Len(t, txs, 3, "three independent transactions")
	for _, fb := range []string{a, b, c} {
		w := callbackFor(h, fb)
		assert.Equal(t, http.StatusFound, w.Code, w.Body.String())
	}
}

// A state that happens to equal the id of a live transaction reaches nothing.
func TestAuthorize_StateEqualToALiveTransactionIDChangesNothing(t *testing.T) {
	h, sm, mockFB, mr := testHandlers(t)
	realisticFirebase(mockFB)
	registerAttacker(t, sm)

	victimFB := firebaseStateOf(t, browserAuthorize(t, h, authQuery(victimClient, victimRedirect, "victim-state", victimVerifier)))
	victimTx, before := onlyTx(t, sm, mr)

	_ = firebaseStateOf(t, browserAuthorize(t, h, authQuery(attackerClient, attackerRedirect, victimTx, attackerVerifier)))

	after, err := sm.GetOAuthState(context.Background(), victimTx)
	require.NoError(t, err)
	require.NotNil(t, after)
	assert.Equal(t, *before, *after, "the victim's transaction is untouched")
	w := callbackFor(h, victimFB)
	require.Equal(t, http.StatusFound, w.Code)
	loc, _ := url.Parse(w.Header().Get("Location"))
	assert.Equal(t, "app.example.com", loc.Host)
}

// A Firebase state that is already in use must not take over the mappings of the
// login that owns it: the second login fails, and leaves nothing behind.
func TestAuthorize_FirebaseStateAlreadyInUseFailsTheSecondLogin(t *testing.T) {
	h, sm, _, mr := testHandlers(t)
	// The default mock hands out the same Firebase state every time.
	first := firebaseStateOf(t, browserAuthorize(t, h, authQuery(victimClient, victimRedirect, "one", victimVerifier)))
	require.Equal(t, "firebase-state-123", first)

	w := browserAuthorize(t, h, authQuery(victimClient, victimRedirect, "two", victimVerifier))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Len(t, storedTxs(t, sm, mr), 1, "the failed login's transaction is abandoned")

	cb := callbackFor(h, first)
	require.Equal(t, http.StatusFound, cb.Code)
	loc, _ := url.Parse(cb.Header().Get("Location"))
	assert.Equal(t, "one", loc.Query().Get("state"), "the first login is intact")
}

// Failures after the transaction is stored abandon it.
func TestAuthorize_ProviderFailureLeavesNoTransaction(t *testing.T) {
	h, sm, mockFB, mr := testHandlers(t)
	mockFB.createAuthURIFunc = func(ctx context.Context, provider, continueURI string, scopes []string) (string, string, error) {
		return "", "", assert.AnError
	}
	w := browserAuthorize(t, h, authQuery(victimClient, victimRedirect, "s", victimVerifier))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, storedTxs(t, sm, mr))

	mockFB.createAuthURIFunc = func(ctx context.Context, provider, continueURI string, scopes []string) (string, string, error) {
		return "sess", "https://firebase.example.com/auth?no=state", nil
	}
	w = browserAuthorize(t, h, authQuery(victimClient, victimRedirect, "s", victimVerifier))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, storedTxs(t, sm, mr))
}

// Transactions in flight when this code is deployed were keyed by the client's
// state, and their provider mappings point at that key. They finish normally.
func TestCallback_TransactionStartedByTheOldVersionStillCompletes(t *testing.T) {
	h, sm, _, mr := testHandlers(t)
	ctx := context.Background()
	// The old version wrote the transaction under the client's state, with no tx id.
	data := fmt.Sprintf(`{"state":"legacy-client-state","code_challenge":%q,"code_challenge_method":"S256","redirect_uri":%q,"client_id":%q,"scope":"limacharlie:read","resource":"","provider":"google.com","created_at":1}`,
		generatePKCEChallenge(victimVerifier), victimRedirect, victimClient)
	require.NoError(t, mr.Set(state.StatePrefix+"legacy-client-state", data))
	mr.SetTTL(state.StatePrefix+"legacy-client-state", 10*time.Minute)
	require.NoError(t, sm.CreateSelectionSession(ctx, "oauth:state:legacy-fb", map[string]string{"oauth_state": "legacy-client-state"}))
	require.NoError(t, sm.CreateSelectionSession(ctx, "oauth:fbsession:legacy-fb", map[string]string{"session_id": "legacy-sess"}))

	w := callbackFor(h, "legacy-fb")
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, _ := url.Parse(w.Header().Get("Location"))
	assert.Equal(t, "app.example.com", loc.Host)
	assert.Equal(t, "legacy-client-state", loc.Query().Get("state"))
	assert.NotEmpty(t, loc.Query().Get("code"))
}
