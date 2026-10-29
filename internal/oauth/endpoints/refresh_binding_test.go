package endpoints

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func refreshFormFor(refresh, clientID string) url.Values {
	f := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}
	if clientID != "" {
		f.Set("client_id", clientID)
	}
	return f
}

// signInAs runs a whole authorization for the victim's client and returns the
// tokens its code was exchanged for.
func signInAs(t *testing.T, h *Handlers) (access, refresh string) {
	t.Helper()
	fb := firebaseStateOf(t, browserAuthorize(t, h, authQuery(victimClient, victimRedirect, "s", victimVerifier)))
	w := callbackFor(h, fb)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	w = audPostToken(t, h, tokenForm(loc.Query().Get("code"), victimClient, victimRedirect, victimVerifier))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	resp := audDecode(t, w)
	return resp["access_token"].(string), resp["refresh_token"].(string)
}

func TestRefresh_TokensAreBoundToTheClientTheCodeWasIssuedTo(t *testing.T) {
	h, sm, mockFB, _ := testHandlers(t)
	realisticFirebase(mockFB)
	ctx := context.Background()
	access, refresh := signInAs(t, h)

	at, _ := sm.GetAccessTokenData(ctx, access)
	rt, _ := sm.GetRefreshTokenData(ctx, refresh)
	require.NotNil(t, at)
	require.NotNil(t, rt)
	assert.Equal(t, victimClient, at.ClientID)
	assert.Equal(t, victimClient, rt.ClientID)

	// The same client refreshes, again and again; the binding survives rotation.
	for i := 0; i < 2; i++ {
		w := audPostToken(t, h, refreshFormFor(refresh, victimClient))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		resp := audDecode(t, w)
		refresh = resp["refresh_token"].(string)
		rt, _ = sm.GetRefreshTokenData(ctx, refresh)
		require.NotNil(t, rt)
		assert.Equal(t, victimClient, rt.ClientID)
	}
}

func TestRefresh_AnotherClientIsRefusedWithInvalidGrant(t *testing.T) {
	h, sm, mockFB, _ := testHandlers(t)
	realisticFirebase(mockFB)
	ctx := context.Background()
	registerAttacker(t, sm)
	access, refresh := signInAs(t, h)

	w := audPostToken(t, h, refreshFormFor(refresh, attackerClient))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, ErrInvalidGrant, audDecode(t, w)["error"])
	assert.NotContains(t, w.Body.String(), victimClient, "the error does not say which client the token belongs to")

	// The token family is revoked: a stolen refresh token gets one try.
	rt, _ := sm.GetRefreshTokenData(ctx, refresh)
	assert.Nil(t, rt)
	at, _ := sm.GetAccessTokenData(ctx, access)
	assert.Nil(t, at)
	w = audPostToken(t, h, refreshFormFor(refresh, victimClient))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRefresh_MissingClientIDOnABoundTokenIsAcceptedAndStaysBound(t *testing.T) {
	// A client that omits client_id on refresh keeps working (refusing would
	// sign it out every day), and the rotated token keeps its binding, so a
	// wrong client_id is still refused afterwards.
	h, sm, mockFB, _ := testHandlers(t)
	realisticFirebase(mockFB)
	_, refresh := signInAs(t, h)

	w := audPostToken(t, h, refreshFormFor(refresh, ""))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	next := audDecode(t, w)["refresh_token"].(string)
	rt, _ := sm.GetRefreshTokenData(context.Background(), next)
	require.NotNil(t, rt)
	assert.Equal(t, victimClient, rt.ClientID, "binding kept through rotation")

	w = audPostToken(t, h, refreshFormFor(next, attackerClient))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, ErrInvalidGrant, audDecode(t, w)["error"])
}

// Refresh tokens already in Redis have no client_id. Users signed in with them
// are not signed out: the first refresh is accepted and binds the token.
func TestRefresh_LegacyTokenIsAcceptedAndStamped(t *testing.T) {
	h, sm, _, _ := testHandlers(t)
	ctx := context.Background()
	require.NoError(t, sm.StoreRefreshToken(ctx, state.NewRefreshTokenData("legacy-rt", "legacy-at", "user", "fb-refresh", "limacharlie:read")))

	w := audPostToken(t, h, refreshFormFor("legacy-rt", victimClient))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	next := audDecode(t, w)["refresh_token"].(string)
	rt, _ := sm.GetRefreshTokenData(ctx, next)
	require.NotNil(t, rt)
	assert.Equal(t, victimClient, rt.ClientID)

	w = audPostToken(t, h, refreshFormFor(next, attackerClient))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRefresh_LegacyTokenWithoutClientIDStillWorks(t *testing.T) {
	h, sm, _, _ := testHandlers(t)
	require.NoError(t, sm.StoreRefreshToken(context.Background(), state.NewRefreshTokenData("legacy-rt2", "legacy-at", "user", "fb-refresh", "limacharlie:read")))
	w := audPostToken(t, h, refreshFormFor("legacy-rt2", ""))
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestRefresh_OversizedClientIDIsRejected(t *testing.T) {
	h, sm, _, _ := testHandlers(t)
	require.NoError(t, sm.StoreRefreshToken(context.Background(), state.NewRefreshTokenData("legacy-rt3", "legacy-at", "user", "fb-refresh", "limacharlie:read")))
	w := audPostToken(t, h, refreshFormFor("legacy-rt3", strings.Repeat("c", 5000)))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, ErrInvalidRequest, audDecode(t, w)["error"])
	rt, _ := sm.GetRefreshTokenData(context.Background(), "legacy-rt3")
	assert.NotNil(t, rt, "nothing stored or rotated")
}
