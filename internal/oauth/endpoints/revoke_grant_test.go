package endpoints

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func postRevoke(h *Handlers, tok, hint string) *httptest.ResponseRecorder {
	form := url.Values{"token": {tok}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.HandleRevoke(w, req)
	return w
}

func TestRevokeEndpoint_EitherTokenEndsTheGrant(t *testing.T) {
	for _, tc := range []struct{ name, hint string }{
		{"refresh token", "refresh_token"},
		{"access token", "access_token"},
		{"no hint", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, sm, mockFB, _ := testHandlers(t)
			realisticFirebase(mockFB)
			ctx := context.Background()
			access, refresh := signInAs(t, h)

			tok := refresh
			if tc.name == "access token" {
				tok = access
			}
			w := postRevoke(h, tok, tc.hint)
			assert.Equal(t, http.StatusOK, w.Code)

			at, _ := sm.GetAccessTokenData(ctx, access)
			rt, _ := sm.GetRefreshTokenData(ctx, refresh)
			assert.Nil(t, at, "the access token is gone")
			assert.Nil(t, rt, "so is the refresh token")
			w = audPostToken(t, h, refreshFormFor(refresh, victimClient))
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Equal(t, ErrInvalidGrant, audDecode(t, w)["error"])
		})
	}
}

// A client that never got the answer to its refresh still holds the old tokens;
// revoking those ends the grant, successors included.
func TestRevokeEndpoint_ARotatedAwayTokenStillEndsTheGrant(t *testing.T) {
	h, sm, mockFB, mr := testHandlers(t)
	realisticFirebase(mockFB)
	ctx := context.Background()
	oldAccess, oldRefresh := signInAs(t, h)

	w := audPostToken(t, h, refreshFormFor(oldRefresh, victimClient))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	resp := audDecode(t, w)
	newAccess, newRefresh := resp["access_token"].(string), resp["refresh_token"].(string)
	at, _ := sm.GetAccessTokenData(ctx, newAccess)
	require.NotNil(t, at)

	old, _ := sm.GetAccessTokenData(ctx, oldAccess)
	assert.Nil(t, old, "the rotation retired the old access token")

	assert.Equal(t, http.StatusOK, postRevoke(h, oldRefresh, "refresh_token").Code)

	at, _ = sm.GetAccessTokenData(ctx, newAccess)
	rt, _ := sm.GetRefreshTokenData(ctx, newRefresh)
	assert.Nil(t, at, "the successors do not outlive the revocation of the token they replaced")
	assert.Nil(t, rt)
	for _, k := range mr.Keys() {
		assert.False(t, strings.HasPrefix(k, "oauth:token:") || strings.HasPrefix(k, "oauth:refresh:"), "live credential left: %s", k)
	}
}

// RFC 7009: the answer is 200 whether or not the token existed, and asking
// about tokens nobody issued must not leave records behind.
func TestRevokeEndpoint_AnUnknownTokenIs200AndLeavesNothing(t *testing.T) {
	h, _, _, mr := testHandlers(t)
	before := len(mr.Keys())
	for i := 0; i < 10; i++ {
		w := postRevoke(h, "never-issued-"+strings.Repeat("x", i), "access_token")
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Body.String())
	}
	assert.Len(t, mr.Keys(), before)
}

// A backend failure is not an unknown token: the client must be told so that it
// retries, and the token must still be there to be revoked by the retry.
func TestRevokeEndpoint_ABackendFailureIsAServerError(t *testing.T) {
	h, sm, mockFB, mr := testHandlers(t)
	realisticFirebase(mockFB)
	ctx := context.Background()
	access, refresh := signInAs(t, h)

	mr.SetError("ERR redis is down")
	w := postRevoke(h, refresh, "refresh_token")
	mr.SetError("")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, ErrServerError, audDecode(t, w)["error"])
	assert.NotContains(t, w.Body.String(), refresh, "the answer does not echo the token")
	at, _ := sm.GetAccessTokenData(ctx, access)
	assert.NotNil(t, at, "nothing was revoked")

	w = postRevoke(h, refresh, "refresh_token")
	assert.Equal(t, http.StatusOK, w.Code)
	at, _ = sm.GetAccessTokenData(ctx, access)
	assert.Nil(t, at)
}

// Two refreshes of one token: one gets tokens, the other invalid_grant.
func TestRefreshEndpoint_TheLoserOfConcurrentRefreshesGetsInvalidGrant(t *testing.T) {
	h, sm, mockFB, _ := testHandlers(t)
	realisticFirebase(mockFB)
	_, refresh := signInAs(t, h)

	inFlight, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	mockFB.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		once.Do(func() { close(inFlight) })
		<-proceed
		return "id", time.Now().Add(time.Hour).Unix(), nil
	}

	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- audPostToken(t, h, refreshFormFor(refresh, victimClient)) }()
	<-inFlight

	loser := audPostToken(t, h, refreshFormFor(refresh, victimClient))
	assert.Equal(t, http.StatusBadRequest, loser.Code)
	assert.Equal(t, ErrInvalidGrant, audDecode(t, loser)["error"])

	close(proceed)
	winner := <-first
	require.Equal(t, http.StatusOK, winner.Code, winner.Body.String())
	next := audDecode(t, winner)["refresh_token"].(string)
	rt, _ := sm.GetRefreshTokenData(context.Background(), next)
	assert.NotNil(t, rt)
	old, _ := sm.GetRefreshTokenData(context.Background(), refresh)
	assert.Nil(t, old)
}
