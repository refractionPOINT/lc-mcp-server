package endpoints

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A refresh that outlives its claim on the token rotated nothing and revoked
// nothing: the client is told to retry (503 server_error), not that its grant is
// dead (invalid_grant signs the user out), and the same token then works.
func TestRefreshEndpoint_AClaimThatRanOutIsRetryableNotInvalidGrant(t *testing.T) {
	h, _, mockFB, mr := testHandlers(t)
	realisticFirebase(mockFB)
	_, refresh := signInAs(t, h)

	var slow atomic.Bool
	slow.Store(true)
	mockFB.refreshIDTokenFunc = func(context.Context, string) (string, int64, error) {
		if slow.CompareAndSwap(true, false) {
			mr.FastForward(state.RefreshClaimTTL + time.Second)
		}
		return "id", time.Now().Add(time.Hour).Unix(), nil
	}

	w := audPostToken(t, h, refreshFormFor(refresh, victimClient))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
	assert.Equal(t, ErrServerError, audDecode(t, w)["error"])

	w = audPostToken(t, h, refreshFormFor(refresh, victimClient))
	require.Equal(t, http.StatusOK, w.Code, "the same refresh token works afterwards: %s", w.Body.String())
}

// A retry of an already rotated refresh token by the same client, right after,
// gets the same tokens back (refresh grace); another client does not.
func TestRefreshEndpoint_ARetryOfARotatedTokenGetsTheSameTokensInTheGraceWindow(t *testing.T) {
	h, _, mockFB, _ := testHandlers(t)
	realisticFirebase(mockFB)
	_, refresh := signInAs(t, h)

	first := audPostToken(t, h, refreshFormFor(refresh, victimClient))
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	want := audDecode(t, first)

	retry := audPostToken(t, h, refreshFormFor(refresh, victimClient))
	require.Equal(t, http.StatusOK, retry.Code, retry.Body.String())
	got := audDecode(t, retry)
	assert.Equal(t, want["access_token"], got["access_token"])
	assert.Equal(t, want["refresh_token"], got["refresh_token"])

	other := audPostToken(t, h, refreshFormFor(refresh, "some-other-client"))
	assert.Equal(t, http.StatusBadRequest, other.Code)
	assert.Equal(t, ErrInvalidGrant, audDecode(t, other)["error"])
}
