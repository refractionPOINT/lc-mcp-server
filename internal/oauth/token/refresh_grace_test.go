package token

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/refractionpoint/lc-mcp-go/internal/redis/faultproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests are about the refresh grace window: what revocation and a client
// mismatch do while a just-rotated refresh token is still accepted, and what a
// request gets whose token another request rotated.

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// nearlyExpired makes a token (its record and its token->grant index, which are
// written together and last as long as each other) look like it is about to end
// its lifetime, the way a token does at the end of its 30 days.
func nearlyExpired(mr *miniredis.Miniredis, recordKey, token string, left time.Duration) {
	mr.SetTTL(recordKey, left)
	mr.SetTTL(state.TokenFamilyPrefix+sha256Hex(token), left)
}

// ===== Revoking a token that grace still accepts =====

// A token near the end of its life is rotated. The rotation record lasts two
// minutes, so grace still hands out the successors after the old token's own
// lifetime is over. /revoke of that token, and a wrong client presenting it, must
// still reach the grant: they used to find neither the record nor the index and
// do nothing, with the successors left usable.
func TestGraceRevocation_ATokenThatGraceStillAcceptsStillLeadsToItsGrant(t *testing.T) {
	ctx := context.Background()

	// rotated returns an environment where the old tokens have just been
	// rotated while 1 s of their own lifetime was left, and 2 s have passed.
	rotated := func(t *testing.T) (*faultEnv, *TokenResponse, *TokenResponse) {
		t.Helper()
		env := newFaultEnv(t, 0)
		issued := issueFor(t, env.direct, clientA)
		nearlyExpired(env.mr, state.RefreshPrefix+issued.RefreshToken, issued.RefreshToken, time.Second)
		nearlyExpired(env.mr, state.TokenPrefix+issued.AccessToken, issued.AccessToken, time.Second)
		first, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
		require.NoError(t, err)
		env.mr.FastForward(2 * time.Second)

		// Precondition: grace still works for the old refresh token.
		again, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
		require.NoError(t, err, "grace must still accept the rotated token")
		require.Equal(t, first.RefreshToken, again.RefreshToken)
		require.True(t, usable(t, env.direct, first.AccessToken))
		return env, issued, first
	}
	requireGrantDead := func(t *testing.T, env *faultEnv, issued, successors *TokenResponse) {
		t.Helper()
		assert.False(t, usable(t, env.direct, successors.AccessToken), "the successors survived the revocation")
		rt, _ := env.sm.GetRefreshTokenData(ctx, successors.RefreshToken)
		assert.Nil(t, rt, "the successor refresh token survived the revocation")
		_, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
		assert.True(t, IsDeadRefresh(err), "grace must not hand out a revoked grant: %v", err)
		assert.Empty(t, liveTokenKeys(env.mr))
	}

	t.Run("/revoke of the rotated refresh token revokes the grant", func(t *testing.T) {
		env, issued, first := rotated(t)
		require.NoError(t, env.direct.RevokeToken(ctx, issued.RefreshToken, "refresh_token"))
		requireGrantDead(t, env, issued, first)
	})

	t.Run("/revoke of the rotated access token revokes the grant", func(t *testing.T) {
		env, issued, first := rotated(t)
		require.NoError(t, env.direct.RevokeToken(ctx, issued.AccessToken, "access_token"))
		requireGrantDead(t, env, issued, first)
	})

	t.Run("a wrong client presenting the rotated refresh token revokes the grant", func(t *testing.T) {
		env, issued, first := rotated(t)
		got, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
		assert.Nil(t, got)
		require.ErrorIs(t, err, ErrClientMismatch)
		requireGrantDead(t, env, issued, first)
	})
}

// ===== A mismatch whose revocation cannot be confirmed, during grace =====

// graceMismatchEnv has a grant rotated once, the reply "lost", and the proxy
// failing both the revocation script and the family marker write: nothing can be
// revoked.
func graceMismatchEnv(t *testing.T) (*faultEnv, *TokenResponse, *TokenResponse) {
	t.Helper()
	env := newFaultEnv(t, -1)
	issued := issueFor(t, env.direct, clientA)
	first, err := env.direct.RefreshAccessToken(context.Background(), issued.RefreshToken, clientA, nil)
	require.NoError(t, err)
	env.proxy.OnRequest(func(r faultproxy.Request) bool { return isRevokeScript(r) || isFamilyMarkerWrite(r) })
	return env, issued, first
}

// When the revocation after a mismatch cannot be confirmed, the wrong client gets
// a retryable error, and, as on the live path, nobody refreshes meanwhile: the
// owner must not be able to refresh the successor as if nothing had happened.
func TestGraceMismatch_WhenNothingCanBeRevokedNobodyRefreshesMeanwhile(t *testing.T) {
	ctx := context.Background()
	env, issued, first := graceMismatchEnv(t)

	got, err := env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
	assert.Nil(t, got)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrClientMismatch), "a revocation that is not confirmed is not reported as done")
	assert.False(t, IsDeadRefresh(err), "a backend error: the wrong client retries")
	env.proxy.Reset()

	again, err := env.direct.RefreshAccessToken(ctx, first.RefreshToken, clientA, nil)
	assert.Nil(t, again, "the successor must not be refreshable before the revocation is confirmed")
	assert.ErrorIs(t, err, ErrRefreshInFlight)

	// Nor does grace hand the pair to anybody who names the right client: the
	// wrong client may be a thief trying client ids.
	pair, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	assert.Nil(t, pair, "grace must not answer while a revocation is pending")
	assert.ErrorIs(t, err, ErrRefreshInFlight)

	// The wrong client coming back with Redis healthy completes the revocation.
	_, err = env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
	assert.ErrorIs(t, err, ErrClientMismatch)
	assert.False(t, usable(t, env.direct, first.AccessToken))
	assert.Empty(t, liveTokenKeys(env.mr))
}

// The block is temporary: it is the claim, which ends on its own.
func TestGraceMismatch_TheBlockEndsWithTheClaim(t *testing.T) {
	ctx := context.Background()
	env, issued, first := graceMismatchEnv(t)

	_, err := env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
	require.Error(t, err)
	env.proxy.Reset()
	_, err = env.direct.RefreshAccessToken(ctx, first.RefreshToken, clientA, nil)
	require.ErrorIs(t, err, ErrRefreshInFlight)

	env.mr.FastForward(state.RefreshClaimTTL + time.Second)
	next, err := env.direct.RefreshAccessToken(ctx, first.RefreshToken, clientA, nil)
	require.NoError(t, err, "a failed revocation must not lock the owner out for good")
	assert.True(t, usable(t, env.direct, next.AccessToken))
	_, err = env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	assert.ErrorIs(t, err, ErrRefreshTokenUnknown, "and grace is over for the old token")
}

// With the full revocation failing but the family marker landing, the grant is
// revoked, as on the live path.
func TestGraceMismatch_AFailingRevocationFallsBackToTheFamilyMarker(t *testing.T) {
	ctx := context.Background()
	env := newFaultEnv(t, -1)
	issued := issueFor(t, env.direct, clientA)
	first, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, err)
	env.proxy.OnRequest(isRevokeScript)

	got, err := env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, ErrClientMismatch)
	env.proxy.Reset()

	assert.False(t, usable(t, env.direct, first.AccessToken))
	_, err = env.direct.RefreshAccessToken(ctx, first.RefreshToken, clientA, nil)
	require.Error(t, err)
	assert.True(t, IsDeadRefresh(err))
}

// The fence on the successor is a fallback for when the revocation fails: if the
// successor is being refreshed already, the fence takes the claim from that
// refresh, and the mismatch still revokes the grant, so the refresh in flight
// publishes nothing and is told the grant is revoked. (When the revocation fails
// too, the refresh in flight is only fenced out: see revocation_fence_test.go.)
func TestGraceMismatch_ARefreshOfTheSuccessorInFlightIsRevokedToo(t *testing.T) {
	ctx := context.Background()
	stateManager, mr := setupTestStateManager(t)
	fb := newMockFirebaseClient()
	m := NewManager(stateManager, fb, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
	issued := issueFor(t, m, clientA)
	first, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, err)

	var thiefErr error
	fb.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		// The owner's refresh of the successor is in flight when the rotated
		// token is presented by another client.
		_, thiefErr = m.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
		return validFirebaseResult()
	}
	got, err := m.RefreshAccessToken(ctx, first.RefreshToken, clientA, nil)

	assert.ErrorIs(t, thiefErr, ErrClientMismatch)
	assert.Nil(t, got, "the refresh in flight publishes nothing for a revoked grant")
	assert.ErrorIs(t, err, ErrRefreshRevoked)
	assert.False(t, usable(t, m, first.AccessToken))
	assert.Empty(t, liveTokenKeys(mr))
}

// A confirmed revocation leaves no claim behind.
func TestGraceMismatch_AConfirmedRevocationLeavesNothing(t *testing.T) {
	ctx := context.Background()
	env := newFaultEnv(t, 0)
	issued := issueFor(t, env.direct, clientA)
	first, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, err)

	_, err = env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
	require.ErrorIs(t, err, ErrClientMismatch)
	assert.False(t, usable(t, env.direct, first.AccessToken))
	assert.Empty(t, liveTokenKeys(env.mr))
	for _, k := range env.mr.Keys() {
		assert.NotContains(t, k, state.RefreshClaimPrefix, "no refresh claim is left behind")
	}
}

// ===== A claim takeover does not sign the slower request out =====

// slowThenRetried runs a refresh of rt that is slow: its claim runs out and the
// client's retry takes the token over. during runs in the retry's place, with the
// retry's result; the slow refresh returns afterwards.
func slowThenRetried(t *testing.T, m *Manager, mr *miniredis.Miniredis, fb *mockFirebaseClient, rt string,
	slowResolve, retryResolve ResourceResolver, slowClient, retryClient string, during func(retry *TokenResponse)) (*TokenResponse, error, *TokenResponse, error) {
	t.Helper()
	ctx := context.Background()
	var calls atomic.Int32
	var retry *TokenResponse
	var retryErr error
	fb.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		if calls.Add(1) == 1 {
			mr.FastForward(state.RefreshClaimTTL + time.Second) // Firebase was slow
			retry, retryErr = m.RefreshAccessToken(ctx, rt, retryClient, retryResolve)
			if retryErr == nil && during != nil {
				during(retry)
			}
		}
		return validFirebaseResult()
	}
	slow, slowErr := m.RefreshAccessToken(ctx, rt, slowClient, slowResolve)
	return slow, slowErr, retry, retryErr
}

// A refresh whose claim ran out and was taken over by its own retry is not a dead
// grant: the retry rotated the token, and an immediate retry of the slow request
// would get the retry's successors through grace. The slow request gets them too.
func TestClaimTakeover_TheSlowerRequestIsHandedTheSuccessorsOfTheOneThatTookOver(t *testing.T) {
	stateManager, mr := setupTestStateManager(t)
	fb := newMockFirebaseClient()
	m := NewManager(stateManager, fb, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
	issued := issueFor(t, m, clientA)

	slow, slowErr, retry, retryErr := slowThenRetried(t, m, mr, fb, issued.RefreshToken, nil, nil, clientA, clientA, nil)
	require.NoError(t, retryErr, "the retry owns the token now")
	require.NoError(t, slowErr, "the slow request must not be signed out: its retry got the successors through grace")
	assert.Equal(t, retry.AccessToken, slow.AccessToken, "the same pair, nothing minted")
	assert.Equal(t, retry.RefreshToken, slow.RefreshToken)
	assert.True(t, usable(t, m, slow.AccessToken))
	assert.Len(t, liveTokenKeys(mr), 2, "one generation, not two families")
}

// The recovery is the normal checked one: the client the slow request names is
// checked against the binding.
func TestClaimTakeover_TheSlowerRequestIsChecked(t *testing.T) {
	t.Run("the client moved on: the successors were used, so it is dead", func(t *testing.T) {
		stateManager, mr := setupTestStateManager(t)
		fb := newMockFirebaseClient()
		m := NewManager(stateManager, fb, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
		issued := issueFor(t, m, clientA)

		var next *TokenResponse
		slow, slowErr, retry, retryErr := slowThenRetried(t, m, mr, fb, issued.RefreshToken, nil, nil, clientA, clientA, func(retry *TokenResponse) {
			var err error
			next, err = m.RefreshAccessToken(context.Background(), retry.RefreshToken, clientA, nil)
			require.NoError(t, err, "the client carries on with what the retry was given")
		})
		require.NoError(t, retryErr)
		require.NotNil(t, retry)
		assert.Nil(t, slow)
		require.Error(t, slowErr)
		assert.ErrorIs(t, slowErr, ErrRefreshSuperseded)
		assert.True(t, IsDeadRefresh(slowErr))
		assert.True(t, usable(t, m, next.AccessToken), "and it is not the slow request that breaks the client's grant")
	})

	t.Run("the grant was revoked meanwhile: dead", func(t *testing.T) {
		stateManager, mr := setupTestStateManager(t)
		fb := newMockFirebaseClient()
		m := NewManager(stateManager, fb, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
		issued := issueFor(t, m, clientA)

		slow, slowErr, _, retryErr := slowThenRetried(t, m, mr, fb, issued.RefreshToken, nil, nil, clientA, clientA, func(retry *TokenResponse) {
			require.NoError(t, m.RevokeToken(context.Background(), retry.RefreshToken, "refresh_token"))
		})
		require.NoError(t, retryErr)
		assert.Nil(t, slow)
		require.Error(t, slowErr)
		assert.True(t, IsDeadRefresh(slowErr))
		assert.Empty(t, liveTokenKeys(mr))
	})

	t.Run("the resource the slow request asked for is not the one that was issued", func(t *testing.T) {
		stateManager, mr := setupTestStateManager(t)
		fb := newMockFirebaseClient()
		m := NewManager(stateManager, fb, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
		issued := issueFor(t, m, clientA)
		slowRes := func(string) (string, error) { return "https://mcp.example/a", nil }
		retryRes := func(string) (string, error) { return "https://mcp.example/b", nil }

		slow, slowErr, _, retryErr := slowThenRetried(t, m, mr, fb, issued.RefreshToken, slowRes, retryRes, clientA, clientA, nil)
		require.NoError(t, retryErr)
		assert.Nil(t, slow)
		assert.ErrorIs(t, slowErr, ErrInvalidTarget)
	})

	t.Run("the same resource is handed back", func(t *testing.T) {
		stateManager, mr := setupTestStateManager(t)
		fb := newMockFirebaseClient()
		m := NewManager(stateManager, fb, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
		issued := issueFor(t, m, clientA)
		res := func(string) (string, error) { return "https://mcp.example/a", nil }

		slow, slowErr, retry, retryErr := slowThenRetried(t, m, mr, fb, issued.RefreshToken, res, res, clientA, clientA, nil)
		require.NoError(t, retryErr)
		require.NoError(t, slowErr)
		assert.Equal(t, retry.RefreshToken, slow.RefreshToken)
	})

	t.Run("a legacy token taken over by another client: the binding is enforced and the grant revoked", func(t *testing.T) {
		stateManager, mr := setupTestStateManager(t)
		fb := newMockFirebaseClient()
		m := NewManager(stateManager, fb, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
		require.NoError(t, stateManager.StoreRefreshToken(context.Background(), state.NewRefreshTokenData("legacy-rt", "legacy-at", "user", "fb-refresh", "openid")))

		// The token binds to whoever refreshes it first; the retry is another client.
		slow, slowErr, retry, retryErr := slowThenRetried(t, m, mr, fb, "legacy-rt", nil, nil, clientA, clientB, nil)
		require.NoError(t, retryErr)
		require.NotNil(t, retry)
		assert.Nil(t, slow)
		assert.ErrorIs(t, slowErr, ErrClientMismatch)
		assert.False(t, usable(t, m, retry.AccessToken), "a mismatch revokes the grant")
		assert.Empty(t, liveTokenKeys(mr))
	})
}
