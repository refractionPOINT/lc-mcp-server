package token

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/refractionpoint/lc-mcp-go/internal/redis/faultproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// The tests do not wait for the production backoff between revocation tries.
	mismatchRevokeBackoff = time.Millisecond
}

// isRevokeScript recognises the script that revokes a token's grant: it touches
// the token's access record and tombstone, unlike a claim, and not the family
// record, unlike a publish (which names the rotation record, as the revocation
// does too, to find the grant of a rotated token).
func isRevokeScript(r faultproxy.Request) bool {
	return r.IsScript() && r.HasKeyPrefix(state.RevokedTokenPrefix) && r.HasKeyPrefix(state.TokenPrefix) &&
		r.HasKeyPrefix(state.RefreshClaimPrefix) && !r.HasKeyPrefix(state.FamilyPrefix)
}

// isFamilyMarkerWrite recognises the plain write of a family's revoked marker.
func isFamilyMarkerWrite(r faultproxy.Request) bool {
	return r.Name() == "SET" && len(r.Args) > 1 && strings.HasPrefix(r.Args[1], state.RevokedFamilyPrefix)
}

// ===== A claim that ran out is not a dead grant =====

// A refresh that outlives its claim, with nobody else touching the token, is
// told to retry: the token was neither rotated nor revoked, and the same token
// refreshes fine afterwards. It must not be reported as a dead grant, which
// makes the endpoint answer invalid_grant and signs the user out.
func TestClaimExpiry_AnAttemptThatOutlivesItsClaimIsRetryableNotDead(t *testing.T) {
	stateManager, mr := setupTestStateManager(t)
	fb := newMockFirebaseClient()
	m := NewManager(stateManager, fb, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
	ctx := context.Background()
	issued := issueFor(t, m, clientA)

	var slow atomic.Bool
	slow.Store(true)
	fb.refreshIDTokenFunc = func(context.Context, string) (string, int64, error) {
		if slow.CompareAndSwap(true, false) {
			mr.FastForward(state.RefreshClaimTTL + time.Second) // Firebase was slow
		}
		return validFirebaseResult()
	}

	got, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.False(t, IsDeadRefresh(err), "nobody rotated or revoked the token; this must not be invalid_grant: %v", err)
	assert.ErrorIs(t, err, ErrRefreshClaimLost)

	old, _ := stateManager.GetRefreshTokenData(ctx, issued.RefreshToken)
	assert.NotNil(t, old, "the token is intact")
	again, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, err, "the same token refreshes fine")
	assert.True(t, usable(t, m, again.AccessToken))
}

// A claim that another attempt took over, but that has not rotated the token,
// is no proof of anything either.
func TestClaimExpiry_ATakenOverClaimThatHasNotRotatedIsRetryable(t *testing.T) {
	stateManager, mr := setupTestStateManager(t)
	fb := newMockFirebaseClient()
	m := NewManager(stateManager, fb, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
	ctx := context.Background()
	issued := issueFor(t, m, clientA)

	var calls atomic.Int32
	var second refreshResult
	fb.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		if calls.Add(1) == 1 {
			mr.FastForward(state.RefreshClaimTTL + time.Second)
			// The client's retry takes the claim over, and fails (Firebase is
			// down for it): it rotates nothing.
			second.resp, second.err = m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
			return validFirebaseResult()
		}
		return "", 0, errors.New("firebase unavailable")
	}

	_, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.Error(t, err)
	assert.False(t, IsDeadRefresh(err), "the other attempt failed and rotated nothing: %v", err)
	assert.False(t, IsDeadRefresh(second.err))
}

// ===== A committed rotation whose reply was lost =====

// With the production client policy, if every reply to a committed publish is
// lost the endpoint can only answer 503, and the old token is gone. The retry
// with the same token from the same client must get the successors the first
// attempt committed: not invalid_grant, and not a second family.
func TestRefreshGrace_ALostPublishReplyIsRecoveredByARetryOfTheSameToken(t *testing.T) {
	env := newFaultEnv(t, 0)
	ctx := context.Background()
	issued := issueFor(t, env.direct, clientA)

	env.proxy.OnReply(func(r faultproxy.Request, rep faultproxy.Reply) faultproxy.Verdict {
		if isPublish(r) && !rep.IsError() {
			return faultproxy.DropReply() // every reply, so the client library gives up
		}
		return faultproxy.Pass()
	})
	got, err := env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.False(t, IsDeadRefresh(err), "the endpoint answers 503: %v", err)
	env.proxy.Reset()

	old, _ := env.sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	require.Nil(t, old, "the rotation committed: the old token is gone, and is not restored")

	recovered, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, err, "the retry must get what the committed rotation issued")
	assert.True(t, usable(t, env.direct, recovered.AccessToken))
	assert.Len(t, liveTokenKeys(env.mr), 2, "one generation: a recovery mints nothing")

	again, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, err)
	assert.Equal(t, recovered.AccessToken, again.AccessToken, "the same pair every time")
	assert.Equal(t, recovered.RefreshToken, again.RefreshToken)
	assert.Equal(t, "openid", recovered.Scope)

	next, err := env.direct.RefreshAccessToken(ctx, recovered.RefreshToken, clientA, nil)
	require.NoError(t, err, "and the client carries on with it")
	assert.True(t, usable(t, env.direct, next.AccessToken))
}

func TestRefreshGrace_Conditions(t *testing.T) {
	ctx := context.Background()
	rotate := func(t *testing.T, resolve ResourceResolver) (*Manager, *state.Manager, *faultEnv, *TokenResponse, *TokenResponse) {
		env := newFaultEnv(t, 0)
		issued := issueFor(t, env.direct, clientA)
		first, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, resolve)
		require.NoError(t, err)
		return env.direct, env.sm, env, issued, first
	}

	t.Run("the same client gets the same pair; no client_id keeps the binding", func(t *testing.T) {
		m, _, _, issued, first := rotate(t, nil)
		for _, client := range []string{clientA, ""} {
			again, err := m.RefreshAccessToken(ctx, issued.RefreshToken, client, nil)
			require.NoError(t, err)
			assert.Equal(t, first.AccessToken, again.AccessToken)
			assert.Equal(t, first.RefreshToken, again.RefreshToken)
		}
	})

	t.Run("another client gets nothing and the grant is revoked", func(t *testing.T) {
		m, sm, env, issued, first := rotate(t, nil)
		got, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
		assert.ErrorIs(t, err, ErrClientMismatch)
		assert.Nil(t, got)
		assert.False(t, usable(t, m, first.AccessToken))
		rt, _ := sm.GetRefreshTokenData(ctx, first.RefreshToken)
		assert.Nil(t, rt)
		assert.Empty(t, liveTokenKeys(env.mr))
	})

	t.Run("outside the window the token is unknown", func(t *testing.T) {
		m, _, env, issued, _ := rotate(t, nil)
		env.mr.FastForward(state.RotationRecordTTL + time.Second)
		_, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
		assert.ErrorIs(t, err, ErrRefreshTokenUnknown)
		assert.True(t, IsDeadRefresh(err))
	})

	t.Run("once the client used the successors the old token yields nothing", func(t *testing.T) {
		m, _, _, issued, first := rotate(t, nil)
		_, err := m.RefreshAccessToken(ctx, first.RefreshToken, clientA, nil)
		require.NoError(t, err)
		got, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
		assert.ErrorIs(t, err, ErrRefreshTokenUnknown)
		assert.Nil(t, got)
	})

	t.Run("a revoked grant gets nothing", func(t *testing.T) {
		m, _, _, issued, first := rotate(t, nil)
		require.NoError(t, m.RevokeToken(ctx, first.RefreshToken, "refresh_token"))
		got, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
		assert.Error(t, err)
		assert.True(t, IsDeadRefresh(err))
		assert.Nil(t, got)
	})

	t.Run("a resource narrowing is honoured, never widened", func(t *testing.T) {
		narrow := func(authorized string) (string, error) { return "https://mcp.example/narrow", nil }
		m, _, env, issued, first := rotate(t, narrow)
		again, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, narrow)
		require.NoError(t, err)
		assert.Equal(t, first.RefreshToken, again.RefreshToken)
		res, err := m.ValidateAccessToken(ctx, again.AccessToken, false)
		require.NoError(t, err)
		assert.Equal(t, "https://mcp.example/narrow", res.Resource)

		other := func(authorized string) (string, error) { return "https://mcp.example/other", nil }
		got, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, other)
		assert.ErrorIs(t, err, ErrInvalidTarget, "the tokens were issued for another resource")
		assert.Nil(t, got)
		refuse := func(string) (string, error) { return "", ErrInvalidTarget }
		_, err = m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, refuse)
		assert.ErrorIs(t, err, ErrInvalidTarget)
		assert.Len(t, liveTokenKeys(env.mr), 2, "nothing was minted or revoked by the refusals")
	})
}

// ===== Revoking after a client mismatch =====

// If the revocation keeps failing, the wrong client's request gets a retryable
// backend error (and no tokens), and the grant is still revoked, so the owner's
// next refresh cannot succeed on a token a thief has shown up with.
func TestMismatchRevocation_AFailingRevocationFallsBackToTheFamilyMarker(t *testing.T) {
	env := newFaultEnv(t, -1)
	ctx := context.Background()
	issued := issueFor(t, env.direct, clientA)
	env.proxy.OnRequest(isRevokeScript)

	got, err := env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
	assert.Nil(t, got)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClientMismatch, "the grant is revoked through the marker; the answer for the wrong client is unchanged")
	env.proxy.Reset()

	assert.False(t, usable(t, env.direct, issued.AccessToken), "the access token must be dead")
	_, err = env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.Error(t, err, "the owner's next refresh must not succeed on a token that was shown to a thief")
	assert.True(t, IsDeadRefresh(err))
}

// When even the marker cannot be written, nothing is confirmed: the wrong
// client gets a retryable error and no tokens, and the refresh claim is kept so
// that no other refresh of the token succeeds meanwhile.
func TestMismatchRevocation_WhenNothingCanBeRevokedNobodyRefreshesMeanwhile(t *testing.T) {
	env := newFaultEnv(t, -1)
	ctx := context.Background()
	issued := issueFor(t, env.direct, clientA)
	env.proxy.OnRequest(func(r faultproxy.Request) bool { return isRevokeScript(r) || isFamilyMarkerWrite(r) })

	got, err := env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
	assert.Nil(t, got)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrClientMismatch), "a revocation that is not confirmed is not reported as done")
	assert.False(t, IsDeadRefresh(err), "a backend error: the wrong client retries")
	env.proxy.Reset()

	again, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	assert.Nil(t, again, "the claim is kept: nobody refreshes before the revocation is confirmed")
	assert.ErrorIs(t, err, ErrRefreshInFlight)

	// Presented again by the wrong client once the claim ran out and Redis is
	// back: the revocation is retried and goes through.
	env.mr.FastForward(state.RefreshClaimTTL + time.Second)
	_, err = env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
	assert.ErrorIs(t, err, ErrClientMismatch)
	assert.False(t, usable(t, env.direct, issued.AccessToken))
}

// A revocation that fails once is retried in the request.
func TestMismatchRevocation_ATransientFailureIsRetriedInTheRequest(t *testing.T) {
	env := newFaultEnv(t, -1)
	ctx := context.Background()
	issued := issueFor(t, env.direct, clientA)
	var failed atomic.Bool
	env.proxy.OnRequest(func(r faultproxy.Request) bool {
		return isRevokeScript(r) && failed.CompareAndSwap(false, true)
	})

	_, err := env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
	assert.ErrorIs(t, err, ErrClientMismatch)
	require.True(t, failed.Load(), "the first revocation attempt failed")
	assert.False(t, usable(t, env.direct, issued.AccessToken))
	assert.Empty(t, liveTokenKeys(env.mr), "the full revocation went through on the retry")
}
