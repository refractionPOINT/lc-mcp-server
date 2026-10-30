package token

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/refractionpoint/lc-mcp-go/internal/redis/faultproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests are about the hold a client mismatch in the refresh grace window
// puts on the grant before it revokes it (see revokeAfterReplayMismatch). The
// rotated token has no claim of its own to keep, so the hold is placed on the
// grant's current refresh token, whoever holds its claim and whatever the network
// does to the command that places it.

// isHold recognises the command that holds the grant's current refresh token while
// the rotated token presented is handled as a mismatch: a script that is neither
// the revocation nor the claim every refresh starts with on the token it was
// handed (which finds the token rotated away and goes on to grace recovery).
func isHold(presented string) func(faultproxy.Request) bool {
	own := state.RefreshPrefix + presented
	return func(r faultproxy.Request) bool {
		if !r.IsScript() || isRevokeScript(r) {
			return false
		}
		for _, k := range r.Keys() {
			if k == own {
				return false
			}
		}
		return true
	}
}

// requireHeld checks the grant is held: nothing refreshes the successor, grace
// hands out nothing, no new generation exists, and the hold ends on its own.
func requireHeld(t *testing.T, env *faultEnv, issued, successors *TokenResponse) {
	t.Helper()
	ctx := context.Background()
	env.proxy.Reset()

	again, err := env.direct.RefreshAccessToken(ctx, successors.RefreshToken, clientA, nil)
	assert.Nil(t, again, "the successor must not be refreshable while the revocation is unconfirmed")
	assert.ErrorIs(t, err, ErrRefreshInFlight)

	// The live path and grace recovery both refuse: the wrong client may be a thief
	// trying client ids, and the owner must not be handed anything meanwhile.
	pair, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	assert.Nil(t, pair, "grace must not answer while a revocation is pending")
	assert.ErrorIs(t, err, ErrRefreshInFlight)

	rt, _ := env.sm.GetRefreshTokenData(ctx, successors.RefreshToken)
	assert.NotNil(t, rt, "the successor refresh token is untouched: the hold is not a revocation")
	assert.Len(t, liveTokenKeys(env.mr), 2, "one generation: nothing was published")

	// The hold is temporary: it is the claim, which ends on its own.
	env.mr.FastForward(state.RefreshClaimTTL + time.Second)
	next, err := env.direct.RefreshAccessToken(ctx, successors.RefreshToken, clientA, nil)
	require.NoError(t, err, "a failed revocation must not lock the owner out for good")
	assert.True(t, usable(t, env.direct, next.AccessToken))
}

// The successor is being refreshed by its owner when the rotated token is
// presented by another client, and nothing can be revoked: not the grant, and not
// the family marker. The owner's refresh must not be able to publish usable
// successors meanwhile (it used to: its claim was in the way of the hold, so the
// revocation went ahead without one).
func TestGraceMismatchFence_ARefreshInFlightCannotPublishWhenNothingCanBeRevoked(t *testing.T) {
	ctx := context.Background()
	env, issued, first := graceMismatchEnv(t) // the proxy fails the revocation and the marker

	ownerFB := newMockFirebaseClient()
	owner := NewManager(env.sm, ownerFB, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
	var thiefResp *TokenResponse
	var thiefErr error
	ownerFB.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		// The owner's refresh of the successor is in flight when the rotated token
		// is presented by another client.
		thiefResp, thiefErr = env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
		return validFirebaseResult()
	}

	got, err := owner.RefreshAccessToken(ctx, first.RefreshToken, clientA, nil)

	assert.Nil(t, thiefResp)
	require.Error(t, thiefErr)
	assert.False(t, errors.Is(thiefErr, ErrClientMismatch), "a revocation that is not confirmed is not reported as done")
	assert.False(t, IsDeadRefresh(thiefErr), "a backend error: the wrong client retries")

	assert.Nil(t, got, "the refresh in flight published successors although the revocation could not be confirmed")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRefreshClaimLost, "retryable: the legitimate user is not signed out by a revocation that did not happen")
	assert.False(t, IsDeadRefresh(err))

	requireHeld(t, env, issued, first)
}

// The same, when the revocation falls back to the family marker: the grant is
// revoked, so the refresh in flight is dead.
func TestGraceMismatchFence_ARefreshInFlightIsDeadOnceTheMarkerLands(t *testing.T) {
	ctx := context.Background()
	env := newFaultEnv(t, -1)
	issued := issueFor(t, env.direct, clientA)
	first, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, err)
	env.proxy.OnRequest(isRevokeScript) // the marker write goes through

	ownerFB := newMockFirebaseClient()
	owner := NewManager(env.sm, ownerFB, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
	var thiefErr error
	ownerFB.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		_, thiefErr = env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
		return validFirebaseResult()
	}

	got, err := owner.RefreshAccessToken(ctx, first.RefreshToken, clientA, nil)
	assert.ErrorIs(t, thiefErr, ErrClientMismatch)
	assert.Nil(t, got)
	require.Error(t, err)
	assert.True(t, IsDeadRefresh(err), "the grant is revoked: %v", err)
	assert.False(t, usable(t, env.direct, first.AccessToken))
}

// A hold whose reply is lost on the way back is a hold all the same. The generic
// claim used to be given up when its reply failed to arrive, which left the
// successor idle and refreshable the moment the revocation failed too.
func TestGraceMismatchFence_ALostReplyOnTheHoldDoesNotReleaseIt(t *testing.T) {
	ctx := context.Background()
	env, issued, first := graceMismatchEnv(t) // the proxy fails the revocation and the marker

	// The hold runs, its reply is lost, and (no retries) the caller only sees a
	// failure.
	hold := isHold(issued.RefreshToken)
	var dropped atomic.Bool
	env.proxy.OnReply(func(r faultproxy.Request, rep faultproxy.Reply) faultproxy.Verdict {
		if hold(r) && !rep.IsError() && dropped.CompareAndSwap(false, true) {
			return faultproxy.DropReply()
		}
		return faultproxy.Pass()
	})

	got, err := env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
	require.True(t, dropped.Load(), "the reply of the hold was lost")
	assert.Nil(t, got)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrClientMismatch), "a revocation that is not confirmed is not reported as done")
	assert.False(t, IsDeadRefresh(err), "a backend error: the wrong client retries")

	requireHeld(t, env, issued, first)
}

// Both at once: the successor is being refreshed by its owner and the reply of the
// hold is lost. The hold ran, so the owner's claim is gone and it publishes
// nothing, all the same.
func TestGraceMismatchFence_ALostReplyOnTheHoldOfARefreshInFlightStillFencesItOut(t *testing.T) {
	ctx := context.Background()
	env, issued, first := graceMismatchEnv(t) // the proxy fails the revocation and the marker
	hold := isHold(issued.RefreshToken)
	var dropped atomic.Bool
	env.proxy.OnReply(func(r faultproxy.Request, rep faultproxy.Reply) faultproxy.Verdict {
		if hold(r) && !rep.IsError() && dropped.CompareAndSwap(false, true) {
			return faultproxy.DropReply()
		}
		return faultproxy.Pass()
	})

	ownerFB := newMockFirebaseClient()
	owner := NewManager(env.sm, ownerFB, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
	var thiefErr error
	ownerFB.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		_, thiefErr = env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
		return validFirebaseResult()
	}

	got, err := owner.RefreshAccessToken(ctx, first.RefreshToken, clientA, nil)
	require.True(t, dropped.Load(), "the reply of the hold was lost")
	require.Error(t, thiefErr)
	assert.False(t, IsDeadRefresh(thiefErr))

	assert.Nil(t, got, "the refresh in flight published successors")
	assert.ErrorIs(t, err, ErrRefreshClaimLost)
	requireHeld(t, env, issued, first)
}

// A reply lost once, with the production retry policy, is invisible: the client
// library sends the same command again and a repeated hold changes nothing. The
// mismatch is then revoked normally and leaves no hold behind.
func TestGraceMismatchFence_ARepeatedHoldIsHarmless(t *testing.T) {
	ctx := context.Background()
	env := newFaultEnv(t, 0)
	issued := issueFor(t, env.direct, clientA)
	first, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, err)

	hold := isHold(issued.RefreshToken)
	var dropped atomic.Bool
	env.proxy.OnReply(func(r faultproxy.Request, rep faultproxy.Reply) faultproxy.Verdict {
		if hold(r) && !rep.IsError() && dropped.CompareAndSwap(false, true) {
			return faultproxy.DropReply()
		}
		return faultproxy.Pass()
	})

	_, err = env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
	require.True(t, dropped.Load())
	assert.ErrorIs(t, err, ErrClientMismatch)
	assert.False(t, usable(t, env.direct, first.AccessToken))
	assert.Empty(t, liveTokenKeys(env.mr))
	for _, k := range env.mr.Keys() {
		assert.NotContains(t, k, state.RefreshClaimPrefix, "a confirmed revocation leaves no hold behind")
	}
}

// A hold that cannot be placed does not stop the revocation: it is still what
// the mismatch calls for, and the hold is only the fallback for when it fails.
func TestGraceMismatchFence_AHoldThatCannotBePlacedDoesNotStopTheRevocation(t *testing.T) {
	ctx := context.Background()
	env := newFaultEnv(t, -1)
	issued := issueFor(t, env.direct, clientA)
	first, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, err)

	hold := isHold(issued.RefreshToken)
	var lost atomic.Bool
	env.proxy.OnRequest(func(r faultproxy.Request) bool {
		return hold(r) && lost.CompareAndSwap(false, true) // the hold never arrives
	})

	_, err = env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
	require.True(t, lost.Load(), "the hold was lost")
	assert.ErrorIs(t, err, ErrClientMismatch, "the revocation went ahead and was confirmed")
	assert.False(t, usable(t, env.direct, first.AccessToken))
	assert.Empty(t, liveTokenKeys(env.mr))
}

// When the hold, the revocation and the marker all fail, nothing is changed and
// the wrong client is told to retry. (Nothing can be guaranteed then: no write of
// the protection landed. See revokeAfterReplayMismatch.)
func TestGraceMismatchFence_WhenEveryProtectiveWriteFailsNothingIsChangedAndTheRequestIsRetryable(t *testing.T) {
	ctx := context.Background()
	env := newFaultEnv(t, -1)
	issued := issueFor(t, env.direct, clientA)
	first, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, err)
	before := len(env.mr.Keys())
	hold := isHold(issued.RefreshToken)
	env.proxy.OnRequest(func(r faultproxy.Request) bool { return hold(r) || isRevokeScript(r) || isFamilyMarkerWrite(r) })

	got, err := env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
	assert.Nil(t, got)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrClientMismatch))
	assert.False(t, IsDeadRefresh(err))
	env.proxy.Reset()

	assert.Equal(t, before, len(env.mr.Keys()), "no write landed")
	assert.True(t, usable(t, env.direct, first.AccessToken))
	// With Redis back, the next presentation completes the revocation.
	_, err = env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
	assert.ErrorIs(t, err, ErrClientMismatch)
	assert.False(t, usable(t, env.direct, first.AccessToken))
}

// The claim of an owner that was fenced out does not come back when the owner
// cleans up after itself: the cleanup only drops a claim that is its own.
func TestGraceMismatchFence_TheOwnersCleanupLeavesTheHoldAlone(t *testing.T) {
	ctx := context.Background()
	env, issued, first := graceMismatchEnv(t)

	ownerFB := newMockFirebaseClient()
	owner := NewManager(env.sm, ownerFB, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
	ownerFB.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		_, _ = env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
		return "", 0, errors.New("firebase unavailable") // the owner fails and cleans up
	}
	_, err := owner.RefreshAccessToken(ctx, first.RefreshToken, clientA, nil)
	require.Error(t, err)

	requireHeld(t, env, issued, first)
}
