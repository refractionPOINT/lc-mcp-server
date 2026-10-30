package state

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FenceFamily holds the grant's current refresh token for a revocation that may
// not complete: the token's claim is set to the revocation fence, whoever owns it.

func TestFenceFamily_HoldsTheCurrentRefreshToken(t *testing.T) {
	ctx := context.Background()
	m, mr := setupTestManager(t)
	issueGrant(t, m, "fam", "at", "rt")
	recordBefore, _ := mr.Get(RefreshPrefix + "rt")

	fenced, err := m.FenceFamily(ctx, "fam")
	require.NoError(t, err)
	assert.True(t, fenced)

	key := RefreshClaimPrefix + tokenHash("rt")
	v, err := mr.Get(key)
	require.NoError(t, err)
	assert.Equal(t, revocationFence, v)
	assert.InDelta(t, RefreshClaimTTL.Seconds(), mr.TTL(key).Seconds(), 2, "it ends on its own, like any claim")

	recordAfter, _ := mr.Get(RefreshPrefix + "rt")
	assert.Equal(t, recordBefore, recordAfter, "a fence is a claim, not a revocation: the token is untouched")

	claim, err := m.ClaimRefreshToken(ctx, "rt")
	assert.Nil(t, claim)
	assert.ErrorIs(t, err, ErrRefreshInFlight, "nobody starts a refresh on a fenced token")
}

// The point of the fence over a claim: a refresh that is already running on the
// token owns its claim, and the fence takes it away. The refresh can then publish
// nothing, is told the token is intact (it may retry), and its own cleanup and
// late commands cannot give the fence up.
func TestFenceFamily_ReplacesTheClaimOfARefreshInFlight(t *testing.T) {
	ctx := context.Background()
	m, mr := setupTestManager(t)
	issueGrant(t, m, "fam", "at", "rt")

	claim, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err)
	key := RefreshClaimPrefix + tokenHash("rt")
	require.Equal(t, claim.Owner, mustGet(t, mr, key))

	fenced, err := m.FenceFamily(ctx, "fam")
	require.NoError(t, err)
	assert.True(t, fenced)
	assert.Equal(t, revocationFence, mustGet(t, mr, key), "the fence replaced the owner")

	err = m.PublishRotation(ctx, claim, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam"))
	assert.ErrorIs(t, err, ErrClaimLost, "the refresh in flight can no longer publish")
	assert.NotErrorIs(t, err, ErrAlreadyRotated)
	assert.NotErrorIs(t, err, ErrTokenRevoked, "and it is not told the grant is dead: nothing revoked it")
	assert.False(t, exists(mr, TokenPrefix+"at-1"), "nothing was published")
	assert.False(t, exists(mr, RefreshPrefix+"rt-1"), "nothing was published")
	assert.True(t, exists(mr, RefreshPrefix+"rt", TokenPrefix+"at"), "the token is intact")

	t.Run("the cleanup of the refresh that lost its claim leaves the fence alone", func(t *testing.T) {
		m.ReleaseRefreshClaim(ctx, claim)
		assert.Equal(t, revocationFence, mustGet(t, mr, key))
	})

	t.Run("a late copy of that refresh's claim does not take the token back", func(t *testing.T) {
		_, err := m.claimAs(ctx, "rt", claim.Owner)
		assert.ErrorIs(t, err, ErrRefreshInFlight)
		assert.Equal(t, revocationFence, mustGet(t, mr, key))
	})

	t.Run("its retry meets the fence until the fence ends", func(t *testing.T) {
		_, err := m.ClaimRefreshToken(ctx, "rt")
		assert.ErrorIs(t, err, ErrRefreshInFlight)

		mr.FastForward(RefreshClaimTTL + time.Second)
		retry, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err, "a fence that was not followed by a revocation does not lock the token for good")
		require.NoError(t, m.PublishRotation(ctx, retry, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam")))
	})
}

func mustGet(t *testing.T, mr *miniredis.Miniredis, key string) string {
	t.Helper()
	v, err := mr.Get(key)
	require.NoError(t, err)
	return v
}

// The token held is the grant's current one, found by the script from the
// family record: a successor that was rotated away in the meantime is not held
// (nothing would be), its own successor is.
func TestFenceFamily_FollowsTheGrantToItsCurrentRefreshToken(t *testing.T) {
	ctx := context.Background()
	m, mr := setupTestManager(t)
	issueGrant(t, m, "fam", "at", "rt")
	claim, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err)
	require.NoError(t, m.PublishRotation(ctx, claim, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam")))
	next, err := m.ClaimRefreshToken(ctx, "rt-1")
	require.NoError(t, err)
	require.NoError(t, m.PublishRotation(ctx, next, newAccess("at-2", "fam"), newRefresh("rt-2", "at-2", "fam")))

	fenced, err := m.FenceFamily(ctx, "fam")
	require.NoError(t, err)
	assert.True(t, fenced)
	assert.Equal(t, revocationFence, mustGet(t, mr, RefreshClaimPrefix+tokenHash("rt-2")))
	assert.False(t, exists(mr, RefreshClaimPrefix+tokenHash("rt")), "no stray claim on a token that is gone")
	assert.False(t, exists(mr, RefreshClaimPrefix+tokenHash("rt-1")), "no stray claim on a token that is gone")

	got, err := m.RotationSuccessors(ctx, "rt-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.SuccessorClaimed, "grace recovery sees the fence and hands nothing out")
}

func TestFenceFamily_NothingToHold(t *testing.T) {
	ctx := context.Background()

	t.Run("a revoked grant", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		require.NoError(t, m.MarkFamilyRevoked(ctx, "fam")) // the marker alone: the family record is still there
		before := snapshot(mr)

		fenced, err := m.FenceFamily(ctx, "fam")
		require.NoError(t, err)
		assert.False(t, fenced)
		assert.Equal(t, before, snapshot(mr), "nothing is written for a grant that is dead already")
	})

	t.Run("a grant that is not on record", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		before := snapshot(mr)

		fenced, err := m.FenceFamily(ctx, "unknown")
		require.NoError(t, err)
		assert.False(t, fenced)
		assert.Equal(t, before, snapshot(mr))
	})

	t.Run("a family record that names no refresh token, or is not a hash", func(t *testing.T) {
		m, mr := setupTestManager(t)
		mr.HSet(FamilyPrefix+"no-rt", "at", "at-x")
		require.NoError(t, mr.Set(FamilyPrefix+"junk", "not a hash"))
		before := snapshot(mr)

		for _, fam := range []string{"no-rt", "junk"} {
			fenced, err := m.FenceFamily(ctx, fam)
			require.NoError(t, err, fam)
			assert.False(t, fenced, fam)
		}
		assert.Equal(t, before, snapshot(mr))
	})

	t.Run("no family at all is an error: there is nothing to name", func(t *testing.T) {
		m, _ := setupTestManager(t)
		fenced, err := m.FenceFamily(ctx, "")
		assert.Error(t, err)
		assert.False(t, fenced)
	})
}

// A command that arrives twice (a reply lost, the Redis client sending it again)
// finds the fence in place and writes the same thing.
func TestFenceFamily_ARepeatIsHarmless(t *testing.T) {
	ctx := context.Background()
	m, mr := setupTestManager(t)
	issueGrant(t, m, "fam", "at", "rt")

	for i := 0; i < 3; i++ {
		fenced, err := m.FenceFamily(ctx, "fam")
		require.NoError(t, err)
		assert.True(t, fenced)
	}
	key := RefreshClaimPrefix + tokenHash("rt")
	assert.Equal(t, revocationFence, mustGet(t, mr, key))

	mr.FastForward(RefreshClaimTTL - 10*time.Second)
	_, err := m.FenceFamily(ctx, "fam")
	require.NoError(t, err)
	assert.InDelta(t, RefreshClaimTTL.Seconds(), mr.TTL(key).Seconds(), 2, "a repeat renews the fence: the revocation it covers is still unconfirmed")
}

// A confirmed revocation takes the fence away with the grant; a grant that is
// only marked revoked leaves it to end on its own, and refuses everything anyway.
func TestFenceFamily_ARevocationOutlastsTheFence(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*Manager, *RefreshClaim) {
		m, _ := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		_, err = m.FenceFamily(ctx, "fam")
		require.NoError(t, err)
		return m, claim
	}
	key := RefreshClaimPrefix + tokenHash("rt")

	t.Run("the refresh that lost its claim is dead once the grant is revoked", func(t *testing.T) {
		m, claim := setup(t)
		_, err := m.RevokeToken(ctx, "rt")
		require.NoError(t, err)
		assert.ErrorIs(t, m.PublishRotation(ctx, claim, newAccess("n", "fam"), newRefresh("nr", "n", "fam")), ErrTokenRevoked)
	})

	t.Run("the fence goes with the grant", func(t *testing.T) {
		for name, revoke := range map[string]func(*Manager) error{
			"RevokeToken": func(m *Manager) error { _, err := m.RevokeToken(ctx, "rt"); return err },
			"RevokeTokenInFamily": func(m *Manager) error {
				_, err := m.RevokeTokenInFamily(ctx, "rt", "fam")
				return err
			},
			"RevokeFamily": func(m *Manager) error { return m.RevokeFamily(ctx, "fam") },
		} {
			t.Run(name, func(t *testing.T) {
				m, mr := setupTestManager(t)
				issueGrant(t, m, "fam", "at", "rt")
				_, err := m.FenceFamily(ctx, "fam")
				require.NoError(t, err)
				require.True(t, exists(mr, key))

				require.NoError(t, revoke(m))
				assert.False(t, exists(mr, key), "the claim key goes with the grant's current tokens")
				assert.False(t, exists(mr, RefreshPrefix+"rt"))
			})
		}
	})

	t.Run("a marked grant refuses everything whatever the fence", func(t *testing.T) {
		m, claim := setup(t)
		require.NoError(t, m.MarkFamilyRevoked(ctx, "fam"))

		_, err := m.ClaimRefreshToken(ctx, "rt")
		assert.ErrorIs(t, err, ErrTokenRevoked, "dead, not merely in flight")
		assert.ErrorIs(t, m.PublishRotation(ctx, claim, newAccess("n", "fam"), newRefresh("nr", "n", "fam")), ErrTokenRevoked)
	})
}
