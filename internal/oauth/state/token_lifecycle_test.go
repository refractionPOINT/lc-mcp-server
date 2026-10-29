package state

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRefresh(id, at, family string) *RefreshTokenData {
	rt := NewRefreshTokenData(id, at, "uid", "fb-refresh", "openid")
	rt.FamilyID = family
	rt.ClientID = "client-a"
	return rt
}

func newAccess(id, family string) *AccessTokenData {
	at := NewAccessTokenData(id, "uid", "fb-id", "fb-refresh", time.Now().Add(time.Hour).Unix(), "openid", TokenTTL)
	at.FamilyID = family
	return at
}

func TestStoreTokens_AreCreateOnly(t *testing.T) {
	m, _ := setupTestManager(t)
	ctx := context.Background()

	require.NoError(t, m.StoreAccessToken(ctx, newAccess("at", "")))
	assert.ErrorIs(t, m.StoreAccessToken(ctx, newAccess("at", "")), ErrAlreadyExists)
	require.NoError(t, m.StoreRefreshToken(ctx, newRefresh("rt", "at", "")))
	assert.ErrorIs(t, m.StoreRefreshToken(ctx, newRefresh("rt", "at", "")), ErrAlreadyExists)
}

func TestFamilyID_RoundTripsAndLegacyHasNone(t *testing.T) {
	m, _ := setupTestManager(t)
	ctx := context.Background()
	require.NoError(t, m.StoreAccessToken(ctx, newAccess("at", "fam")))
	require.NoError(t, m.StoreRefreshToken(ctx, newRefresh("rt", "at", "fam")))
	require.NoError(t, m.StoreRefreshToken(ctx, NewRefreshTokenData("legacy", "at", "uid", "fb", "openid")))

	at, _ := m.GetAccessTokenData(ctx, "at")
	rt, _ := m.GetRefreshTokenData(ctx, "rt")
	legacy, _ := m.GetRefreshTokenData(ctx, "legacy")
	assert.Equal(t, "fam", at.FamilyID)
	assert.Equal(t, "fam", rt.FamilyID)
	assert.Empty(t, legacy.FamilyID)

	revoked, err := m.IsFamilyRevoked(ctx, "")
	require.NoError(t, err)
	assert.False(t, revoked, "no family, never revoked")
}

func TestUpdateAccessToken_NeverRecreatesAndHonorsRevocation(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()

	at := newAccess("at", "fam")
	require.NoError(t, m.StoreAccessToken(ctx, at))

	t.Run("updates a live token with the intended TTL", func(t *testing.T) {
		at.FirebaseIDToken = "new-id"
		at.ExpiresAt = time.Now().Add(2 * time.Hour).Unix()
		updated, err := m.UpdateAccessToken(ctx, at)
		require.NoError(t, err)
		assert.True(t, updated)
		got, _ := m.GetAccessTokenData(ctx, "at")
		assert.Equal(t, "new-id", got.FirebaseIDToken)
		assert.InDelta(t, (2*time.Hour + TokenGracePeriod*time.Second).Seconds(), mr.TTL(TokenPrefix+"at").Seconds(), 5)
	})

	t.Run("a deleted token is not re-created", func(t *testing.T) {
		require.NoError(t, m.RevokeAccessToken(ctx, "at"))
		updated, err := m.UpdateAccessToken(ctx, at)
		require.NoError(t, err)
		assert.False(t, updated)
		got, _ := m.GetAccessTokenData(ctx, "at")
		assert.Nil(t, got)
	})

	t.Run("a revoked family is not updated", func(t *testing.T) {
		require.NoError(t, m.StoreAccessToken(ctx, newAccess("at2", "fam2")))
		require.NoError(t, m.RevokeFamily(ctx, "fam2"))
		upd := newAccess("at2", "fam2")
		upd.FirebaseIDToken = "changed"
		updated, err := m.UpdateAccessToken(ctx, upd)
		require.NoError(t, err)
		assert.False(t, updated)
		got, _ := m.GetAccessTokenData(ctx, "at2")
		require.NotNil(t, got)
		assert.Equal(t, "fb-id", got.FirebaseIDToken)
	})

	t.Run("the extend and update helpers use it", func(t *testing.T) {
		require.NoError(t, m.StoreAccessToken(ctx, newAccess("at3", "")))
		require.NoError(t, m.ExtendAccessTokenExpiration(ctx, "at3", time.Now().Add(3*time.Hour).Unix()))
		require.NoError(t, m.UpdateAccessTokenFirebaseTokens(ctx, "at3", "x", time.Now().Unix()))
		require.NoError(t, m.RevokeAccessToken(ctx, "at3"))
		assert.Error(t, m.ExtendAccessTokenExpiration(ctx, "at3", time.Now().Add(3*time.Hour).Unix()))
		assert.Error(t, m.UpdateAccessTokenFirebaseTokens(ctx, "at3", "x", time.Now().Unix()))
		got, _ := m.GetAccessTokenData(ctx, "at3")
		assert.Nil(t, got)
	})
}

func TestClaimRefreshToken(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()
	require.NoError(t, m.StoreRefreshToken(ctx, newRefresh("rt", "at", "fam")))

	claim, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err)
	require.NotNil(t, claim)
	assert.Equal(t, "fam", claim.Data.FamilyID)
	assert.Equal(t, "fb-refresh", claim.Data.FirebaseRefreshToken)
	assert.False(t, mr.Exists(RefreshPrefix+"rt"))

	inFlight, err := m.RefreshInFlight(ctx, "rt")
	require.NoError(t, err)
	assert.True(t, inFlight)

	second, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err)
	assert.Nil(t, second)

	m.ReleaseRefreshClaim(ctx, "rt")
	inFlight, _ = m.RefreshInFlight(ctx, "rt")
	assert.False(t, inFlight)
}

func TestClaimRefreshToken_ExactlyOneWinner(t *testing.T) {
	m, _ := setupTestManager(t)
	ctx := context.Background()
	require.NoError(t, m.StoreRefreshToken(ctx, newRefresh("rt", "at", "fam")))

	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := m.ClaimRefreshToken(ctx, "rt")
			assert.NoError(t, err)
			if c != nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.EqualValues(t, 1, wins.Load())
}

func TestRestoreRefreshToken(t *testing.T) {
	ctx := context.Background()

	t.Run("restores with the remaining TTL", func(t *testing.T) {
		m, mr := setupTestManager(t)
		require.NoError(t, m.StoreRefreshToken(ctx, newRefresh("rt", "at", "fam")))
		mr.FastForward(10 * 24 * time.Hour)
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		require.NotNil(t, claim)

		restored, err := m.RestoreRefreshToken(ctx, claim)
		require.NoError(t, err)
		assert.True(t, restored)
		got, _ := m.GetRefreshTokenData(ctx, "rt")
		require.NotNil(t, got)
		assert.Equal(t, "fb-refresh", got.FirebaseRefreshToken)
		assert.InDelta(t, (20 * 24 * time.Hour).Seconds(), mr.TTL(RefreshPrefix+"rt").Seconds(), 5)
	})

	t.Run("is create-only", func(t *testing.T) {
		m, _ := setupTestManager(t)
		require.NoError(t, m.StoreRefreshToken(ctx, newRefresh("rt", "at", "fam")))
		claim, _ := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, m.StoreRefreshToken(ctx, newRefresh("rt", "other-at", "fam")))
		_, err := m.RestoreRefreshToken(ctx, claim)
		assert.ErrorIs(t, err, ErrAlreadyExists)
		got, _ := m.GetRefreshTokenData(ctx, "rt")
		assert.Equal(t, "other-at", got.AccessToken)
	})

	t.Run("never restores a revoked token", func(t *testing.T) {
		m, _ := setupTestManager(t)
		require.NoError(t, m.StoreRefreshToken(ctx, newRefresh("rt", "at", "fam")))
		claim, _ := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, m.RevokeRefreshToken(ctx, "rt"))
		_, err := m.RestoreRefreshToken(ctx, claim)
		assert.ErrorIs(t, err, ErrTokenRevoked)
		got, _ := m.GetRefreshTokenData(ctx, "rt")
		assert.Nil(t, got)
	})

	t.Run("never restores a token of a revoked family", func(t *testing.T) {
		m, _ := setupTestManager(t)
		require.NoError(t, m.StoreRefreshToken(ctx, newRefresh("rt", "at", "fam")))
		claim, _ := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, m.RevokeFamily(ctx, "fam"))
		_, err := m.RestoreRefreshToken(ctx, claim)
		assert.ErrorIs(t, err, ErrTokenRevoked)
		got, _ := m.GetRefreshTokenData(ctx, "rt")
		assert.Nil(t, got)
	})
}

func TestPublishRotation(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*Manager, *RefreshClaim) {
		m, _ := setupTestManager(t)
		require.NoError(t, m.StoreAccessToken(ctx, newAccess("old-at", "fam")))
		require.NoError(t, m.StoreRefreshToken(ctx, newRefresh("rt", "old-at", "fam")))
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		require.NotNil(t, claim)
		return m, claim
	}

	t.Run("publishes both and retires the old access token", func(t *testing.T) {
		m, claim := setup(t)
		require.NoError(t, m.PublishRotation(ctx, claim, newAccess("new-at", "fam"), newRefresh("new-rt", "new-at", "fam")))
		at, _ := m.GetAccessTokenData(ctx, "new-at")
		rt, _ := m.GetRefreshTokenData(ctx, "new-rt")
		old, _ := m.GetAccessTokenData(ctx, "old-at")
		assert.NotNil(t, at)
		assert.NotNil(t, rt)
		assert.Nil(t, old)
	})

	t.Run("a revoked token publishes nothing", func(t *testing.T) {
		m, claim := setup(t)
		require.NoError(t, m.RevokeRefreshToken(ctx, "rt"))
		err := m.PublishRotation(ctx, claim, newAccess("new-at", "fam"), newRefresh("new-rt", "new-at", "fam"))
		assert.ErrorIs(t, err, ErrTokenRevoked)
		at, _ := m.GetAccessTokenData(ctx, "new-at")
		rt, _ := m.GetRefreshTokenData(ctx, "new-rt")
		assert.Nil(t, at)
		assert.Nil(t, rt)
	})

	t.Run("a revoked family publishes nothing", func(t *testing.T) {
		m, claim := setup(t)
		require.NoError(t, m.RevokeFamily(ctx, "fam"))
		err := m.PublishRotation(ctx, claim, newAccess("new-at", "fam"), newRefresh("new-rt", "new-at", "fam"))
		assert.ErrorIs(t, err, ErrTokenRevoked)
		at, _ := m.GetAccessTokenData(ctx, "new-at")
		old, _ := m.GetAccessTokenData(ctx, "old-at")
		assert.Nil(t, at)
		assert.NotNil(t, old, "nothing changes when blocked")
	})

	t.Run("an id collision publishes nothing", func(t *testing.T) {
		m, claim := setup(t)
		require.NoError(t, m.StoreRefreshToken(ctx, newRefresh("new-rt", "x", "fam")))
		err := m.PublishRotation(ctx, claim, newAccess("new-at", "fam"), newRefresh("new-rt", "new-at", "fam"))
		assert.ErrorIs(t, err, ErrAlreadyExists)
		at, _ := m.GetAccessTokenData(ctx, "new-at")
		assert.Nil(t, at)
	})
}

func TestRevokeRefreshToken_RevokesTheGrantAndOnlyTombstonesRealTokens(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()
	require.NoError(t, m.StoreAccessToken(ctx, newAccess("at", "fam")))
	require.NoError(t, m.StoreRefreshToken(ctx, newRefresh("rt", "at", "fam")))

	require.NoError(t, m.RevokeRefreshToken(ctx, "rt"))
	at, _ := m.GetAccessTokenData(ctx, "at")
	rt, _ := m.GetRefreshTokenData(ctx, "rt")
	assert.Nil(t, at)
	assert.Nil(t, rt)
	revoked, _ := m.IsFamilyRevoked(ctx, "fam")
	assert.True(t, revoked)

	before := len(mr.Keys())
	require.NoError(t, m.RevokeRefreshToken(ctx, "made-up"))
	assert.Len(t, mr.Keys(), before, "an unknown token leaves no tombstone")
}

func TestRevokeClaimedFamily(t *testing.T) {
	m, _ := setupTestManager(t)
	ctx := context.Background()
	require.NoError(t, m.StoreAccessToken(ctx, newAccess("at", "fam")))
	require.NoError(t, m.StoreRefreshToken(ctx, newRefresh("rt", "at", "fam")))
	claim, _ := m.ClaimRefreshToken(ctx, "rt")

	require.NoError(t, m.RevokeClaimedFamily(ctx, claim))
	at, _ := m.GetAccessTokenData(ctx, "at")
	assert.Nil(t, at)
	revoked, _ := m.IsFamilyRevoked(ctx, "fam")
	assert.True(t, revoked)
	_, err := m.RestoreRefreshToken(ctx, claim)
	assert.ErrorIs(t, err, ErrTokenRevoked)
}
