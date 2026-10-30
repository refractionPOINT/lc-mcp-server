package state

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
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

// issueGrant stores a whole grant the way a sign-in does.
func issueGrant(t *testing.T, m *Manager, family, access, refresh string) {
	t.Helper()
	require.NoError(t, m.IssueTokens(context.Background(), newAccess(access, family), newRefresh(refresh, access, family)))
}

// storeLegacyGrant stores tokens as they were before families existed: records
// only, no family id, no family record, no index.
func storeLegacyGrant(t *testing.T, m *Manager, access, refresh string) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, m.StoreAccessToken(ctx, newAccess(access, "")))
	rt := newRefresh(refresh, access, "")
	rt.ClientID = ""
	require.NoError(t, m.StoreRefreshToken(ctx, rt))
}

func exists(mr *miniredis.Miniredis, keys ...string) bool {
	for _, k := range keys {
		if !mr.Exists(k) {
			return false
		}
	}
	return true
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
		require.NotNil(t, got, "no family record named it, so only the marker blocks the write")
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

// An extension keeps the token's index and its family record alive as long as
// the token, so a token can always be traced to its grant while it lives.
func TestUpdateAccessToken_KeepsIndexAndFamilyAliveAsLongAsTheToken(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()
	issueGrant(t, m, "fam", "at", "rt")
	idx := TokenFamilyPrefix + tokenHash("at")
	before := mr.TTL(idx)

	at, err := m.GetAccessTokenData(ctx, "at")
	require.NoError(t, err)
	at.ExpiresAt = time.Now().Add(40 * 24 * time.Hour).Unix()
	updated, err := m.UpdateAccessToken(ctx, at)
	require.NoError(t, err)
	require.True(t, updated)

	tokenTTL := mr.TTL(TokenPrefix + "at")
	assert.Greater(t, mr.TTL(idx), before, "the index follows the extension")
	assert.GreaterOrEqual(t, mr.TTL(idx), tokenTTL-time.Second)
	assert.GreaterOrEqual(t, mr.TTL(FamilyPrefix+"fam"), tokenTTL-time.Second)

	t.Run("a missing index is written again", func(t *testing.T) {
		mr.Del(idx)
		at.ExpiresAt = time.Now().Add(41 * 24 * time.Hour).Unix()
		updated, err := m.UpdateAccessToken(ctx, at)
		require.NoError(t, err)
		require.True(t, updated)
		assert.Equal(t, "fam", func() string { v, _ := mr.Get(idx); return v }())
		assert.GreaterOrEqual(t, mr.TTL(idx), mr.TTL(TokenPrefix+"at")-time.Second)
	})
}

// ===== Issuing =====

func TestIssueTokens(t *testing.T) {
	ctx := context.Background()

	t.Run("stores the tokens, the family record and the indices", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")

		at, _ := m.GetAccessTokenData(ctx, "at")
		rt, _ := m.GetRefreshTokenData(ctx, "rt")
		require.NotNil(t, at)
		require.NotNil(t, rt)
		assert.Equal(t, "fam", at.FamilyID)
		assert.Equal(t, "fam", rt.FamilyID)

		assert.Equal(t, "rt", mr.HGet(FamilyPrefix+"fam", "rt"))
		assert.Equal(t, tokenHash("rt"), mr.HGet(FamilyPrefix+"fam", "rth"))
		assert.Equal(t, "at", mr.HGet(FamilyPrefix+"fam", "at"))
		for _, tok := range []string{"at", "rt"} {
			v, err := mr.Get(TokenFamilyPrefix + tokenHash(tok))
			require.NoError(t, err)
			assert.Equal(t, "fam", v)
		}
	})

	t.Run("indices and the family record live at least as long as the tokens", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")

		atTTL := mr.TTL(TokenPrefix + "at")
		rtTTL := mr.TTL(RefreshPrefix + "rt")
		assert.GreaterOrEqual(t, mr.TTL(TokenFamilyPrefix+tokenHash("at")), atTTL-time.Second)
		assert.GreaterOrEqual(t, mr.TTL(TokenFamilyPrefix+tokenHash("rt")), rtTTL-time.Second)
		assert.GreaterOrEqual(t, mr.TTL(FamilyPrefix+"fam"), max(atTTL, rtTTL)-time.Second)
	})

	t.Run("is create-only", func(t *testing.T) {
		m, _ := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		err := m.IssueTokens(ctx, newAccess("at", "fam2"), newRefresh("rt-2", "at", "fam2"))
		assert.ErrorIs(t, err, ErrAlreadyExists)
		rt2, _ := m.GetRefreshTokenData(ctx, "rt-2")
		assert.Nil(t, rt2, "nothing is stored when one of the tokens exists")
		err = m.IssueTokens(ctx, newAccess("at-2", "fam2"), newRefresh("rt", "at-2", "fam2"))
		assert.ErrorIs(t, err, ErrAlreadyExists)
		at2, _ := m.GetAccessTokenData(ctx, "at-2")
		assert.Nil(t, at2)
	})

	t.Run("a repeat of the same call succeeds and changes nothing", func(t *testing.T) {
		m, mr := setupTestManager(t)
		call, err := m.prepareIssue(newAccess("at", "fam"), newRefresh("rt", "at", "fam"))
		require.NoError(t, err)
		require.NoError(t, m.issue(ctx, call))
		before := snapshot(mr)
		require.NoError(t, m.issue(ctx, call), "the Redis client repeats a command whose reply was lost")
		assert.Equal(t, before, snapshot(mr))
	})

	t.Run("a revoked family gets nothing", func(t *testing.T) {
		m, mr := setupTestManager(t)
		mr.Set(RevokedFamilyPrefix+"fam", "1")
		err := m.IssueTokens(ctx, newAccess("at", "fam"), newRefresh("rt", "at", "fam"))
		assert.ErrorIs(t, err, ErrTokenRevoked)
		assert.False(t, exists(mr, TokenPrefix+"at"), "")
		assert.False(t, exists(mr, RefreshPrefix+"rt"), "")
	})

	t.Run("both tokens must belong to one family", func(t *testing.T) {
		m, _ := setupTestManager(t)
		assert.Error(t, m.IssueTokens(ctx, newAccess("at", "fam"), newRefresh("rt", "at", "other")))
		assert.Error(t, m.IssueTokens(ctx, newAccess("at", ""), newRefresh("rt", "at", "")))
	})
}

// snapshot is every key with its value (hash fields included) and a rounded
// TTL: it changes when a script wrote, rewrote or deleted anything.
func snapshot(mr *miniredis.Miniredis) map[string]string {
	out := map[string]string{}
	for _, k := range mr.Keys() {
		v, err := mr.Get(k)
		if err != nil {
			v = "hash:"
			fields, _ := mr.HKeys(k)
			for _, f := range fields {
				v += f + "=" + mr.HGet(k, f) + ";"
			}
		}
		out[k] = v
	}
	return out
}

// ===== Claims =====

func TestClaimRefreshToken(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()
	issueGrant(t, m, "fam", "at", "rt")
	recordBefore, _ := mr.Get(RefreshPrefix + "rt")

	claim, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err)
	require.NotNil(t, claim)
	assert.Equal(t, "fam", claim.FamilyID)
	assert.Equal(t, "fam", claim.Data.FamilyID)
	assert.Equal(t, "fb-refresh", claim.Data.FirebaseRefreshToken)
	assert.Equal(t, "at", claim.Data.AccessToken)

	t.Run("the refresh record stays where it is", func(t *testing.T) {
		recordAfter, err := mr.Get(RefreshPrefix + "rt")
		require.NoError(t, err)
		assert.Equal(t, recordBefore, recordAfter, "a claim is a separate key; the record is untouched")
		got, _ := m.GetRefreshTokenData(ctx, "rt")
		assert.NotNil(t, got)
	})

	t.Run("the claim key holds the attempt's id and expires on its own", func(t *testing.T) {
		key := RefreshClaimPrefix + tokenHash("rt")
		v, err := mr.Get(key)
		require.NoError(t, err)
		assert.Equal(t, claim.Owner, v)
		assert.NotEmpty(t, claim.Owner)
		assert.InDelta(t, RefreshClaimTTL.Seconds(), mr.TTL(key).Seconds(), 2)
	})

	t.Run("another attempt cannot claim it", func(t *testing.T) {
		second, err := m.ClaimRefreshToken(ctx, "rt")
		assert.ErrorIs(t, err, ErrRefreshInFlight)
		assert.Nil(t, second)
	})

	t.Run("the same attempt can claim again (a repeat after a lost reply)", func(t *testing.T) {
		again, err := m.claimAs(ctx, "rt", claim.Owner)
		require.NoError(t, err)
		assert.Equal(t, claim.Owner, again.Owner)
		assert.Equal(t, "fam", again.FamilyID)
		v, _ := mr.Get(RefreshClaimPrefix + tokenHash("rt"))
		assert.Equal(t, claim.Owner, v)
	})

	t.Run("releasing it lets the next attempt claim", func(t *testing.T) {
		m.ReleaseRefreshClaim(ctx, claim)
		assert.False(t, mr.Exists(RefreshClaimPrefix+tokenHash("rt")))
		next, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		assert.NotNil(t, next)
	})
}

func TestClaimRefreshToken_Refusals(t *testing.T) {
	ctx := context.Background()

	t.Run("an unknown token", func(t *testing.T) {
		m, mr := setupTestManager(t)
		_, err := m.ClaimRefreshToken(ctx, "nope")
		assert.ErrorIs(t, err, ErrRefreshTokenNotFound)
		assert.Empty(t, mr.Keys(), "nothing is written for an unknown token")
	})

	t.Run("a tombstoned token", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		mr.Set(RevokedTokenPrefix+tokenHash("rt"), "1")
		_, err := m.ClaimRefreshToken(ctx, "rt")
		assert.ErrorIs(t, err, ErrTokenRevoked)
		assert.False(t, mr.Exists(RefreshClaimPrefix+tokenHash("rt")), "no claim for a revoked token")
	})

	t.Run("a token of a revoked family", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		mr.Set(RevokedFamilyPrefix+"fam", "1")
		_, err := m.ClaimRefreshToken(ctx, "rt")
		assert.ErrorIs(t, err, ErrTokenRevoked)
		assert.False(t, mr.Exists(RefreshClaimPrefix+tokenHash("rt")))
	})

	t.Run("a record that cannot be read is left alone and its claim given up", func(t *testing.T) {
		m, mr := setupTestManager(t)
		mr.Set(RefreshPrefix+"junk", "not json")
		mr.SetTTL(RefreshPrefix+"junk", time.Hour)
		_, err := m.ClaimRefreshToken(ctx, "junk")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrRefreshTokenNotFound)
		v, _ := mr.Get(RefreshPrefix + "junk")
		assert.Equal(t, "not json", v)
		assert.False(t, mr.Exists(RefreshClaimPrefix+tokenHash("junk")))
	})

	t.Run("a backend failure is an error and leaves no claim behind", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		mr.SetError("ERR boom")
		_, err := m.ClaimRefreshToken(ctx, "rt")
		mr.SetError("")
		require.Error(t, err)
		assert.False(t, mr.Exists(RefreshClaimPrefix+tokenHash("rt")))
	})
}

// A claim that is not released expires on its own, and then the token is
// claimable again: a crashed pod cannot lock a token for good.
func TestClaimRefreshToken_ExpiresAndCanBeTakenAgain(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()
	issueGrant(t, m, "fam", "at", "rt")

	first, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err)
	_, err = m.ClaimRefreshToken(ctx, "rt")
	require.ErrorIs(t, err, ErrRefreshInFlight)

	mr.FastForward(RefreshClaimTTL + time.Second)
	second, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err, "the token was never removed, so it can be claimed again")
	assert.NotEqual(t, first.Owner, second.Owner)
}

// The release is a compare-and-delete on the attempt's id: a late or repeated
// release by an attempt that no longer owns the claim must not clear the claim
// of the attempt that does.
func TestReleaseRefreshClaim_IsOwnershipChecked(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()
	issueGrant(t, m, "fam", "at", "rt")
	key := RefreshClaimPrefix + tokenHash("rt")

	a, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err)
	m.ReleaseRefreshClaim(ctx, a)
	b, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err)

	m.ReleaseRefreshClaim(ctx, a) // a's cleanup runs again, late
	v, err := mr.Get(key)
	require.NoError(t, err, "b's claim survives a's stale release")
	assert.Equal(t, b.Owner, v)
	_, err = m.ClaimRefreshToken(ctx, "rt")
	assert.ErrorIs(t, err, ErrRefreshInFlight)

	t.Run("an attempt that lost its claim to expiry does not clear the next one", func(t *testing.T) {
		mr.FastForward(RefreshClaimTTL + time.Second) // b's claim expires
		c, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		m.ReleaseRefreshClaim(ctx, b)
		v, err := mr.Get(key)
		require.NoError(t, err)
		assert.Equal(t, c.Owner, v)
	})
}

// An attempt that has given its claim up is over for good. A copy of its claim
// command that arrives late (the network delayed it past the client's retry)
// must not take the claim back: that would block the token for the length of the
// claim, and let a late copy of the attempt's publish through.
func TestClaimRefreshToken_ACopyOfAnEndedAttemptCannotTakeTheClaimBack(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()
	issueGrant(t, m, "fam", "at", "rt")

	a, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err)
	m.ReleaseRefreshClaim(ctx, a)

	_, err = m.claimAs(ctx, "rt", a.Owner) // the late copy
	assert.ErrorIs(t, err, ErrRefreshInFlight)
	assert.False(t, mr.Exists(RefreshClaimPrefix+tokenHash("rt")), "the late copy took nothing")
	assert.InDelta(t, AttemptOverTTL.Seconds(), mr.TTL(AttemptOverPrefix+a.Owner).Seconds(), 2)

	b, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err, "the token is free for the next attempt")
	assert.NotEqual(t, a.Owner, b.Owner)
}

func TestPublishRotation_ALateCopyOfAnEndedAttemptPublishesNothing(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()
	issueGrant(t, m, "fam", "at", "rt")

	a, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err)
	late, err := m.preparePublish(a, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam"))
	require.NoError(t, err)
	m.ReleaseRefreshClaim(ctx, a) // the attempt failed and gave up

	_, err = m.claimAs(ctx, "rt", a.Owner)
	require.Error(t, err)
	before := snapshot(mr)
	assert.ErrorIs(t, m.publish(ctx, late), ErrClaimLost, "the copy of the publish finds no claim to use")
	assert.Equal(t, before, snapshot(mr))
	old, _ := m.GetRefreshTokenData(ctx, "rt")
	assert.NotNil(t, old, "the token was not consumed by an attempt the client never heard of")
}

// A copy of the first issue that arrives after the grant has moved on must not
// bring the first generation back.
func TestIssueTokens_ALateCopyDoesNotBringTheFirstTokensBack(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()
	call, err := m.prepareIssue(newAccess("at", "fam"), newRefresh("rt", "at", "fam"))
	require.NoError(t, err)
	require.NoError(t, m.issue(ctx, call))
	require.NoError(t, m.issue(ctx, call), "a prompt repeat is the client library's retry")

	claim, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err)
	require.NoError(t, m.PublishRotation(ctx, claim, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam")))
	before := snapshot(mr)

	assert.ErrorIs(t, m.issue(ctx, call), ErrAlreadyExists, "the late copy")
	assert.Equal(t, before, snapshot(mr))
	assert.False(t, exists(mr, RefreshPrefix+"rt"), "the first refresh token is not back")
	assert.False(t, exists(mr, TokenPrefix+"at"))
	assert.Equal(t, "rt-1", mr.HGet(FamilyPrefix+"fam", "rt"))
}

func TestClaimRefreshToken_ExactlyOneWinner(t *testing.T) {
	m, _ := setupTestManager(t)
	ctx := context.Background()
	issueGrant(t, m, "fam", "at", "rt")

	var wins, inFlight atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := m.ClaimRefreshToken(ctx, "rt")
			switch {
			case err == nil && c != nil:
				wins.Add(1)
			case err == ErrRefreshInFlight:
				inFlight.Add(1)
			default:
				t.Errorf("unexpected claim result: %v", err)
			}
		}()
	}
	wg.Wait()
	assert.EqualValues(t, 1, wins.Load())
	assert.EqualValues(t, 19, inFlight.Load())
}

// A token issued before families existed has no family on its record. The claim
// gives it one, written atomically to its index, so concurrent first uses agree
// and a later revocation can find the grant.
func TestClaimRefreshToken_LegacyTokenGetsAFamily(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()
	storeLegacyGrant(t, m, "legacy-at", "legacy-rt")
	recordBefore, _ := mr.Get(RefreshPrefix + "legacy-rt")
	idx := TokenFamilyPrefix + tokenHash("legacy-rt")
	require.False(t, mr.Exists(idx))

	claim, err := m.ClaimRefreshToken(ctx, "legacy-rt")
	require.NoError(t, err)
	require.NotEmpty(t, claim.FamilyID)
	assert.Empty(t, claim.Data.FamilyID, "the record itself is not rewritten")
	recordAfter, _ := mr.Get(RefreshPrefix + "legacy-rt")
	assert.Equal(t, recordBefore, recordAfter)

	v, err := mr.Get(idx)
	require.NoError(t, err)
	assert.Equal(t, claim.FamilyID, v)
	assert.InDelta(t, mr.TTL(RefreshPrefix+"legacy-rt").Seconds(), mr.TTL(idx).Seconds(), 2, "the index lives as long as the token")

	t.Run("the family is stable across attempts", func(t *testing.T) {
		m.ReleaseRefreshClaim(ctx, claim)
		again, err := m.ClaimRefreshToken(ctx, "legacy-rt")
		require.NoError(t, err)
		assert.Equal(t, claim.FamilyID, again.FamilyID)
	})
}

func TestClaimRefreshToken_LegacyFirstUsesAgreeOnOneFamily(t *testing.T) {
	m, _ := setupTestManager(t)
	ctx := context.Background()
	storeLegacyGrant(t, m, "legacy-at", "legacy-rt")

	const n = 16
	families := make(chan string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Distinct attempts at once; the claim itself lets one through, so
			// release and retry until each attempt has seen the family.
			for {
				c, err := m.ClaimRefreshToken(ctx, "legacy-rt")
				if err == nil {
					families <- c.FamilyID
					m.ReleaseRefreshClaim(ctx, c)
					return
				}
				time.Sleep(time.Millisecond)
			}
		}(i)
	}
	wg.Wait()
	close(families)
	seen := map[string]bool{}
	for f := range families {
		seen[f] = true
	}
	assert.Len(t, seen, 1, "every first use got the same family")
}

func TestClaimRefreshToken_MissingIndexIsWrittenAgain(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()
	issueGrant(t, m, "fam", "at", "rt")
	idx := TokenFamilyPrefix + tokenHash("rt")
	mr.Del(idx)

	_, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err)
	v, err := mr.Get(idx)
	require.NoError(t, err)
	assert.Equal(t, "fam", v)
}

// ===== Publishing =====

func TestPublishRotation(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*Manager, *miniredis.Miniredis, *RefreshClaim) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "old-at", "rt")
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		return m, mr, claim
	}
	successors := func() (*AccessTokenData, *RefreshTokenData) {
		return newAccess("new-at", "fam"), newRefresh("new-rt", "new-at", "fam")
	}

	t.Run("publishes both and retires the old tokens", func(t *testing.T) {
		m, mr, claim := setup(t)
		at, rt := successors()
		require.NoError(t, m.PublishRotation(ctx, claim, at, rt))

		gotAT, _ := m.GetAccessTokenData(ctx, "new-at")
		gotRT, _ := m.GetRefreshTokenData(ctx, "new-rt")
		oldAT, _ := m.GetAccessTokenData(ctx, "old-at")
		oldRT, _ := m.GetRefreshTokenData(ctx, "rt")
		assert.NotNil(t, gotAT)
		assert.NotNil(t, gotRT)
		assert.Nil(t, oldAT, "the access token it was issued with is retired")
		assert.Nil(t, oldRT, "the refresh token is consumed")
		assert.False(t, mr.Exists(RefreshClaimPrefix+tokenHash("rt")), "the claim is dropped with the publish")
	})

	t.Run("the family record and the indices follow the rotation", func(t *testing.T) {
		m, mr, claim := setup(t)
		oldRTTTL := mr.TTL(RefreshPrefix + "rt")
		oldATTTL := mr.TTL(TokenPrefix + "old-at")
		at, rt := successors()
		require.NoError(t, m.PublishRotation(ctx, claim, at, rt))

		assert.Equal(t, "new-rt", mr.HGet(FamilyPrefix+"fam", "rt"))
		assert.Equal(t, tokenHash("new-rt"), mr.HGet(FamilyPrefix+"fam", "rth"))
		assert.Equal(t, "new-at", mr.HGet(FamilyPrefix+"fam", "at"))
		for _, tok := range []string{"new-at", "new-rt", "old-at", "rt"} {
			v, err := mr.Get(TokenFamilyPrefix + tokenHash(tok))
			require.NoError(t, err, tok)
			assert.Equal(t, "fam", v, tok)
		}
		assert.GreaterOrEqual(t, mr.TTL(TokenFamilyPrefix+tokenHash("rt")), oldRTTTL-2*time.Second, "a consumed token's index lasts as long as the token could have")
		assert.GreaterOrEqual(t, mr.TTL(TokenFamilyPrefix+tokenHash("old-at")), oldATTTL-2*time.Second)
		assert.GreaterOrEqual(t, mr.TTL(FamilyPrefix+"fam"), mr.TTL(RefreshPrefix+"new-rt")-time.Second)
		assert.InDelta(t, RotationRecordTTL.Seconds(), mr.TTL(RotationPrefix+tokenHash("rt")).Seconds(), 2)
	})

	t.Run("a repeat as the same attempt succeeds and changes nothing", func(t *testing.T) {
		m, mr, claim := setup(t)
		at, rt := successors()
		call, err := m.preparePublish(claim, at, rt)
		require.NoError(t, err)
		require.NoError(t, m.publish(ctx, call))
		before := snapshot(mr)

		require.NoError(t, m.publish(ctx, call), "the Redis client repeats a command whose reply was lost")
		assert.Equal(t, before, snapshot(mr))
	})

	t.Run("a repeat does not resurrect anything a revocation took", func(t *testing.T) {
		m, mr, claim := setup(t)
		at, rt := successors()
		call, err := m.preparePublish(claim, at, rt)
		require.NoError(t, err)
		require.NoError(t, m.publish(ctx, call))
		_, err = m.RevokeToken(ctx, "rt")
		require.NoError(t, err)
		before := snapshot(mr)

		require.NoError(t, m.publish(ctx, call), "answers like the first run, the record says so")
		assert.Equal(t, before, snapshot(mr), "and writes nothing")
		gotAT, _ := m.GetAccessTokenData(ctx, "new-at")
		assert.Nil(t, gotAT)
	})

	t.Run("different successors for the same attempt are not a repeat", func(t *testing.T) {
		m, _, claim := setup(t)
		at, rt := successors()
		require.NoError(t, m.PublishRotation(ctx, claim, at, rt))
		err := m.PublishRotation(ctx, claim, newAccess("other-at", "fam"), newRefresh("other-rt", "other-at", "fam"))
		assert.ErrorIs(t, err, ErrClaimLost)
		other, _ := m.GetAccessTokenData(ctx, "other-at")
		assert.Nil(t, other)
	})

	t.Run("a revoked token publishes nothing", func(t *testing.T) {
		m, mr, claim := setup(t)
		_, err := m.RevokeToken(ctx, "rt")
		require.NoError(t, err)
		before := snapshot(mr)
		at, rt := successors()
		assert.ErrorIs(t, m.PublishRotation(ctx, claim, at, rt), ErrTokenRevoked)
		assert.Equal(t, before, snapshot(mr))
	})

	t.Run("a tombstone alone blocks the publish", func(t *testing.T) {
		m, mr, claim := setup(t)
		mr.Set(RevokedTokenPrefix+tokenHash("rt"), "1")
		before := snapshot(mr)
		at, rt := successors()
		assert.ErrorIs(t, m.PublishRotation(ctx, claim, at, rt), ErrTokenRevoked)
		assert.Equal(t, before, snapshot(mr))
	})

	t.Run("a family marker alone blocks the publish", func(t *testing.T) {
		m, mr, claim := setup(t)
		mr.Set(RevokedFamilyPrefix+"fam", "1")
		before := snapshot(mr)
		at, rt := successors()
		assert.ErrorIs(t, m.PublishRotation(ctx, claim, at, rt), ErrTokenRevoked)
		assert.Equal(t, before, snapshot(mr), "nothing changes when blocked")
		old, _ := m.GetAccessTokenData(ctx, "old-at")
		assert.NotNil(t, old)
	})

	t.Run("a revoked family publishes nothing", func(t *testing.T) {
		m, _, claim := setup(t)
		require.NoError(t, m.RevokeFamily(ctx, "fam"))
		at, rt := successors()
		assert.ErrorIs(t, m.PublishRotation(ctx, claim, at, rt), ErrTokenRevoked)
		got, _ := m.GetAccessTokenData(ctx, "new-at")
		assert.Nil(t, got)
	})

	t.Run("an expired claim cannot publish", func(t *testing.T) {
		m, mr, claim := setup(t)
		mr.FastForward(RefreshClaimTTL + time.Second)
		before := snapshot(mr)
		at, rt := successors()
		assert.ErrorIs(t, m.PublishRotation(ctx, claim, at, rt), ErrClaimLost)
		assert.Equal(t, before, snapshot(mr))
	})

	t.Run("a claim another attempt took over cannot publish", func(t *testing.T) {
		m, mr, stale := setup(t)
		mr.FastForward(RefreshClaimTTL + time.Second)
		fresh, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)

		at, rt := successors()
		assert.ErrorIs(t, m.PublishRotation(ctx, stale, at, rt), ErrClaimLost)
		got, _ := m.GetAccessTokenData(ctx, "new-at")
		assert.Nil(t, got, "the stale attempt published nothing")

		require.NoError(t, m.PublishRotation(ctx, fresh, newAccess("fresh-at", "fam"), newRefresh("fresh-rt", "fresh-at", "fam")))
		// The stale attempt wakes up after the new one rotated the token.
		assert.ErrorIs(t, m.PublishRotation(ctx, stale, at, rt), ErrClaimLost)
		got, _ = m.GetAccessTokenData(ctx, "new-at")
		assert.Nil(t, got)
	})

	t.Run("a cleared claim cannot publish", func(t *testing.T) {
		m, mr, claim := setup(t)
		mr.Del(RefreshClaimPrefix + tokenHash("rt"))
		at, rt := successors()
		assert.ErrorIs(t, m.PublishRotation(ctx, claim, at, rt), ErrClaimLost)
	})

	t.Run("an id collision publishes nothing", func(t *testing.T) {
		m, _, claim := setup(t)
		require.NoError(t, m.StoreRefreshToken(ctx, newRefresh("new-rt", "x", "fam")))
		at, rt := successors()
		assert.ErrorIs(t, m.PublishRotation(ctx, claim, at, rt), ErrAlreadyExists)
		got, _ := m.GetAccessTokenData(ctx, "new-at")
		assert.Nil(t, got)
		old, _ := m.GetRefreshTokenData(ctx, "rt")
		assert.NotNil(t, old, "the token is still there to retry with")
	})

	t.Run("the successors must carry the family of the claim", func(t *testing.T) {
		m, _, claim := setup(t)
		assert.Error(t, m.PublishRotation(ctx, claim, newAccess("new-at", "other"), newRefresh("new-rt", "new-at", "other")))
		assert.Error(t, m.PublishRotation(ctx, claim, newAccess("new-at", ""), newRefresh("new-rt", "new-at", "")))
	})
}

// A token issued before families existed rotates into a family, and its old
// access token is indexed under it on the way out, so revoking either of the
// old tokens afterwards still reaches the successors.
func TestPublishRotation_LegacyGrant(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()
	storeLegacyGrant(t, m, "legacy-at", "legacy-rt")
	claim, err := m.ClaimRefreshToken(ctx, "legacy-rt")
	require.NoError(t, err)

	fam := claim.FamilyID
	require.NoError(t, m.PublishRotation(ctx, claim, newAccess("new-at", fam), newRefresh("new-rt", "new-at", fam)))

	v, err := mr.Get(TokenFamilyPrefix + tokenHash("legacy-at"))
	require.NoError(t, err, "the old access token is indexed when it is retired")
	assert.Equal(t, fam, v)
	got, _ := m.GetRefreshTokenData(ctx, "new-rt")
	require.NotNil(t, got)
	assert.Equal(t, fam, got.FamilyID)

	out, err := m.RevokeToken(ctx, "legacy-at")
	require.NoError(t, err)
	assert.Equal(t, RevokedGrantByToken, out)
	assert.False(t, exists(mr, RefreshPrefix+"new-rt"))
	assert.False(t, exists(mr, TokenPrefix+"new-at"))
}

// A publish needs no old access token: a refresh record that names none rotates
// too.
func TestPublishRotation_RefreshRecordWithoutAnAccessToken(t *testing.T) {
	m, _ := setupTestManager(t)
	ctx := context.Background()
	require.NoError(t, m.StoreRefreshToken(ctx, newRefresh("rt", "", "fam")))
	claim, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err)

	require.NoError(t, m.PublishRotation(ctx, claim, newAccess("new-at", "fam"), newRefresh("new-rt", "new-at", "fam")))
	got, _ := m.GetRefreshTokenData(ctx, "new-rt")
	assert.NotNil(t, got)
}

// ===== Revocation =====

func TestRevokeToken(t *testing.T) {
	ctx := context.Background()
	revoked := func(t *testing.T, m *Manager, fam string) bool {
		t.Helper()
		r, err := m.IsFamilyRevoked(ctx, fam)
		require.NoError(t, err)
		return r
	}

	t.Run("a refresh token revokes its whole grant", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		out, err := m.RevokeToken(ctx, "rt")
		require.NoError(t, err)
		assert.Equal(t, RevokedRefreshToken, out)

		assert.False(t, exists(mr, RefreshPrefix+"rt"))
		assert.False(t, exists(mr, TokenPrefix+"at"))
		assert.False(t, exists(mr, FamilyPrefix+"fam"))
		assert.True(t, revoked(t, m, "fam"))
		assert.True(t, exists(mr, RevokedTokenPrefix+tokenHash("rt")))
		assert.InDelta(t, RevokedTokenTTL.Seconds(), mr.TTL(RevokedTokenPrefix+tokenHash("rt")).Seconds(), 2)
		assert.InDelta(t, RevokedFamilyTTL.Seconds(), mr.TTL(RevokedFamilyPrefix+"fam").Seconds(), 2)
	})

	t.Run("an access token revokes its whole grant", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		out, err := m.RevokeToken(ctx, "at")
		require.NoError(t, err)
		assert.Equal(t, RevokedAccessToken, out)

		assert.False(t, exists(mr, TokenPrefix+"at"))
		assert.False(t, exists(mr, RefreshPrefix+"rt"), "the refresh token cannot mint another access token")
		assert.True(t, revoked(t, m, "fam"))
	})

	t.Run("a refresh token that is being refreshed: the record, the access token and the claim go", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)

		out, err := m.RevokeToken(ctx, "rt")
		require.NoError(t, err)
		assert.Equal(t, RevokedRefreshToken, out)
		assert.False(t, exists(mr, RefreshPrefix+"rt"))
		assert.False(t, exists(mr, TokenPrefix+"at"), "the access token is dead as soon as the revocation returns")
		assert.False(t, exists(mr, RefreshClaimPrefix+tokenHash("rt")), "so is the claim")
		assert.True(t, revoked(t, m, "fam"))

		err = m.PublishRotation(ctx, claim, newAccess("new-at", "fam"), newRefresh("new-rt", "new-at", "fam"))
		assert.ErrorIs(t, err, ErrTokenRevoked, "the refresh in flight publishes nothing")
		assert.False(t, exists(mr, TokenPrefix+"new-at"))
		assert.False(t, exists(mr, RefreshPrefix+"new-rt"))
	})

	t.Run("an expired claim does not hide the token from a revocation", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		mr.FastForward(RefreshClaimTTL + time.Second)

		out, err := m.RevokeToken(ctx, "rt")
		require.NoError(t, err)
		assert.Equal(t, RevokedRefreshToken, out)
		assert.False(t, exists(mr, TokenPrefix+"at"))
		err = m.PublishRotation(ctx, claim, newAccess("new-at", "fam"), newRefresh("new-rt", "new-at", "fam"))
		assert.Error(t, err)
		assert.False(t, exists(mr, RefreshPrefix+"new-rt"))
	})

	t.Run("a refresh token that was rotated away still revokes the successors", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		require.NoError(t, m.PublishRotation(ctx, claim, newAccess("new-at", "fam"), newRefresh("new-rt", "new-at", "fam")))

		out, err := m.RevokeToken(ctx, "rt")
		require.NoError(t, err)
		assert.Equal(t, RevokedGrantByToken, out)
		assert.False(t, exists(mr, TokenPrefix+"new-at"))
		assert.False(t, exists(mr, RefreshPrefix+"new-rt"))
		assert.True(t, revoked(t, m, "fam"))
	})

	t.Run("an access token that was rotated away still revokes the successors", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		require.NoError(t, m.PublishRotation(ctx, claim, newAccess("new-at", "fam"), newRefresh("new-rt", "new-at", "fam")))

		out, err := m.RevokeToken(ctx, "at")
		require.NoError(t, err)
		assert.Equal(t, RevokedGrantByToken, out)
		assert.False(t, exists(mr, TokenPrefix+"new-at"))
		assert.False(t, exists(mr, RefreshPrefix+"new-rt"))
	})

	t.Run("a rotated-away token reaches the successor that a refresh has claimed", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		first, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		require.NoError(t, m.PublishRotation(ctx, first, newAccess("at-2", "fam"), newRefresh("rt-2", "at-2", "fam")))
		second, err := m.ClaimRefreshToken(ctx, "rt-2")
		require.NoError(t, err)

		_, err = m.RevokeToken(ctx, "rt") // the first token, long consumed
		require.NoError(t, err)
		assert.False(t, exists(mr, RefreshPrefix+"rt-2"))
		assert.False(t, exists(mr, TokenPrefix+"at-2"))
		assert.False(t, exists(mr, RefreshClaimPrefix+tokenHash("rt-2")), "the claim of the successor goes too")
		err = m.PublishRotation(ctx, second, newAccess("at-3", "fam"), newRefresh("rt-3", "at-3", "fam"))
		assert.ErrorIs(t, err, ErrTokenRevoked)
	})

	t.Run("a legacy refresh token is revoked with the access token its record names", func(t *testing.T) {
		m, mr := setupTestManager(t)
		storeLegacyGrant(t, m, "legacy-at", "legacy-rt")
		out, err := m.RevokeToken(ctx, "legacy-rt")
		require.NoError(t, err)
		assert.Equal(t, RevokedRefreshToken, out)
		assert.False(t, exists(mr, RefreshPrefix+"legacy-rt"))
		assert.False(t, exists(mr, TokenPrefix+"legacy-at"))
		assert.True(t, exists(mr, RevokedTokenPrefix+tokenHash("legacy-rt")))
	})

	t.Run("a legacy refresh token that is being refreshed gets its grant revoked", func(t *testing.T) {
		m, mr := setupTestManager(t)
		storeLegacyGrant(t, m, "legacy-at", "legacy-rt")
		claim, err := m.ClaimRefreshToken(ctx, "legacy-rt")
		require.NoError(t, err)

		_, err = m.RevokeToken(ctx, "legacy-rt")
		require.NoError(t, err)
		assert.False(t, exists(mr, TokenPrefix+"legacy-at"))
		assert.True(t, revoked(t, m, claim.FamilyID), "the family the claim assigned is marked")
		err = m.PublishRotation(ctx, claim, newAccess("new-at", claim.FamilyID), newRefresh("new-rt", "new-at", claim.FamilyID))
		assert.ErrorIs(t, err, ErrTokenRevoked)
	})

	t.Run("a legacy access token is revoked by itself", func(t *testing.T) {
		m, mr := setupTestManager(t)
		storeLegacyGrant(t, m, "legacy-at", "legacy-rt")
		out, err := m.RevokeToken(ctx, "legacy-at")
		require.NoError(t, err)
		assert.Equal(t, RevokedAccessToken, out)
		assert.False(t, exists(mr, TokenPrefix+"legacy-at"))
		assert.True(t, exists(mr, RefreshPrefix+"legacy-rt"), "nothing links a legacy access token to its refresh token")
	})

	t.Run("an unknown token changes nothing at all", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		before := snapshot(mr)
		for i := 0; i < 20; i++ {
			out, err := m.RevokeToken(ctx, "made-up-"+string(rune('a'+i)))
			require.NoError(t, err)
			assert.Equal(t, RevokedNothing, out)
		}
		assert.Equal(t, before, snapshot(mr), "an unauthenticated caller cannot write records")
	})

	t.Run("revoking again is a success that changes nothing more", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		_, err := m.RevokeToken(ctx, "rt")
		require.NoError(t, err)
		before := snapshot(mr)
		out, err := m.RevokeToken(ctx, "rt")
		require.NoError(t, err)
		assert.Equal(t, RevokedGrantByToken, out)
		assert.Equal(t, before, snapshot(mr))
		out, err = m.RevokeToken(ctx, "at")
		require.NoError(t, err)
		assert.Equal(t, RevokedGrantByToken, out)
		before[RevokedTokenPrefix+tokenHash("at")] = "1" // the only addition: the access token is tombstoned as well
		assert.Equal(t, before, snapshot(mr))
	})

	t.Run("a legacy token revoked twice is reported as already revoked", func(t *testing.T) {
		m, _ := setupTestManager(t)
		storeLegacyGrant(t, m, "legacy-at", "legacy-rt")
		_, err := m.RevokeToken(ctx, "legacy-rt")
		require.NoError(t, err)
		out, err := m.RevokeToken(ctx, "legacy-rt")
		require.NoError(t, err)
		assert.Equal(t, RevokedAlready, out)
	})

	t.Run("a backend failure is an error, and the revocation can be repeated", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		mr.SetError("ERR boom")
		_, err := m.RevokeToken(ctx, "rt")
		mr.SetError("")
		require.Error(t, err)
		assert.True(t, exists(mr, TokenPrefix+"at", RefreshPrefix+"rt"), "nothing was done")

		out, err := m.RevokeToken(ctx, "rt")
		require.NoError(t, err)
		assert.Equal(t, RevokedRefreshToken, out)
		assert.False(t, exists(mr, TokenPrefix+"at"))
	})

	t.Run("tokens of other grants are untouched", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		issueGrant(t, m, "fam-b", "at-b", "rt-b")
		_, err := m.RevokeToken(ctx, "rt")
		require.NoError(t, err)
		assert.True(t, exists(mr, TokenPrefix+"at-b", RefreshPrefix+"rt-b", FamilyPrefix+"fam-b"))
		assert.False(t, revoked(t, m, "fam-b"))
	})
}

func TestRevokeFamily(t *testing.T) {
	ctx := context.Background()
	m, mr := setupTestManager(t)
	issueGrant(t, m, "fam", "at", "rt")
	claim, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err)

	require.NoError(t, m.RevokeFamily(ctx, "fam"))
	assert.False(t, exists(mr, RefreshPrefix+"rt"))
	assert.False(t, exists(mr, TokenPrefix+"at"))
	assert.False(t, exists(mr, RefreshClaimPrefix+tokenHash("rt")))
	revoked, _ := m.IsFamilyRevoked(ctx, "fam")
	assert.True(t, revoked)
	assert.ErrorIs(t, m.PublishRotation(ctx, claim, newAccess("n", "fam"), newRefresh("nr", "n", "fam")), ErrTokenRevoked)

	require.NoError(t, m.RevokeFamily(ctx, ""), "no family, nothing to do")
}

func TestRevokedTokenIsNeverAccepted(t *testing.T) {
	ctx := context.Background()
	m, _ := setupTestManager(t)
	issueGrant(t, m, "fam", "at", "rt")
	_, err := m.RevokeToken(ctx, "rt")
	require.NoError(t, err)

	_, err = m.ClaimRefreshToken(ctx, "rt")
	assert.ErrorIs(t, err, ErrRefreshTokenNotFound)
	at, _ := m.GetAccessTokenData(ctx, "at")
	assert.Nil(t, at)
	// Nothing can create a token for the revoked grant.
	assert.ErrorIs(t, m.IssueTokens(ctx, newAccess("at-x", "fam"), newRefresh("rt-x", "at-x", "fam")), ErrTokenRevoked)
}

// ===== Races =====

// Whatever order a refresh and a revocation of the same grant run in, once the
// revocation has returned the grant has no live token: either the refresh
// published first and the revocation took its successors, or the revocation
// came first and the refresh published nothing.
func TestRevokeRacingRefresh_LeavesNoLiveToken(t *testing.T) {
	ctx := context.Background()
	for _, revoke := range []string{"old refresh token", "old access token"} {
		t.Run(revoke, func(t *testing.T) {
			for i := 0; i < 60; i++ {
				m, mr := setupTestManager(t)
				issueGrant(t, m, "fam", "at", "rt")

				start := make(chan struct{})
				var wg sync.WaitGroup
				var publishErr error
				wg.Add(2)
				go func() {
					defer wg.Done()
					<-start
					claim, err := m.ClaimRefreshToken(ctx, "rt")
					if err != nil {
						publishErr = err
						return
					}
					publishErr = m.PublishRotation(ctx, claim, newAccess("new-at", "fam"), newRefresh("new-rt", "new-at", "fam"))
				}()
				go func() {
					defer wg.Done()
					<-start
					tok := "rt"
					if revoke == "old access token" {
						tok = "at"
					}
					_, err := m.RevokeToken(ctx, tok)
					assert.NoError(t, err)
				}()
				close(start)
				wg.Wait()

				for _, k := range mr.Keys() {
					assert.NotContains(t, []string{TokenPrefix + "at", TokenPrefix + "new-at", RefreshPrefix + "rt", RefreshPrefix + "new-rt"}, k,
						"iteration %d: live token %q after a revocation that returned (refresh result: %v)", i, k, publishErr)
				}
			}
		})
	}
}
