package state

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The refresh grace window accepts a rotated refresh token for RotationRecordTTL.
// A revocation of that token (or of the access token it was issued with) in that
// window has to reach the grant, however little of the old token's own lifetime
// was left when it was rotated.

// nearlyExpired makes a token's record and its token->grant index (written
// together, lasting as long as each other) look like they are about to end.
func nearlyExpired(mr *miniredis.Miniredis, recordKey, token string, left time.Duration) {
	mr.SetTTL(recordKey, left)
	mr.SetTTL(TokenFamilyPrefix+tokenHash(token), left)
}

func TestPublishRotation_TheOldTokensKeepTheirIndexAsLongAsTheRotationRecord(t *testing.T) {
	ctx := context.Background()
	rotateNearExpiry := func(t *testing.T) (*Manager, *miniredis.Miniredis) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		nearlyExpired(mr, RefreshPrefix+"rt", "rt", time.Second)
		nearlyExpired(mr, TokenPrefix+"at", "at", time.Second)
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		require.NoError(t, m.PublishRotation(ctx, claim, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam")))
		return m, mr
	}

	t.Run("the indices last as long as the rotation record", func(t *testing.T) {
		_, mr := rotateNearExpiry(t)
		for _, tok := range []string{"rt", "at"} {
			assert.GreaterOrEqual(t, mr.TTL(TokenFamilyPrefix+tokenHash(tok)), RotationRecordTTL-2*time.Second, tok)
		}
	})

	t.Run("a longer-lived index is not shortened", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		before := mr.TTL(TokenFamilyPrefix + tokenHash("rt"))
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		require.NoError(t, m.PublishRotation(ctx, claim, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam")))
		assert.GreaterOrEqual(t, mr.TTL(TokenFamilyPrefix+tokenHash("rt")), before-2*time.Second)
	})

	t.Run("revoking the old refresh token in the window revokes the grant", func(t *testing.T) {
		m, mr := rotateNearExpiry(t)
		mr.FastForward(RotationRecordTTL - 5*time.Second)
		got, err := m.RotationSuccessors(ctx, "rt")
		require.NoError(t, err)
		require.NotNil(t, got, "grace still accepts the token")

		out, err := m.RevokeToken(ctx, "rt")
		require.NoError(t, err)
		assert.Equal(t, RevokedGrantByToken, out)
		assert.False(t, exists(mr, TokenPrefix+"at-1"))
		assert.False(t, exists(mr, RefreshPrefix+"rt-1"))
		revoked, err := m.IsFamilyRevoked(ctx, "fam")
		require.NoError(t, err)
		assert.True(t, revoked)
	})

	t.Run("revoking the old access token in the window revokes the grant", func(t *testing.T) {
		m, mr := rotateNearExpiry(t)
		mr.FastForward(RotationRecordTTL - 5*time.Second)

		out, err := m.RevokeToken(ctx, "at")
		require.NoError(t, err)
		assert.Equal(t, RevokedGrantByToken, out)
		assert.False(t, exists(mr, TokenPrefix+"at-1"))
		assert.False(t, exists(mr, RefreshPrefix+"rt-1"))
	})
}

// The rotation record names the grant, so a revocation finds it even if the
// index is gone for any other reason.
func TestRevokeToken_ARotatedTokenWhoseIndexIsGoneIsResolvedByItsRotationRecord(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*Manager, *miniredis.Miniredis) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		require.NoError(t, m.PublishRotation(ctx, claim, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam")))
		mr.Del(TokenFamilyPrefix + tokenHash("rt"))
		return m, mr
	}

	t.Run("within the window", func(t *testing.T) {
		m, mr := setup(t)
		out, err := m.RevokeToken(ctx, "rt")
		require.NoError(t, err)
		assert.Equal(t, RevokedGrantByToken, out)
		assert.False(t, exists(mr, TokenPrefix+"at-1"))
		assert.False(t, exists(mr, RefreshPrefix+"rt-1"))
		assert.True(t, exists(mr, RevokedFamilyPrefix+"fam"))
		assert.True(t, exists(mr, RevokedTokenPrefix+tokenHash("rt")))
	})

	t.Run("not after the window: the token is unknown then", func(t *testing.T) {
		m, mr := setup(t)
		mr.FastForward(RotationRecordTTL + time.Second)
		before := snapshot(mr)
		out, err := m.RevokeToken(ctx, "rt")
		require.NoError(t, err)
		assert.Equal(t, RevokedNothing, out)
		assert.Equal(t, before, snapshot(mr))
	})

	t.Run("a rotation record only speaks for its own token", func(t *testing.T) {
		m, mr := setup(t)
		before := snapshot(mr)
		out, err := m.RevokeToken(ctx, "somebody-elses-token")
		require.NoError(t, err)
		assert.Equal(t, RevokedNothing, out)
		assert.Equal(t, before, snapshot(mr))
	})
}

func TestRevokeTokenInFamily(t *testing.T) {
	ctx := context.Background()

	t.Run("a token nobody knows still revokes the grant the caller names", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		require.NoError(t, m.PublishRotation(ctx, claim, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam")))
		mr.Del(TokenFamilyPrefix + tokenHash("rt"))
		mr.Del(RotationPrefix + tokenHash("rt"))

		unknown, err := m.RevokeToken(ctx, "rt")
		require.NoError(t, err)
		require.Equal(t, RevokedNothing, unknown, "nothing leads from the token to the grant")

		out, err := m.RevokeTokenInFamily(ctx, "rt", "fam")
		require.NoError(t, err)
		assert.NotEqual(t, RevokedNothing, out, "a revocation of a known grant is never 'nothing'")
		assert.False(t, exists(mr, TokenPrefix+"at-1"))
		assert.False(t, exists(mr, RefreshPrefix+"rt-1"))
		assert.False(t, exists(mr, RefreshClaimPrefix+tokenHash("rt-1")))
		revoked, err := m.IsFamilyRevoked(ctx, "fam")
		require.NoError(t, err)
		assert.True(t, revoked)
	})

	t.Run("a live token is revoked as usual", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		out, err := m.RevokeTokenInFamily(ctx, "rt", "fam")
		require.NoError(t, err)
		assert.Equal(t, RevokedRefreshToken, out)
		assert.False(t, exists(mr, RefreshPrefix+"rt"))
		assert.False(t, exists(mr, TokenPrefix+"at"))
	})

	t.Run("the grant named is revoked and so is the one the token leads to", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		issueGrant(t, m, "other", "at-o", "rt-o")
		out, err := m.RevokeTokenInFamily(ctx, "rt", "other")
		require.NoError(t, err)
		assert.Equal(t, RevokedRefreshToken, out)
		for _, fam := range []string{"fam", "other"} {
			revoked, err := m.IsFamilyRevoked(ctx, fam)
			require.NoError(t, err)
			assert.True(t, revoked, fam)
		}
		assert.False(t, exists(mr, RefreshPrefix+"rt-o"))
	})

	t.Run("a revoked claim on the token goes with it", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		_, err = m.RevokeTokenInFamily(ctx, "rt", "fam")
		require.NoError(t, err)
		assert.False(t, exists(mr, RefreshClaimPrefix+tokenHash("rt")))
		assert.ErrorIs(t, m.PublishRotation(ctx, claim, newAccess("n", "fam"), newRefresh("nr", "n", "fam")), ErrTokenRevoked)
	})

	t.Run("without a grant it is RevokeToken: an unknown token changes nothing", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		before := snapshot(mr)
		out, err := m.RevokeTokenInFamily(ctx, "made-up", "")
		require.NoError(t, err)
		assert.Equal(t, RevokedNothing, out)
		assert.Equal(t, before, snapshot(mr))
	})
}

func TestRotationSuccessors_ReportsAClaimedSuccessor(t *testing.T) {
	ctx := context.Background()
	m, _ := setupTestManager(t)
	issueGrant(t, m, "fam", "at", "rt")
	claim, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err)
	require.NoError(t, m.PublishRotation(ctx, claim, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam")))

	got, err := m.RotationSuccessors(ctx, "rt")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.False(t, got.SuccessorClaimed)

	next, err := m.ClaimRefreshToken(ctx, "rt-1")
	require.NoError(t, err)
	got, err = m.RotationSuccessors(ctx, "rt")
	require.NoError(t, err)
	require.NotNil(t, got, "the successors are still the grant's")
	assert.True(t, got.SuccessorClaimed, "a refresh of the successor is in flight")

	m.ReleaseRefreshClaim(ctx, next)
	got, err = m.RotationSuccessors(ctx, "rt")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.False(t, got.SuccessorClaimed)
}

func TestRotationSuccessors_ARecordNamingAnotherGrantIsNotHonoured(t *testing.T) {
	ctx := context.Background()
	m, mr := setupTestManager(t)
	issueGrant(t, m, "fam", "at", "rt")
	claim, err := m.ClaimRefreshToken(ctx, "rt")
	require.NoError(t, err)
	require.NoError(t, m.PublishRotation(ctx, claim, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam")))

	rec, err := mr.Get(RotationPrefix + tokenHash("rt"))
	require.NoError(t, err)
	require.NoError(t, mr.Set(RotationPrefix+tokenHash("rt"), "owner:at-1:rt-1:another:"))
	got, err := m.RotationSuccessors(ctx, "rt")
	require.NoError(t, err)
	assert.Nil(t, got, "successors of another grant are never handed out")

	require.NoError(t, mr.Set(RotationPrefix+tokenHash("rt"), rec))
	got, err = m.RotationSuccessors(ctx, "rt")
	require.NoError(t, err)
	assert.NotNil(t, got)
}
