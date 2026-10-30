package state

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The publish tells a lost claim apart from a rotated token and a revoked or
// gone one: only the last two are proof that the grant is dead.
func TestPublishRotation_RefusalsAreToldApart(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*Manager, *RefreshClaim) {
		m, _ := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		return m, claim
	}

	t.Run("a claim that ran out on an intact token is only a lost claim", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		mr.FastForward(RefreshClaimTTL + time.Second)
		err = m.PublishRotation(ctx, claim, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam"))
		assert.ErrorIs(t, err, ErrClaimLost)
		assert.NotErrorIs(t, err, ErrAlreadyRotated)
		assert.NotErrorIs(t, err, ErrTokenRevoked)
	})

	t.Run("a token another attempt rotated is proven rotated", func(t *testing.T) {
		m, claim := setup(t)
		other, err := m.claimAs(ctx, "rt", "other")
		assert.ErrorIs(t, err, ErrRefreshInFlight)
		require.Nil(t, other)
		require.NoError(t, m.PublishRotation(ctx, claim, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam")))
		stale := *claim
		stale.Owner = "stale"
		err = m.PublishRotation(ctx, &stale, newAccess("at-2", "fam"), newRefresh("rt-2", "at-2", "fam"))
		assert.ErrorIs(t, err, ErrAlreadyRotated)
	})

	t.Run("a token that is gone, rotation record or not, is not a lost claim", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		mr.Del(RefreshPrefix + "rt") // expired
		mr.Del(RefreshClaimPrefix + tokenHash("rt"))
		err = m.PublishRotation(ctx, claim, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam"))
		assert.ErrorIs(t, err, ErrTokenRevoked)
	})
}

func TestRotationSuccessors(t *testing.T) {
	ctx := context.Background()
	rotated := func(t *testing.T) (*Manager, *RefreshClaim) {
		m, _ := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		require.NoError(t, m.PublishRotation(ctx, claim, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam")))
		return m, claim
	}

	t.Run("returns what the rotation published", func(t *testing.T) {
		m, _ := rotated(t)
		got, err := m.RotationSuccessors(ctx, "rt")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "at-1", got.Access.AccessToken)
		assert.Equal(t, "rt-1", got.Refresh.RefreshToken)
		assert.Equal(t, "client-a", got.Refresh.ClientID)
	})
	t.Run("nothing for a token that was never rotated", func(t *testing.T) {
		m, _ := setupTestManager(t)
		got, err := m.RotationSuccessors(ctx, "unknown")
		require.NoError(t, err)
		assert.Nil(t, got)
	})
	t.Run("nothing once the window is over", func(t *testing.T) {
		m, mr := setupTestManager(t)
		issueGrant(t, m, "fam", "at", "rt")
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		require.NoError(t, m.PublishRotation(ctx, claim, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam")))
		mr.FastForward(RotationRecordTTL + time.Second)
		got, err := m.RotationSuccessors(ctx, "rt")
		require.NoError(t, err)
		assert.Nil(t, got)
	})
	t.Run("nothing for a revoked grant", func(t *testing.T) {
		m, _ := rotated(t)
		require.NoError(t, m.RevokeFamily(ctx, "fam"))
		got, err := m.RotationSuccessors(ctx, "rt")
		require.NoError(t, err)
		assert.Nil(t, got)
	})
	t.Run("nothing once the successor refresh token was used", func(t *testing.T) {
		m, _ := rotated(t)
		claim, err := m.ClaimRefreshToken(ctx, "rt-1")
		require.NoError(t, err)
		require.NoError(t, m.PublishRotation(ctx, claim, newAccess("at-2", "fam"), newRefresh("rt-2", "at-2", "fam")))
		got, err := m.RotationSuccessors(ctx, "rt")
		require.NoError(t, err)
		assert.Nil(t, got)
	})
	t.Run("a resource containing colons survives the record", func(t *testing.T) {
		m, _ := setupTestManager(t)
		old := newRefresh("rt", "at", "fam")
		old.Resource = "https://mcp.example:8443/a:b"
		require.NoError(t, m.IssueTokens(ctx, newAccess("at", "fam"), old))
		claim, err := m.ClaimRefreshToken(ctx, "rt")
		require.NoError(t, err)
		require.NoError(t, m.PublishRotation(ctx, claim, newAccess("at-1", "fam"), newRefresh("rt-1", "at-1", "fam")))
		got, err := m.RotationSuccessors(ctx, "rt")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "https://mcp.example:8443/a:b", got.AuthorizedResource)
	})
}

func TestMarkFamilyRevoked(t *testing.T) {
	ctx := context.Background()
	m, _ := setupTestManager(t)
	issueGrant(t, m, "fam", "at", "rt")
	require.NoError(t, m.MarkFamilyRevoked(ctx, "fam"))

	_, err := m.ClaimRefreshToken(ctx, "rt")
	assert.ErrorIs(t, err, ErrTokenRevoked, "the marker alone refuses a claim")
	revoked, err := m.IsFamilyRevoked(ctx, "fam")
	require.NoError(t, err)
	assert.True(t, revoked)
	assert.Error(t, m.MarkFamilyRevoked(ctx, ""))
}
