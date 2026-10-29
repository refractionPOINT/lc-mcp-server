package token

import (
	"context"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Token families: one per sign-in, carried through rotations, revoked as a unit.

// Revoking the grant (family marker) during the refresh blocks publishing and
// restoring even though the revoker could not name the token.
func TestRefreshRace_FamilyRevokedDuringRefreshPublishesNothing(t *testing.T) {
	m, sm, mockFB := setupTestManager(t)
	ctx := context.Background()
	issued := issueFor(t, m, clientA)
	rtData, err := sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	require.NoError(t, err)
	require.NotEmpty(t, rtData.FamilyID, "every sign-in starts a family")

	mockFB.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		require.NoError(t, sm.RevokeFamily(ctx, rtData.FamilyID))
		return validFirebaseResult()
	}

	got, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, ErrRefreshRevoked)

	rt, _ := sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	assert.Nil(t, rt)
	assert.False(t, usable(t, m, issued.AccessToken))
}

// The rotated tokens keep the family, so a later revocation reaches them.
func TestRefreshRace_RotationCarriesTheFamily(t *testing.T) {
	m, sm, _ := setupTestManager(t)
	ctx := context.Background()
	issued := issueFor(t, m, clientA)
	first, _ := sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	require.NotNil(t, first)

	got, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, err)
	at, _ := sm.GetAccessTokenData(ctx, got.AccessToken)
	rt, _ := sm.GetRefreshTokenData(ctx, got.RefreshToken)
	require.NotNil(t, at)
	require.NotNil(t, rt)
	assert.Equal(t, first.FamilyID, at.FamilyID)
	assert.Equal(t, first.FamilyID, rt.FamilyID)

	require.NoError(t, sm.RevokeFamily(ctx, first.FamilyID))
	assert.False(t, usable(t, m, got.AccessToken), "a revoked family's access token is rejected even if its record is there")
	intro, err := m.IntrospectToken(ctx, got.AccessToken)
	require.NoError(t, err)
	assert.False(t, intro.Active)
}

// Tokens issued before families existed refresh, and the rotation starts a
// family for them.
func TestRefreshRace_LegacyTokenWithoutFamilyRefreshes(t *testing.T) {
	m, sm, _ := setupTestManager(t)
	ctx := context.Background()
	require.NoError(t, sm.StoreAccessToken(ctx, state.NewAccessTokenData("legacy-at", "user", "id", "fb-refresh", time.Now().Add(time.Hour).Unix(), "openid", state.TokenTTL)))
	require.NoError(t, sm.StoreRefreshToken(ctx, state.NewRefreshTokenData("legacy-rt", "legacy-at", "user", "fb-refresh", "openid")))
	assert.True(t, usable(t, m, "legacy-at"))

	got, err := m.RefreshAccessToken(ctx, "legacy-rt", "", nil)
	require.NoError(t, err)
	at, _ := sm.GetAccessTokenData(ctx, got.AccessToken)
	rt, _ := sm.GetRefreshTokenData(ctx, got.RefreshToken)
	require.NotNil(t, at)
	require.NotNil(t, rt)
	assert.NotEmpty(t, at.FamilyID)
	assert.Equal(t, at.FamilyID, rt.FamilyID)
	assert.False(t, usable(t, m, "legacy-at"), "the old access token was retired by the rotation")
}

func TestRevoke_RefreshTokenRevokesTheWholeGrant(t *testing.T) {
	m, sm, _ := setupTestManager(t)
	ctx := context.Background()
	issued := issueFor(t, m, clientA)
	rt, _ := sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	require.NotNil(t, rt)

	require.NoError(t, m.RevokeToken(ctx, issued.RefreshToken, "refresh_token"))

	assert.False(t, usable(t, m, issued.AccessToken), "revoking the refresh token takes its access token with it")
	revoked, err := sm.IsFamilyRevoked(ctx, rt.FamilyID)
	require.NoError(t, err)
	assert.True(t, revoked)
	_, err = m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	assert.Error(t, err)
}
