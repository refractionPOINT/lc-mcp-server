package token

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/refractionpoint/lc-mcp-go/internal/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tokens that are already in Redis when this code is deployed were written by
// the previous release: no family id, no family record, no index. Nobody signed
// in may be signed out by the deploy, and the lifecycle must work on them.

// legacyEnv stores tokens byte for byte as the previous release wrote them.
type legacyEnv struct {
	m  *Manager
	sm *state.Manager
	fb *mockFirebaseClient
	mr *miniredis.Miniredis
}

func newLegacyEnv(t *testing.T) *legacyEnv {
	t.Helper()
	mr := miniredis.RunT(t)
	rc, err := redis.New(&redis.Config{URL: "redis://" + mr.Addr()}, testLogger())
	require.NoError(t, err)
	enc := setupTestEncryption(t)
	sm := state.NewManager(rc, enc, testLogger())
	fb := newMockFirebaseClient()
	m := NewManager(sm, fb, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
	env := &legacyEnv{m: m, sm: sm, fb: fb, mr: mr}

	// The record formats are written out here, not produced by the code under
	// test: a field the old release did not have must not be needed.
	encID, err := enc.Encrypt("legacy-fb-id")
	require.NoError(t, err)
	encRefresh, err := enc.Encrypt("legacy-fb-refresh")
	require.NoError(t, err)
	now := time.Now().Unix()
	access, err := json.Marshal(map[string]any{
		"access_token": "legacy-at", "uid": "user", "firebase_id_token": encID, "firebase_refresh_token": encRefresh,
		"firebase_expires_at": now + 3600, "scope": "openid", "created_at": now, "expires_at": now + 86400,
		"extension_count": 0, "last_extended_at": 0,
	})
	require.NoError(t, err)
	refresh, err := json.Marshal(map[string]any{
		"refresh_token": "legacy-rt", "access_token": "legacy-at", "uid": "user", "firebase_refresh_token": encRefresh,
		"scope": "openid", "created_at": now,
	})
	require.NoError(t, err)
	mr.Set(state.TokenPrefix+"legacy-at", string(access))
	mr.SetTTL(state.TokenPrefix+"legacy-at", (86400+state.TokenGracePeriod)*time.Second)
	mr.Set(state.RefreshPrefix+"legacy-rt", string(refresh))
	mr.SetTTL(state.RefreshPrefix+"legacy-rt", state.RefreshTTL*time.Second)
	return env
}

func TestLegacy_TokensFromThePreviousReleaseKeepWorking(t *testing.T) {
	env := newLegacyEnv(t)
	ctx := context.Background()

	res, err := env.m.ValidateAccessToken(ctx, "legacy-at", true)
	require.NoError(t, err)
	assert.True(t, res.Valid, "a signed-in client is still signed in")

	t.Run("they extend", func(t *testing.T) {
		at, err := env.sm.GetAccessTokenData(ctx, "legacy-at")
		require.NoError(t, err)
		at.ExpiresAt = time.Now().Add(30 * time.Minute).Unix() // inside the refresh buffer
		updated, err := env.sm.UpdateAccessToken(ctx, at)
		require.NoError(t, err)
		require.True(t, updated)
		res, err := env.m.ValidateAccessToken(ctx, "legacy-at", true)
		require.NoError(t, err)
		assert.True(t, res.Valid)
		assert.True(t, res.Refreshed)
	})

	t.Run("the refresh token refreshes, then the new tokens refresh", func(t *testing.T) {
		first, err := env.m.RefreshAccessToken(ctx, "legacy-rt", clientA, nil)
		require.NoError(t, err)
		assert.True(t, usable(t, env.m, first.AccessToken))
		assert.False(t, usable(t, env.m, "legacy-at"), "the old access token was retired by the rotation")

		at, _ := env.sm.GetAccessTokenData(ctx, first.AccessToken)
		rt, _ := env.sm.GetRefreshTokenData(ctx, first.RefreshToken)
		require.NotNil(t, at)
		require.NotNil(t, rt)
		assert.NotEmpty(t, at.FamilyID, "the rotation gave the grant a family")
		assert.Equal(t, at.FamilyID, rt.FamilyID)
		assert.Equal(t, clientA, rt.ClientID)

		second, err := env.m.RefreshAccessToken(ctx, first.RefreshToken, clientA, nil)
		require.NoError(t, err)
		at2, _ := env.sm.GetAccessTokenData(ctx, second.AccessToken)
		require.NotNil(t, at2)
		assert.Equal(t, at.FamilyID, at2.FamilyID, "the family carries over")
	})
}

func TestLegacy_ARefreshTokenIsRevokedWithItsAccessToken(t *testing.T) {
	env := newLegacyEnv(t)
	ctx := context.Background()

	require.NoError(t, env.m.RevokeToken(ctx, "legacy-rt", "refresh_token"))
	assert.False(t, usable(t, env.m, "legacy-at"))
	rt, _ := env.sm.GetRefreshTokenData(ctx, "legacy-rt")
	assert.Nil(t, rt)
	_, err := env.m.RefreshAccessToken(ctx, "legacy-rt", clientA, nil)
	assert.Error(t, err)

	// Revoking again, or an unknown token, is a success.
	require.NoError(t, env.m.RevokeToken(ctx, "legacy-rt", "refresh_token"))
}

// Nothing links a legacy access token to its refresh token (the refresh record
// names the access token, not the other way round), so revoking it revokes it
// alone, until the grant is given a family by its next refresh.
func TestLegacy_AnAccessTokenIsRevokedAlone(t *testing.T) {
	env := newLegacyEnv(t)
	ctx := context.Background()

	require.NoError(t, env.m.RevokeToken(ctx, "legacy-at", "access_token"))
	assert.False(t, usable(t, env.m, "legacy-at"))
	rt, _ := env.sm.GetRefreshTokenData(ctx, "legacy-rt")
	assert.NotNil(t, rt, "the refresh token is still there, as it was before this release")
}

func TestLegacy_ARevocationDuringTheRefreshOfALegacyTokenIssuesNothing(t *testing.T) {
	env := newLegacyEnv(t)
	ctx := context.Background()

	var revokeErr error
	env.fb.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		revokeErr = env.m.RevokeToken(ctx, "legacy-rt", "refresh_token")
		assert.False(t, usable(t, env.m, "legacy-at"), "dead as soon as the revocation returned")
		return validFirebaseResult()
	}
	got, err := env.m.RefreshAccessToken(ctx, "legacy-rt", clientA, nil)
	require.NoError(t, revokeErr)
	assert.Error(t, err)
	assert.Nil(t, got)
	assert.Empty(t, liveTokenKeys(env.mr))
}

// After a legacy grant is rotated, its old tokens lead to the new family: the
// old access token, revoked later, takes the successors with it.
func TestLegacy_AnOldTokenRevokedAfterTheRotationEndsTheNewGrant(t *testing.T) {
	for _, old := range []string{"legacy-at", "legacy-rt"} {
		t.Run(old, func(t *testing.T) {
			env := newLegacyEnv(t)
			ctx := context.Background()
			got, err := env.m.RefreshAccessToken(ctx, "legacy-rt", "", nil)
			require.NoError(t, err)

			require.NoError(t, env.m.RevokeToken(ctx, old, ""))
			assert.False(t, usable(t, env.m, got.AccessToken))
			rt, _ := env.sm.GetRefreshTokenData(ctx, got.RefreshToken)
			assert.Nil(t, rt)
			assert.Empty(t, liveTokenKeys(env.mr))
		})
	}
}

// A rotated legacy token is gone like any other: it does not refresh twice.
func TestLegacy_ARotatedTokenIsNotRefreshableTwice(t *testing.T) {
	env := newLegacyEnv(t)
	ctx := context.Background()
	first, err := env.m.RefreshAccessToken(ctx, "legacy-rt", clientA, nil)
	require.NoError(t, err)
	_, err = env.m.RefreshAccessToken(ctx, "legacy-rt", clientA, nil)
	assert.Error(t, err)
	at, _ := env.sm.GetAccessTokenData(ctx, first.AccessToken)
	require.NotNil(t, at)
	assert.NotEmpty(t, at.FamilyID)
}

// The family marker alone is enough to reject a token whose record is still
// there (a record that could not be named when the grant was revoked).
func TestFamilyMarkerAloneRejectsTheTokensOfAGrant(t *testing.T) {
	stateManager, mr := setupTestStateManager(t)
	m := NewManager(stateManager, newMockFirebaseClient(), testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
	ctx := context.Background()
	issued := issueFor(t, m, clientA)
	rt, err := stateManager.GetRefreshTokenData(ctx, issued.RefreshToken)
	require.NoError(t, err)
	require.True(t, usable(t, m, issued.AccessToken))

	mr.Set(state.RevokedFamilyPrefix+rt.FamilyID, "1")

	assert.False(t, usable(t, m, issued.AccessToken), "the access token record is there, the grant is revoked")
	intro, err := m.IntrospectToken(ctx, issued.AccessToken)
	require.NoError(t, err)
	assert.False(t, intro.Active)
	_, err = m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	assert.ErrorIs(t, err, ErrRefreshRevoked)
	// Nothing can be extended for it either.
	at, _ := stateManager.GetAccessTokenData(ctx, issued.AccessToken)
	updated, err := stateManager.UpdateAccessToken(ctx, at)
	require.NoError(t, err)
	assert.False(t, updated)
}

// A grant's tokens are traceable from the moment they are issued.
func TestIssuedTokensAreIndexedUnderTheirGrant(t *testing.T) {
	stateManager, mr := setupTestStateManager(t)
	m := NewManager(stateManager, newMockFirebaseClient(), testLogger())
	ctx := context.Background()
	issued := issueFor(t, m, clientA)
	rt, err := stateManager.GetRefreshTokenData(ctx, issued.RefreshToken)
	require.NoError(t, err)

	assert.Equal(t, issued.AccessToken, mr.HGet(state.FamilyPrefix+rt.FamilyID, "at"))
	assert.Equal(t, issued.RefreshToken, mr.HGet(state.FamilyPrefix+rt.FamilyID, "rt"))
}
