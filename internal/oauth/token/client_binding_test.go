package token

import (
	"context"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	clientA = "client-a"
	clientB = "client-b"
)

func issueFor(t *testing.T, m *Manager, client string) *TokenResponse {
	t.Helper()
	resp, err := m.CreateTokenResponse(context.Background(), "user", "fb-id", "fb-refresh", time.Now().Add(time.Hour).Unix(), "openid", "", client)
	require.NoError(t, err)
	return resp
}

func TestClientBinding_IssuedTokensCarryTheClient(t *testing.T) {
	m, sm, _ := setupTestManager(t)
	ctx := context.Background()
	issued := issueFor(t, m, clientA)

	at, err := sm.GetAccessTokenData(ctx, issued.AccessToken)
	require.NoError(t, err)
	require.NotNil(t, at)
	rt, err := sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	require.NoError(t, err)
	require.NotNil(t, rt)
	assert.Equal(t, clientA, at.ClientID)
	assert.Equal(t, clientA, rt.ClientID)

	intro, err := m.IntrospectToken(ctx, issued.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, clientA, intro.ClientID)
}

func TestClientBinding_SameClientRefreshesAndRotationKeepsTheBinding(t *testing.T) {
	m, sm, _ := setupTestManager(t)
	ctx := context.Background()
	issued := issueFor(t, m, clientA)

	for i := 0; i < 3; i++ {
		got, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
		require.NoError(t, err)
		at, _ := sm.GetAccessTokenData(ctx, got.AccessToken)
		rt, _ := sm.GetRefreshTokenData(ctx, got.RefreshToken)
		require.NotNil(t, at)
		require.NotNil(t, rt)
		assert.Equal(t, clientA, at.ClientID)
		assert.Equal(t, clientA, rt.ClientID)
		issued = got
	}
}

// Another client presenting the refresh token is refused before anything is
// refreshed or rotated, and the token family is revoked: the secret has been
// seen in the wrong hands, and the holder does not get to try other client ids.
func TestClientBinding_DifferentClientIsRefusedAndTheFamilyRevoked(t *testing.T) {
	m, sm, mockFB := setupTestManager(t)
	ctx := context.Background()
	issued := issueFor(t, m, clientA)

	refreshed := false
	mockFB.refreshIDTokenFunc = func(ctx context.Context, refreshToken string) (string, int64, error) {
		refreshed = true
		return "new-id", time.Now().Add(time.Hour).Unix(), nil
	}

	got, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, ErrClientMismatch)
	assert.False(t, refreshed, "nothing was refreshed for the refused request")

	rt, _ := sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	assert.Nil(t, rt, "the refresh token is revoked")
	at, _ := sm.GetAccessTokenData(ctx, issued.AccessToken)
	assert.Nil(t, at, "and so is its access token")

	// The legitimate client has to sign in again; the holder gains nothing by retrying.
	_, err = m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	assert.Error(t, err)
}

// A bound token presented with no client_id is refused too, but left alone: it
// is the shape of a client that omits client_id, not of someone guessing.
func TestClientBinding_MissingClientIsRefusedButTheTokenIsKept(t *testing.T) {
	m, sm, _ := setupTestManager(t)
	ctx := context.Background()
	issued := issueFor(t, m, clientA)

	got, err := m.RefreshAccessToken(ctx, issued.RefreshToken, "", nil)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, ErrClientMismatch)
	rt, _ := sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	assert.NotNil(t, rt)

	_, err = m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	assert.NoError(t, err)
}

// Refresh tokens that are in Redis from before client binding have no client_id.
// Whoever is signed in with one keeps working, whatever client_id they send, and
// the rotated token is bound to it.
func TestClientBinding_LegacyTokenIsAcceptedAndStamped(t *testing.T) {
	m, sm, _ := setupTestManager(t)
	ctx := context.Background()
	storeLegacy := func(id string) {
		require.NoError(t, sm.StoreRefreshToken(ctx, state.NewRefreshTokenData(id, "legacy-at", "user", "fb-refresh", "openid")))
	}

	t.Run("presented client is stamped", func(t *testing.T) {
		storeLegacy("legacy-1")
		got, err := m.RefreshAccessToken(ctx, "legacy-1", clientA, nil)
		require.NoError(t, err)
		at, _ := sm.GetAccessTokenData(ctx, got.AccessToken)
		rt, _ := sm.GetRefreshTokenData(ctx, got.RefreshToken)
		require.NotNil(t, at)
		require.NotNil(t, rt)
		assert.Equal(t, clientA, at.ClientID)
		assert.Equal(t, clientA, rt.ClientID)

		// From now on it is bound like any other.
		_, err = m.RefreshAccessToken(ctx, got.RefreshToken, clientB, nil)
		assert.ErrorIs(t, err, ErrClientMismatch)
	})

	t.Run("no client presented stays legacy", func(t *testing.T) {
		storeLegacy("legacy-2")
		got, err := m.RefreshAccessToken(ctx, "legacy-2", "", nil)
		require.NoError(t, err)
		rt, _ := sm.GetRefreshTokenData(ctx, got.RefreshToken)
		require.NotNil(t, rt)
		assert.Empty(t, rt.ClientID)
		_, err = m.RefreshAccessToken(ctx, got.RefreshToken, clientB, nil)
		assert.NoError(t, err, "still accepted, and bound to the next client that names itself")
	})
}

func TestClientBinding_RefusedResourceDoesNotBindOrRevoke(t *testing.T) {
	m, sm, _ := setupTestManager(t)
	ctx := context.Background()
	require.NoError(t, sm.StoreRefreshToken(ctx, state.NewRefreshTokenData("legacy-3", "legacy-at", "user", "fb-refresh", "openid")))

	_, err := m.RefreshAccessToken(ctx, "legacy-3", clientA, func(string) (string, error) { return "", ErrInvalidTarget })
	assert.ErrorIs(t, err, ErrInvalidTarget)
	rt, _ := sm.GetRefreshTokenData(ctx, "legacy-3")
	require.NotNil(t, rt)
	assert.Empty(t, rt.ClientID, "a refused request binds nothing")
}

func TestClientBinding_IntrospectionOfALegacyTokenKeepsTheOldClientID(t *testing.T) {
	m, sm, _ := setupTestManager(t)
	ctx := context.Background()
	require.NoError(t, sm.StoreAccessToken(ctx, state.NewAccessTokenData("legacy-access", "user", "id", "rt", time.Now().Add(time.Hour).Unix(), "openid", state.TokenTTL)))
	intro, err := m.IntrospectToken(ctx, "legacy-access")
	require.NoError(t, err)
	assert.Equal(t, "mcp", intro.ClientID)
}
