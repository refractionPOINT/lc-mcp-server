package token

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func storeBoundToken(t *testing.T, sm *state.Manager, accessToken, resource string, expiresAt int64) {
	t.Helper()
	data := state.NewAccessTokenData(accessToken, "user", "fb-id", "fb-refresh", time.Now().Add(time.Hour).Unix(), "openid", state.TokenTTL)
	data.ExpiresAt = expiresAt
	data.Resource = resource
	require.NoError(t, sm.StoreAccessToken(context.Background(), data))
}

func TestValidateAccessTokenForAudience(t *testing.T) {
	ctx := context.Background()
	live := time.Now().Add(12 * time.Hour).Unix()

	t.Run("the resource is reported", func(t *testing.T) {
		manager, sm, _ := setupTestManager(t)
		storeBoundToken(t, sm, "bound", "https://mcp.example.com/mcp", live)

		var seen string
		result, err := manager.ValidateAccessTokenForAudience(ctx, "bound", true, func(resource string) error {
			seen = resource
			return nil
		})

		require.NoError(t, err)
		assert.True(t, result.Valid)
		assert.Equal(t, "https://mcp.example.com/mcp", seen)
		assert.Equal(t, "https://mcp.example.com/mcp", result.Resource)
	})

	t.Run("a legacy token is passed to the check with an empty resource", func(t *testing.T) {
		manager, sm, _ := setupTestManager(t)
		storeBoundToken(t, sm, "legacy", "", live)

		seen := "unset"
		result, err := manager.ValidateAccessTokenForAudience(ctx, "legacy", true, func(resource string) error {
			seen = resource
			return nil
		})

		require.NoError(t, err)
		assert.True(t, result.Valid)
		assert.Empty(t, seen)
		assert.Empty(t, result.Resource)
	})

	t.Run("a rejected audience is an invalid, non-transient token", func(t *testing.T) {
		manager, sm, _ := setupTestManager(t)
		storeBoundToken(t, sm, "bound", "https://mcp.example.com/mcp/all", live)

		result, err := manager.ValidateAccessTokenForAudience(ctx, "bound", true, func(string) error {
			return errors.New("wrong endpoint")
		})

		require.NoError(t, err)
		assert.False(t, result.Valid)
		assert.True(t, result.AudienceMismatch)
		assert.False(t, result.Transient)
		assert.Equal(t, "wrong endpoint", result.Error)
		assert.Empty(t, result.UID, "nothing about the token is released")
		assert.Empty(t, result.LimaCharlieJWT)
	})

	t.Run("a rejected audience has no side effects", func(t *testing.T) {
		manager, sm, mockFB := setupTestManager(t)
		refreshed, exchanged := false, false
		mockFB.refreshIDTokenFunc = func(context.Context, string) (string, int64, error) {
			refreshed = true
			return "new", time.Now().Add(time.Hour).Unix(), nil
		}
		manager.WithJWTExchange(func(string, string, *slog.Logger) (string, error) {
			exchanged = true
			return "jwt", nil
		})
		// Both an almost expired token (which would be extended) and one in
		// its grace period (which would be revived).
		storeBoundToken(t, sm, "expiring", "https://mcp.example.com/mcp/all", time.Now().Add(10*time.Minute).Unix())
		storeBoundToken(t, sm, "in-grace", "https://mcp.example.com/mcp/all", time.Now().Add(-time.Hour).Unix())

		for _, tok := range []string{"expiring", "in-grace"} {
			result, err := manager.ValidateAccessTokenForAudience(ctx, tok, true, func(string) error { return errors.New("no") })
			require.NoError(t, err)
			assert.False(t, result.Valid, tok)

			data, err := sm.GetAccessTokenData(ctx, tok)
			require.NoError(t, err)
			require.NotNil(t, data, tok)
			assert.Zero(t, data.ExtensionCount, tok)
		}
		assert.False(t, refreshed, "Firebase must not be called for a rejected token")
		assert.False(t, exchanged, "no JWT may be minted for a rejected token")
	})

	t.Run("an unknown token is invalid whatever the check says", func(t *testing.T) {
		manager, _, _ := setupTestManager(t)
		result, err := manager.ValidateAccessTokenForAudience(ctx, "nope", true, func(string) error { return nil })
		require.NoError(t, err)
		assert.False(t, result.Valid)
		assert.False(t, result.AudienceMismatch)
	})

	t.Run("an extended token keeps its resource", func(t *testing.T) {
		manager, sm, _ := setupTestManager(t)
		storeBoundToken(t, sm, "in-grace", "https://mcp.example.com/mcp/all", time.Now().Add(-time.Hour).Unix())

		result, err := manager.ValidateAccessTokenForAudience(ctx, "in-grace", true, func(string) error { return nil })
		require.NoError(t, err)
		require.True(t, result.Valid)
		assert.True(t, result.Refreshed)
		assert.Equal(t, "https://mcp.example.com/mcp/all", result.Resource)

		data, err := sm.GetAccessTokenData(ctx, "in-grace")
		require.NoError(t, err)
		require.NotNil(t, data)
		assert.Equal(t, "https://mcp.example.com/mcp/all", data.Resource)
		assert.Equal(t, 1, data.ExtensionCount)
	})
}

func TestResourceIsBoundOnIssueAndRotation(t *testing.T) {
	manager, sm, _ := setupTestManager(t)
	ctx := context.Background()
	const mcp, profile = "https://mcp.example.com/mcp", "https://mcp.example.com/mcp/all"

	issued, err := manager.CreateTokenResponse(ctx, "user", "fb-id", "fb-refresh", time.Now().Add(time.Hour).Unix(), "openid", mcp)
	require.NoError(t, err)
	at, _ := sm.GetAccessTokenData(ctx, issued.AccessToken)
	rt, _ := sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	require.NotNil(t, at)
	require.NotNil(t, rt)
	assert.Equal(t, mcp, at.Resource)
	assert.Equal(t, mcp, rt.Resource)

	t.Run("nil resolver keeps the resource", func(t *testing.T) {
		got, err := manager.RefreshAccessToken(ctx, issued.RefreshToken, nil)
		require.NoError(t, err)
		at, _ := sm.GetAccessTokenData(ctx, got.AccessToken)
		rt, _ := sm.GetRefreshTokenData(ctx, got.RefreshToken)
		require.NotNil(t, at)
		require.NotNil(t, rt)
		assert.Equal(t, mcp, at.Resource)
		assert.Equal(t, mcp, rt.Resource)
		issued = got
	})

	t.Run("resolver sees the bound resource and chooses the new one", func(t *testing.T) {
		var authorized string
		got, err := manager.RefreshAccessToken(ctx, issued.RefreshToken, func(a string) (string, error) {
			authorized = a
			return profile, nil
		})
		require.NoError(t, err)
		assert.Equal(t, mcp, authorized)
		at, _ := sm.GetAccessTokenData(ctx, got.AccessToken)
		rt, _ := sm.GetRefreshTokenData(ctx, got.RefreshToken)
		require.NotNil(t, at)
		require.NotNil(t, rt)
		assert.Equal(t, profile, at.Resource)
		assert.Equal(t, profile, rt.Resource)
		issued = got
	})

	t.Run("a refused resource leaves the refresh token usable", func(t *testing.T) {
		got, err := manager.RefreshAccessToken(ctx, issued.RefreshToken, func(string) (string, error) {
			return "", ErrInvalidTarget
		})
		assert.Nil(t, got)
		assert.ErrorIs(t, err, ErrInvalidTarget)
		still, _ := sm.GetRefreshTokenData(ctx, issued.RefreshToken)
		assert.NotNil(t, still)
	})

	t.Run("a legacy refresh token stays legacy", func(t *testing.T) {
		legacy := state.NewRefreshTokenData("legacy-rt", "legacy-at", "user", "fb-refresh", "openid")
		require.NoError(t, sm.StoreRefreshToken(ctx, legacy))

		got, err := manager.RefreshAccessToken(ctx, "legacy-rt", nil)
		require.NoError(t, err)
		at, _ := sm.GetAccessTokenData(ctx, got.AccessToken)
		require.NotNil(t, at)
		assert.Empty(t, at.Resource)
	})
}

func TestIntrospectionReportsAudience(t *testing.T) {
	manager, sm, _ := setupTestManager(t)
	ctx := context.Background()
	live := time.Now().Add(time.Hour).Unix()
	storeBoundToken(t, sm, "bound", "https://mcp.example.com/mcp", live)
	storeBoundToken(t, sm, "legacy", "", live)

	resp, err := manager.IntrospectToken(ctx, "bound")
	require.NoError(t, err)
	assert.Equal(t, "https://mcp.example.com/mcp", resp.Aud)

	resp, err = manager.IntrospectToken(ctx, "legacy")
	require.NoError(t, err)
	assert.Empty(t, resp.Aud)
}
