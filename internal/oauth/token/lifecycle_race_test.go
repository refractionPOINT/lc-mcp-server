package token

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests interleave token lifecycle operations deterministically: the
// mocked Firebase call is the point where a refresh is "in flight", and the
// hook runs whatever else is happening to the token at that moment.

func validFirebaseResult() (string, int64, error) {
	return "refreshed-id", time.Now().Add(time.Hour).Unix(), nil
}

// usable reports whether the access token validates.
func usable(t *testing.T, m *Manager, accessToken string) bool {
	t.Helper()
	res, err := m.ValidateAccessToken(context.Background(), accessToken, false)
	require.NoError(t, err)
	return res.Valid
}

// A refresh that is in flight when the token is revoked ("log out", /revoke)
// must not issue usable successors, and nothing of the grant stays usable.
func TestRefreshRace_RevokeDuringRefreshIssuesNothing(t *testing.T) {
	m, sm, mockFB := setupTestManager(t)
	ctx := context.Background()
	issued := issueFor(t, m, clientA)

	mockFB.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		require.NoError(t, m.RevokeToken(ctx, issued.RefreshToken, "refresh_token"))
		return validFirebaseResult()
	}

	got, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	assert.Error(t, err, "a refresh that raced a revocation must fail")
	assert.Nil(t, got)

	rt, _ := sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	assert.Nil(t, rt, "the revoked refresh token is not restored")
	assert.False(t, usable(t, m, issued.AccessToken), "the grant's access token is dead")
	_, err = m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	assert.Error(t, err)
}

// The client-mismatch revocation racing a matching-client refresh: whatever
// order they run in, the family must not end up revoked with a usable
// successor.
func TestRefreshRace_MismatchRevocationDuringMatchingRefresh(t *testing.T) {
	m, sm, mockFB := setupTestManager(t)
	ctx := context.Background()
	issued := issueFor(t, m, clientA)

	var bGot *TokenResponse
	var bErr error
	mockFB.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		// While A (the matching client) is in flight, B presents the same
		// refresh token under another client id.
		bGot, bErr = m.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
		return validFirebaseResult()
	}

	aGot, aErr := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)

	assert.Nil(t, bGot, "the other client gets no tokens")
	assert.Error(t, bErr)
	if errors.Is(bErr, ErrClientMismatch) {
		// B revoked the family: then nothing A holds may work.
		if aErr == nil {
			assert.False(t, usable(t, m, aGot.AccessToken), "successor access token usable after the family was revoked")
			rt, _ := sm.GetRefreshTokenData(ctx, aGot.RefreshToken)
			assert.Nil(t, rt, "successor refresh token usable after the family was revoked")
		}
	} else {
		require.NoError(t, aErr, "A holds the token and is the legitimate client")
		assert.True(t, usable(t, m, aGot.AccessToken))
	}
}

// The mismatch revocation that wins the race leaves nothing for the matching
// client to refresh.
func TestRefreshRace_MismatchFirstThenMatchingRefreshFails(t *testing.T) {
	m, sm, _ := setupTestManager(t)
	ctx := context.Background()
	issued := issueFor(t, m, clientA)

	_, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientB, nil)
	assert.ErrorIs(t, err, ErrClientMismatch)
	got, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	assert.Error(t, err)
	assert.Nil(t, got)

	assert.False(t, usable(t, m, issued.AccessToken))
	rt, _ := sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	assert.Nil(t, rt)
}

// Concurrent refreshes of one token: exactly one succeeds, so one refresh
// token never fathers two families.
func TestRefreshRace_ConcurrentRefreshesOfOneTokenExactlyOneSucceeds(t *testing.T) {
	m, sm, mockFB := setupTestManager(t)
	ctx := context.Background()
	issued := issueFor(t, m, clientA)

	// Hold every request in flight until all of them have started.
	const n = 8
	var started sync.WaitGroup
	started.Add(n)
	var firebaseCalls atomic.Int32
	mockFB.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		firebaseCalls.Add(1)
		time.Sleep(100 * time.Millisecond)
		return validFirebaseResult()
	}

	results := make([]*TokenResponse, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			started.Done()
			started.Wait()
			results[i], errs[i] = m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
		}(i)
	}
	wg.Wait()

	var winners []*TokenResponse
	for i := range results {
		if errs[i] == nil {
			winners = append(winners, results[i])
		}
	}
	require.Len(t, winners, 1, "exactly one refresh of a token may succeed")
	assert.EqualValues(t, 1, firebaseCalls.Load(), "the losers never reach Firebase")
	assert.True(t, usable(t, m, winners[0].AccessToken))
	rt, _ := sm.GetRefreshTokenData(ctx, winners[0].RefreshToken)
	assert.NotNil(t, rt)
}

// A refresh that fails for a transient reason after the claim puts the token
// back, with its remaining lifetime, so the legitimate client just retries.
func TestRefreshRace_TransientFailureRestoresTheToken(t *testing.T) {
	m, sm, mockFB := setupTestManager(t)
	ctx := context.Background()
	issued := issueFor(t, m, clientA)

	fail := true
	mockFB.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		if fail {
			return "", 0, errors.New("firebase unavailable")
		}
		return validFirebaseResult()
	}

	_, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.Error(t, err)

	rt, _ := sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	require.NotNil(t, rt, "the refresh token is back after a transient failure")
	assert.Equal(t, clientA, rt.ClientID)
	assert.True(t, usable(t, m, issued.AccessToken), "the access token was never touched")

	fail = false
	got, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, err, "the legitimate client retries successfully")
	assert.True(t, usable(t, m, got.AccessToken))
}

func TestRefreshRace_RestoredTokenKeepsItsRemainingLifetime(t *testing.T) {
	stateManager, mr := setupTestStateManager(t)
	mockFB := newMockFirebaseClient()
	m := NewManager(stateManager, mockFB, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
	ctx := context.Background()
	issued := issueFor(t, m, clientA)

	// 10 days into the refresh token's 30.
	mr.FastForward(10 * 24 * time.Hour)
	key := state.RefreshPrefix + issued.RefreshToken
	before := mr.TTL(key)
	require.Greater(t, before, 19*24*time.Hour)

	mockFB.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		return "", 0, errors.New("firebase unavailable")
	}
	_, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.Error(t, err)

	after := mr.TTL(key)
	assert.LessOrEqual(t, after, before)
	assert.Greater(t, after, before-time.Minute, "restored with the remaining lifetime, not a fresh 30 days")
}

// A token revoked while the refresh is failing is never put back.
func TestRefreshRace_RevokedDuringFailedRefreshIsNotRestored(t *testing.T) {
	m, sm, mockFB := setupTestManager(t)
	ctx := context.Background()
	issued := issueFor(t, m, clientA)

	mockFB.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		require.NoError(t, m.RevokeToken(ctx, issued.RefreshToken, ""))
		return "", 0, errors.New("firebase unavailable")
	}

	_, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.Error(t, err)

	rt, _ := sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	assert.Nil(t, rt, "a revoked token is never restored")
	assert.False(t, usable(t, m, issued.AccessToken))
}

// ===== Access token updates racing revocation =====

// storeExpiring stores an access token that is due for extension.
func storeExpiring(t *testing.T, sm *state.Manager, id string, expiresIn time.Duration, fbExpiresIn time.Duration) {
	t.Helper()
	data := state.NewAccessTokenData(id, "user", "fb-id", "fb-refresh", time.Now().Add(fbExpiresIn).Unix(), "openid", state.TokenTTL)
	data.ExpiresAt = time.Now().Add(expiresIn).Unix()
	require.NoError(t, sm.StoreAccessToken(context.Background(), data))
}

// An automatic extension that is in flight when the token is revoked must not
// bring it back.
func TestExtensionRace_ProactiveExtensionDoesNotResurrectARevokedToken(t *testing.T) {
	m, sm, mockFB := setupTestManager(t)
	ctx := context.Background()
	storeExpiring(t, sm, "at-proactive", 30*time.Minute, time.Hour) // inside the refresh buffer

	mockFB.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		require.NoError(t, sm.RevokeAccessToken(ctx, "at-proactive"))
		return validFirebaseResult()
	}

	res, err := m.ValidateAccessToken(ctx, "at-proactive", true)
	require.NoError(t, err)
	assert.False(t, res.Valid, "a token revoked during its extension is not valid")

	at, _ := sm.GetAccessTokenData(ctx, "at-proactive")
	assert.Nil(t, at, "the extension did not re-create the revoked record")
	assert.False(t, usable(t, m, "at-proactive"))
}

func TestExtensionRace_GracePeriodRecoveryDoesNotResurrectARevokedToken(t *testing.T) {
	m, sm, mockFB := setupTestManager(t)
	ctx := context.Background()
	storeExpiring(t, sm, "at-grace", -time.Hour, time.Hour) // expired, inside the grace period

	mockFB.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		require.NoError(t, sm.RevokeAccessToken(ctx, "at-grace"))
		return validFirebaseResult()
	}

	res, err := m.ValidateAccessToken(ctx, "at-grace", true)
	require.NoError(t, err)
	assert.False(t, res.Valid)

	at, _ := sm.GetAccessTokenData(ctx, "at-grace")
	assert.Nil(t, at, "the recovery did not re-create the revoked record")
}

// The Firebase-only refresh path is conditional too.
func TestExtensionRace_FirebaseRefreshDoesNotResurrectARevokedToken(t *testing.T) {
	m, sm, mockFB := setupTestManager(t)
	ctx := context.Background()
	storeExpiring(t, sm, "at-fb", 20*time.Hour, 2*time.Minute) // MCP token fine, Firebase token about to expire

	mockFB.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		require.NoError(t, sm.RevokeAccessToken(ctx, "at-fb"))
		return validFirebaseResult()
	}

	res, err := m.ValidateAccessToken(ctx, "at-fb", true)
	require.NoError(t, err)
	assert.False(t, res.Valid)
	at, _ := sm.GetAccessTokenData(ctx, "at-fb")
	assert.Nil(t, at)
}

// Normal extension still works, and keeps a TTL.
func TestExtensionRace_NormalExtensionStillWorks(t *testing.T) {
	m, sm, mockFB := setupTestManager(t)
	ctx := context.Background()
	storeExpiring(t, sm, "at-normal", 30*time.Minute, time.Hour)
	before, _ := sm.GetAccessTokenData(ctx, "at-normal")
	require.NotNil(t, before)

	mockFB.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		return "new-id-token", time.Now().Add(time.Hour).Unix(), nil
	}
	res, err := m.ValidateAccessToken(ctx, "at-normal", true)
	require.NoError(t, err)
	require.True(t, res.Valid)
	assert.True(t, res.Refreshed)

	after, _ := sm.GetAccessTokenData(ctx, "at-normal")
	require.NotNil(t, after)
	assert.Equal(t, 1, after.ExtensionCount)
	assert.Equal(t, "new-id-token", after.FirebaseIDToken)
	assert.Greater(t, after.ExpiresAt, before.ExpiresAt)
}

// ===== /revoke =====

// Revoking an access token ends its grant, like revoking the refresh token
// does: the grant is found from either token, and leaving the refresh token
// alive would let whoever holds it mint the access token again. (This replaces
// TestRevoke_AccessTokenOnlyRevokesThatToken, which asserted the opposite.)
func TestRevoke_AccessTokenRevokesTheWholeGrant(t *testing.T) {
	m, sm, _ := setupTestManager(t)
	ctx := context.Background()
	issued := issueFor(t, m, clientA)
	rt, _ := sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	require.NotNil(t, rt)
	family := rt.FamilyID

	require.NoError(t, m.RevokeToken(ctx, issued.AccessToken, "access_token"))
	assert.False(t, usable(t, m, issued.AccessToken))
	rt, _ = sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	assert.Nil(t, rt, "the refresh token goes with the access token")
	revoked, err := sm.IsFamilyRevoked(ctx, family)
	require.NoError(t, err)
	assert.True(t, revoked)
	_, err = m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	assert.Error(t, err)
}

// An unauthenticated /revoke of made-up tokens must not leave records behind.
func TestRevoke_UnknownTokensLeaveNothingBehind(t *testing.T) {
	stateManager, mr := setupTestStateManager(t)
	m := NewManager(stateManager, newMockFirebaseClient(), testLogger())
	for i := 0; i < 20; i++ {
		require.NoError(t, m.RevokeToken(context.Background(), "made-up-"+string(rune('a'+i)), ""))
	}
	assert.Empty(t, mr.Keys())
}
