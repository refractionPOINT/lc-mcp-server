package state

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTx(clientState string) *OAuthState {
	return NewOAuthState(clientState, "challenge", "S256", "https://app.example.com/cb", "client", "openid", "", "google.com")
}

func TestCreateOAuthState_IdsAreServerGeneratedAndUnique(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()

	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		st := newTx("identical-client-state")
		id, err := m.CreateOAuthState(ctx, st)
		require.NoError(t, err)
		assert.Len(t, id, 44, "32 random bytes, base64")
		assert.NotContains(t, id, "identical")
		assert.Equal(t, id, st.TxID)
		assert.False(t, seen[id], "ids never repeat")
		seen[id] = true
	}
	assert.Len(t, mr.Keys(), 200, "identical client states do not overwrite each other")
}

func TestCreateOAuthState_StateIsDataNotKey(t *testing.T) {
	m, _ := setupTestManager(t)
	ctx := context.Background()
	id, err := m.CreateOAuthState(ctx, newTx("some-state"))
	require.NoError(t, err)

	byState, err := m.GetOAuthState(ctx, "some-state")
	require.NoError(t, err)
	assert.Nil(t, byState, "the client's state finds nothing")

	got, err := m.GetOAuthState(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "some-state", got.State)
	assert.Equal(t, id, got.TxID)
}

func TestCreateOnlyRecordsAreNeverOverwritten(t *testing.T) {
	m, _ := setupTestManager(t)
	ctx := context.Background()

	t.Run("raw create-only", func(t *testing.T) {
		require.NoError(t, m.createOnly(ctx, StatePrefix+"fixed", "first", 60))
		assert.ErrorIs(t, m.createOnly(ctx, StatePrefix+"fixed", "second", 60), ErrAlreadyExists)
		v, _ := m.GetEphemeral(ctx, StatePrefix+"fixed")
		assert.Equal(t, "first", v)
	})

	t.Run("selection session", func(t *testing.T) {
		require.NoError(t, m.CreateSelectionSession(ctx, "sel-1", map[string]string{"client_id": "victim"}))
		err := m.CreateSelectionSession(ctx, "sel-1", map[string]string{"client_id": "attacker"})
		assert.ErrorIs(t, err, ErrAlreadyExists)
		got, _ := m.GetSelectionSession(ctx, "sel-1")
		assert.Equal(t, "victim", got["client_id"])
	})

	t.Run("MFA session", func(t *testing.T) {
		first := NewMFASession("pending-1", "enroll", "tx", "User", "uid-1", "a@example.com", nil)
		require.NoError(t, m.StoreMFASession(ctx, "mfa-1", first))
		err := m.StoreMFASession(ctx, "mfa-1", NewMFASession("pending-2", "enroll", "tx2", "User", "uid-2", "b@example.com", nil))
		assert.ErrorIs(t, err, ErrAlreadyExists)
		got, _ := m.GetMFASession(ctx, "mfa-1")
		require.NotNil(t, got)
		assert.Equal(t, "uid-1", got.LocalID)
	})

	t.Run("authorization code", func(t *testing.T) {
		ch, method := "c", "S256"
		first := NewAuthorizationCode("code-1", "s", "uid-1", "id", "rt", time.Now().Unix()+60, "https://a/cb", "client-a", "openid", &ch, &method)
		require.NoError(t, m.StoreAuthorizationCode(ctx, first))
		other := NewAuthorizationCode("code-1", "s", "uid-2", "id", "rt", time.Now().Unix()+60, "https://evil/cb", "client-b", "openid", &ch, &method)
		assert.ErrorIs(t, m.StoreAuthorizationCode(ctx, other), ErrAlreadyExists)
		got, err := m.ConsumeAuthorizationCode(ctx, "code-1")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "uid-1", got.UID)
		assert.Equal(t, "client-a", got.ClientID)
	})

	t.Run("client registration", func(t *testing.T) {
		require.NoError(t, m.StoreClientRegistration(ctx, NewClientRegistration("mcp_x", "Real", []string{"https://real.example.com/cb"})))
		err := m.StoreClientRegistration(ctx, NewClientRegistration("mcp_x", "Replaced", []string{"https://evil.example.com/cb"}))
		assert.ErrorIs(t, err, ErrAlreadyExists)
		got, _ := m.GetClientRegistration(ctx, "mcp_x")
		require.NotNil(t, got)
		assert.Equal(t, []string{"https://real.example.com/cb"}, got.RedirectURIs)
	})
}

func TestStoreOAuthMappings(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()

	t.Run("round trip", func(t *testing.T) {
		require.NoError(t, m.StoreOAuthMappings(ctx, "fb-1", "tx-1", "sess-1"))
		tx, sess, err := m.ConsumeOAuthStateMappings(ctx, "fb-1")
		require.NoError(t, err)
		assert.Equal(t, "tx-1", tx)
		assert.Equal(t, "sess-1", sess)
		_, _, err = m.ConsumeOAuthStateMappings(ctx, "fb-1")
		assert.Error(t, err, "single use")
	})

	t.Run("a firebase state in use is not taken over", func(t *testing.T) {
		require.NoError(t, m.StoreOAuthMappings(ctx, "fb-2", "tx-victim", "sess-victim"))
		err := m.StoreOAuthMappings(ctx, "fb-2", "tx-attacker", "sess-attacker")
		assert.ErrorIs(t, err, ErrAlreadyExists)
		tx, sess, err := m.ConsumeOAuthStateMappings(ctx, "fb-2")
		require.NoError(t, err)
		assert.Equal(t, "tx-victim", tx)
		assert.Equal(t, "sess-victim", sess)
	})

	t.Run("a half-taken state fails and removes only what it wrote", func(t *testing.T) {
		require.NoError(t, m.CreateSelectionSession(ctx, "oauth:fbsession:fb-3", map[string]string{"session_id": "other"}))
		err := m.StoreOAuthMappings(ctx, "fb-3", "tx-3", "sess-3")
		assert.ErrorIs(t, err, ErrAlreadyExists)
		assert.False(t, mr.Exists(SelectionPrefix+"oauth:state:fb-3"), "the mapping this call wrote is removed")
		assert.True(t, mr.Exists(SelectionPrefix+"oauth:fbsession:fb-3"), "the one it did not write stays")
	})

	t.Run("requires a state and a transaction", func(t *testing.T) {
		assert.Error(t, m.StoreOAuthMappings(ctx, "", "tx", "s"))
		assert.Error(t, m.StoreOAuthMappings(ctx, "fb", "", "s"))
	})

	t.Run("mappings expire", func(t *testing.T) {
		require.NoError(t, m.StoreOAuthMappings(ctx, "fb-4", "tx-4", "sess-4"))
		mr.FastForward((SelectionTTL + 1) * time.Second)
		_, _, err := m.ConsumeOAuthStateMappings(ctx, "fb-4")
		assert.Error(t, err)
	})
}

func TestUpdateSelectionSession(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()

	require.NoError(t, m.CreateSelectionSession(ctx, "s", map[string]string{"a": "1"}))
	mr.FastForward(100 * time.Second)
	ttlBefore := mr.TTL(SelectionPrefix + "s")

	require.NoError(t, m.UpdateSelectionSession(ctx, "s", map[string]string{"a": "2"}))
	got, _ := m.GetSelectionSession(ctx, "s")
	assert.Equal(t, "2", got["a"])
	assert.Equal(t, ttlBefore, mr.TTL(SelectionPrefix+"s"), "the expiry is not extended")

	t.Run("a consumed session is not resurrected", func(t *testing.T) {
		_, err := m.ConsumeSelectionSession(ctx, "s")
		require.NoError(t, err)
		assert.ErrorIs(t, m.UpdateSelectionSession(ctx, "s", map[string]string{"a": "3"}), ErrSelectionSessionGone)
		got, _ := m.GetSelectionSession(ctx, "s")
		assert.Nil(t, got)
	})
}

func TestRefreshTokenClientIDRoundTrips(t *testing.T) {
	m, _ := setupTestManager(t)
	ctx := context.Background()

	rt := NewRefreshTokenData("rt-1", "at-1", "uid", "fb-rt", "openid")
	rt.ClientID = "client-a"
	require.NoError(t, m.StoreRefreshToken(ctx, rt))
	got, err := m.GetRefreshTokenData(ctx, "rt-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "client-a", got.ClientID)

	// A record written before client binding has no client_id.
	require.NoError(t, m.StoreRefreshToken(ctx, NewRefreshTokenData("rt-2", "at-2", "uid", "fb-rt", "openid")))
	got, _ = m.GetRefreshTokenData(ctx, "rt-2")
	require.NotNil(t, got)
	assert.Empty(t, got.ClientID)
}
