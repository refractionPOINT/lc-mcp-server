package state

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/refractionpoint/lc-mcp-go/internal/crypto"
	"github.com/refractionpoint/lc-mcp-go/internal/redis"
	"github.com/refractionpoint/lc-mcp-go/internal/redis/faultproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Redis client sends a command again when its reply is lost, and the lost
// attempt may already have run. A create-only write (SET NX) then finds its own
// record and used to report a conflict, failing a sign-in step that had worked.
// These tests lose the reply to the write and check the step still succeeds,
// with the record stored once, and that another writer's value is still refused.

// proxiedManager is a state manager whose Redis traffic crosses a fault proxy,
// with the client's normal retry behaviour.
func proxiedManager(t *testing.T) (*Manager, *faultproxy.Proxy, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	proxy := faultproxy.New(t, mr.Addr())

	rc, err := redis.New(&redis.Config{URL: "redis://" + proxy.Addr()}, testLogger())
	require.NoError(t, err)

	// t.Setenv restores any previous value when the test ends.
	t.Setenv("REDIS_ENCRYPTION_KEY", generateEncryptionKey(t))
	enc, err := crypto.NewTokenEncryption(testLogger())
	require.NoError(t, err)
	return NewManager(rc, enc, testLogger()), proxy, mr
}

// writesKeyWhere recognises the command that creates a key accepted by want: a
// script naming it, or a plain SET / SETNX.
func writesKeyWhere(want func(key string) bool) func(faultproxy.Request) bool {
	return func(r faultproxy.Request) bool {
		for _, k := range r.Keys() {
			if want(k) {
				return true
			}
		}
		return (r.Name() == "SET" || r.Name() == "SETNX") && len(r.Args) > 1 && want(r.Args[1])
	}
}

func writesKey(key string) func(faultproxy.Request) bool {
	return writesKeyWhere(func(k string) bool { return k == key })
}

func writesKeyWithPrefix(prefix string) func(faultproxy.Request) bool {
	return writesKeyWhere(func(k string) bool { return strings.HasPrefix(k, prefix) })
}

// loseTheReplyOf drops the reply to the first command that matches and has run
// (an error reply, such as a script the server does not know yet, ran nothing),
// as a network does after the server has acted. The returned counter says how
// many replies were lost.
func loseTheReplyOf(p *faultproxy.Proxy, match func(faultproxy.Request) bool) *atomic.Int32 {
	var lost atomic.Int32
	p.OnReply(func(r faultproxy.Request, rep faultproxy.Reply) faultproxy.Verdict {
		if match(r) && !rep.IsError() && lost.CompareAndSwap(0, 1) {
			return faultproxy.DropReply()
		}
		return faultproxy.Pass()
	})
	return &lost
}

func TestCreateOnly_ALostReplyDoesNotFailTheStep(t *testing.T) {
	ctx := context.Background()
	challenge, method := "c", "S256"

	t.Run("authorization code", func(t *testing.T) {
		m, proxy, _ := proxiedManager(t)
		lost := loseTheReplyOf(proxy, writesKey(CodePrefix+"code-1"))

		code := NewAuthorizationCode("code-1", "s", "uid-1", "id", "rt", time.Now().Unix()+60, "https://a/cb", "client-a", "openid", &challenge, &method)
		require.NoError(t, m.StoreAuthorizationCode(ctx, code), "the code was stored; the repeat of the write must not call it a conflict")
		assert.EqualValues(t, 1, lost.Load(), "the fault happened")

		proxy.Reset()
		got, err := m.ConsumeAuthorizationCode(ctx, "code-1")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "uid-1", got.UID)
	})

	t.Run("client registration", func(t *testing.T) {
		m, proxy, _ := proxiedManager(t)
		lost := loseTheReplyOf(proxy, writesKey(ClientPrefix+"mcp_x"))

		require.NoError(t, m.StoreClientRegistration(ctx, NewClientRegistration("mcp_x", "Real", []string{"https://real.example.com/cb"})))
		assert.EqualValues(t, 1, lost.Load())

		proxy.Reset()
		got, err := m.GetClientRegistration(ctx, "mcp_x")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, []string{"https://real.example.com/cb"}, got.RedirectURIs)
	})

	t.Run("selection session", func(t *testing.T) {
		m, proxy, _ := proxiedManager(t)
		lost := loseTheReplyOf(proxy, writesKey(SelectionPrefix+"sel-1"))

		require.NoError(t, m.CreateSelectionSession(ctx, "sel-1", map[string]string{"client_id": "c"}))
		assert.EqualValues(t, 1, lost.Load())

		proxy.Reset()
		got, err := m.GetSelectionSession(ctx, "sel-1")
		require.NoError(t, err)
		assert.Equal(t, "c", got["client_id"])
	})

	t.Run("MFA session", func(t *testing.T) {
		m, proxy, _ := proxiedManager(t)
		lost := loseTheReplyOf(proxy, writesKey(MFAPrefix+"mfa-1"))

		require.NoError(t, m.StoreMFASession(ctx, "mfa-1", NewMFASession("pending-1", "enroll", "tx", "User", "uid-1", "a@example.com", nil)))
		assert.EqualValues(t, 1, lost.Load())

		proxy.Reset()
		got, err := m.GetMFASession(ctx, "mfa-1")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "uid-1", got.LocalID)
	})

	t.Run("provider round trip mappings", func(t *testing.T) {
		for name, key := range map[string]string{
			"state mapping":   SelectionPrefix + "oauth:state:fb-1",
			"session mapping": SelectionPrefix + "oauth:fbsession:fb-1",
		} {
			t.Run(name, func(t *testing.T) {
				m, proxy, mr := proxiedManager(t)
				lost := loseTheReplyOf(proxy, writesKey(key))

				require.NoError(t, m.StoreOAuthMappings(ctx, "fb-1", "tx-1", "sess-1"))
				assert.EqualValues(t, 1, lost.Load())
				assert.True(t, exists(mr, SelectionPrefix+"oauth:state:fb-1", SelectionPrefix+"oauth:fbsession:fb-1"))

				proxy.Reset()
				tx, sess, err := m.ConsumeOAuthStateMappings(ctx, "fb-1")
				require.NoError(t, err)
				assert.Equal(t, "tx-1", tx)
				assert.Equal(t, "sess-1", sess)
			})
		}
	})

	t.Run("authorization transaction is stored once under the id it returns", func(t *testing.T) {
		m, proxy, mr := proxiedManager(t)
		lost := loseTheReplyOf(proxy, writesKeyWithPrefix(StatePrefix))

		id, err := m.CreateOAuthState(ctx, newTx("client-state"))
		require.NoError(t, err)
		assert.EqualValues(t, 1, lost.Load())
		assert.Equal(t, []string{StatePrefix + id}, mr.Keys(), "no orphaned transaction from a regenerated id")

		proxy.Reset()
		got, err := m.GetOAuthState(ctx, id)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "client-state", got.State)
	})

	t.Run("access and refresh token records", func(t *testing.T) {
		m, proxy, _ := proxiedManager(t)
		lost := loseTheReplyOf(proxy, writesKey(TokenPrefix+"at-1"))
		require.NoError(t, m.StoreAccessToken(ctx, newAccess("at-1", "")))
		assert.EqualValues(t, 1, lost.Load())

		lost = loseTheReplyOf(proxy, writesKey(RefreshPrefix+"rt-1"))
		require.NoError(t, m.StoreRefreshToken(ctx, newRefresh("rt-1", "at-1", "")))
		assert.EqualValues(t, 1, lost.Load())

		proxy.Reset()
		at, err := m.GetAccessTokenData(ctx, "at-1")
		require.NoError(t, err)
		assert.NotNil(t, at)
		rt, err := m.GetRefreshTokenData(ctx, "rt-1")
		require.NoError(t, err)
		assert.NotNil(t, rt)
	})
}

// The repeat is told apart from a different writer by the value alone: a record
// under the same id with other content is still a conflict, also when the reply to
// that refused write is lost.
func TestCreateOnly_AnotherWritersValueIsStillRefusedAfterALostReply(t *testing.T) {
	ctx := context.Background()
	m, proxy, _ := proxiedManager(t)
	require.NoError(t, m.CreateSelectionSession(ctx, "sel-1", map[string]string{"client_id": "victim"}))

	lost := loseTheReplyOf(proxy, writesKey(SelectionPrefix+"sel-1"))
	err := m.CreateSelectionSession(ctx, "sel-1", map[string]string{"client_id": "attacker"})
	assert.ErrorIs(t, err, ErrAlreadyExists)
	assert.EqualValues(t, 1, lost.Load())

	proxy.Reset()
	got, err := m.GetSelectionSession(ctx, "sel-1")
	require.NoError(t, err)
	assert.Equal(t, "victim", got["client_id"])
}
