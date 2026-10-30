package token

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"github.com/refractionpoint/lc-mcp-go/internal/redis"
	"github.com/refractionpoint/lc-mcp-go/internal/redis/faultproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests break the conversation between the server and Redis: a revocation
// that arrives in the middle of a refresh, a cleanup that arrives twice, a
// command whose reply is lost (the Redis client then sends it again, so it runs
// twice). The tests only use the token manager's own API and Redis's wire
// traffic, so they describe the behaviour the lifecycle must have, whatever it
// does to get there.

// faultEnv is one Redis (miniredis) with two ways in: through a proxy that can
// break the conversation, and directly.
type faultEnv struct {
	mr     *miniredis.Miniredis
	proxy  *faultproxy.Proxy
	fb     *mockFirebaseClient // Firebase as the proxied manager sees it
	via    *Manager            // reaches Redis through the proxy
	direct *Manager            // reaches Redis directly: the revoker, the verifier
	sm     *state.Manager      // a direct view of the state
}

// newFaultEnv builds the environment. maxRetries is the Redis client's command
// retry count: 0 keeps the production default (a failed command is sent again),
// -1 turns retries off so that every network failure reaches the caller.
func newFaultEnv(t *testing.T, maxRetries int) *faultEnv {
	t.Helper()
	mr := miniredis.RunT(t)
	proxy := faultproxy.New(t, mr.Addr())
	enc := setupTestEncryption(t)
	logger := testLogger()

	newState := func(addr string) *state.Manager {
		rc, err := redis.New(&redis.Config{URL: "redis://" + addr, MaxRetries: maxRetries}, logger)
		require.NoError(t, err)
		return state.NewManager(rc, enc, logger)
	}
	env := &faultEnv{mr: mr, proxy: proxy, fb: newMockFirebaseClient()}
	env.sm = newState(mr.Addr())
	env.via = NewManager(newState(proxy.Addr()), env.fb, logger).WithJWTExchange(mockJWTExchange("jwt", nil))
	env.direct = NewManager(env.sm, newMockFirebaseClient(), logger).WithJWTExchange(mockJWTExchange("jwt", nil))
	return env
}

// liveTokenKeys are the token records in Redis: the credentials that could
// still be presented.
func liveTokenKeys(mr *miniredis.Miniredis) []string {
	var keys []string
	for _, k := range mr.Keys() {
		if strings.HasPrefix(k, state.TokenPrefix) || strings.HasPrefix(k, state.RefreshPrefix) {
			keys = append(keys, k)
		}
	}
	return keys
}

// isClaim recognises the command that claims a refresh token.
func isClaim(r faultproxy.Request) bool {
	return r.IsScript() && r.HasKeyPrefix(state.RefreshPrefix) && r.HasKeyPrefix(state.RefreshClaimPrefix) && !r.HasKeyPrefix(state.TokenPrefix)
}

// isPublish recognises the command that publishes the successors of a refresh.
func isPublish(r faultproxy.Request) bool {
	return r.IsScript() && r.HasKeyPrefix(state.TokenPrefix) && r.HasKeyPrefix(state.RefreshPrefix)
}

// isRelease recognises the command that gives a claim up: it touches the claim
// and nothing else of the token.
func isRelease(r faultproxy.Request) bool {
	if r.Name() == "DEL" && len(r.Args) == 2 && strings.HasPrefix(r.Args[1], state.RefreshClaimPrefix) {
		return true
	}
	return r.IsScript() && r.HasKeyPrefix(state.RefreshClaimPrefix) && !r.HasKeyPrefix(state.RefreshPrefix) && !r.HasKeyPrefix(state.TokenPrefix)
}

type refreshResult struct {
	resp *TokenResponse
	err  error
}

// refreshAsync runs a refresh in the background.
func refreshAsync(m *Manager, refreshToken string) <-chan refreshResult {
	done := make(chan refreshResult, 1)
	go func() {
		resp, err := m.RefreshAccessToken(context.Background(), refreshToken, clientA, nil)
		done <- refreshResult{resp, err}
	}()
	return done
}

func waitFor[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

// ===== A revocation arrives while a refresh runs =====

// /revoke of a refresh token that is being refreshed must kill the grant right
// away: when it has returned, the access token is dead, not "when the refresh
// has finished and noticed".
func TestFault_RevokeOfARefreshTokenInFlightKillsTheGrantAtOnce(t *testing.T) {
	m, _, fb := setupTestManager(t)
	ctx := context.Background()
	issued := issueFor(t, m, clientA)

	var revokeErr error
	var accessUsable bool
	fb.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		revokeErr = m.RevokeToken(ctx, issued.RefreshToken, "refresh_token")
		accessUsable = usable(t, m, issued.AccessToken) // while the refresh is still running
		return validFirebaseResult()
	}

	got, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, revokeErr)
	assert.False(t, accessUsable, "the access token must be dead as soon as /revoke has returned, with the refresh still in flight")
	assert.Error(t, err)
	assert.Nil(t, got)
}

// A revocation that arrives after the successors were published but before the
// refresh answered the client still reaches them: the old refresh token leads
// to the grant, and the grant is revoked as a whole.
func TestFault_RevokeBetweenPublishAndTheReplyKillsTheSuccessors(t *testing.T) {
	env := newFaultEnv(t, 0)
	ctx := context.Background()
	issued := issueFor(t, env.direct, clientA)

	hold := faultproxy.NewHold()
	var armed atomic.Bool
	armed.Store(true)
	env.proxy.OnReply(func(r faultproxy.Request, rep faultproxy.Reply) faultproxy.Verdict {
		if isPublish(r) && !rep.IsError() && armed.CompareAndSwap(true, false) {
			return faultproxy.WithholdReply(hold) // the successors are stored; the refresh does not know yet
		}
		return faultproxy.Pass()
	})
	done := refreshAsync(env.via, issued.RefreshToken)
	waitFor(t, hold.Executed(), "the publish to run")

	require.NoError(t, env.direct.RevokeToken(ctx, issued.RefreshToken, "refresh_token"))
	hold.Release()
	res := waitFor(t, done, "the refresh to return")

	if res.err == nil {
		assert.False(t, usable(t, env.direct, res.resp.AccessToken), "the successors were published before the revocation and must not survive it")
		_, err := env.direct.RefreshAccessToken(ctx, res.resp.RefreshToken, clientA, nil)
		assert.Error(t, err)
	}
	assert.Empty(t, liveTokenKeys(env.mr), "no credential of the revoked grant is left in Redis")
}

// The same, revoking the old access token.
func TestFault_RevokeOfTheOldAccessTokenBetweenPublishAndTheReplyKillsTheSuccessors(t *testing.T) {
	env := newFaultEnv(t, 0)
	ctx := context.Background()
	issued := issueFor(t, env.direct, clientA)

	hold := faultproxy.NewHold()
	var armed atomic.Bool
	armed.Store(true)
	env.proxy.OnReply(func(r faultproxy.Request, rep faultproxy.Reply) faultproxy.Verdict {
		if isPublish(r) && !rep.IsError() && armed.CompareAndSwap(true, false) {
			return faultproxy.WithholdReply(hold)
		}
		return faultproxy.Pass()
	})
	done := refreshAsync(env.via, issued.RefreshToken)
	waitFor(t, hold.Executed(), "the publish to run")

	require.NoError(t, env.direct.RevokeToken(ctx, issued.AccessToken, "access_token"))
	hold.Release()
	res := waitFor(t, done, "the refresh to return")

	if res.err == nil {
		assert.False(t, usable(t, env.direct, res.resp.AccessToken))
	}
	assert.Empty(t, liveTokenKeys(env.mr))
}

// ===== Cleanup that does not belong to the attempt that runs it =====

// An attempt's cleanup can arrive again later (the Redis client sends a command
// whose reply was lost once more, after a pause). By then another attempt holds
// the token; the stale cleanup must not touch its claim, or a revocation could
// no longer see that a refresh is running and the refresh would publish.
func TestFault_ALateCleanupOfAnEarlierAttemptCannotDisturbALaterOne(t *testing.T) {
	env := newFaultEnv(t, 0)
	ctx := context.Background()
	issued := issueFor(t, env.direct, clientA)

	var mu sync.Mutex
	var cleanup *faultproxy.Request
	env.proxy.OnRequest(func(r faultproxy.Request) bool {
		if isRelease(r) {
			mu.Lock()
			if cleanup == nil {
				c := r
				cleanup = &c
			}
			mu.Unlock()
		}
		return false
	})

	// Attempt A fails (Firebase is down) and cleans up after itself.
	env.fb.refreshIDTokenFunc = func(context.Context, string) (string, int64, error) {
		return "", 0, errors.New("firebase unavailable")
	}
	_, err := env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.Error(t, err)
	mu.Lock()
	captured := cleanup
	mu.Unlock()
	require.NotNil(t, captured, "attempt A's cleanup went over the wire")

	// Attempt B takes the token and is in flight.
	inFlight, proceed := make(chan struct{}), make(chan struct{})
	env.fb.refreshIDTokenFunc = func(context.Context, string) (string, int64, error) {
		close(inFlight)
		<-proceed
		return validFirebaseResult()
	}
	done := refreshAsync(env.via, issued.RefreshToken)
	waitFor(t, inFlight, "attempt B to start")

	// A's cleanup arrives a second time. Then the user revokes.
	_, err = env.proxy.Send(captured.Raw)
	require.NoError(t, err)
	require.NoError(t, env.direct.RevokeToken(ctx, issued.RefreshToken, "refresh_token"))

	close(proceed)
	res := waitFor(t, done, "attempt B to return")
	if res.err == nil {
		assert.False(t, usable(t, env.direct, res.resp.AccessToken), "attempt B published after the revocation")
	}
	assert.Empty(t, liveTokenKeys(env.mr), "the revocation left a live credential behind")
}

// A copy of an abandoned attempt's claim that the network delivers late, after
// the attempt gave up, must not take the token again.
func TestFault_ALateCopyOfAnAbandonedClaimDoesNotBlockTheToken(t *testing.T) {
	env := newFaultEnv(t, 0)
	ctx := context.Background()
	issued := issueFor(t, env.direct, clientA)

	var mu sync.Mutex
	var claimCmd *faultproxy.Request
	env.proxy.OnRequest(func(r faultproxy.Request) bool {
		if isClaim(r) {
			mu.Lock()
			if claimCmd == nil {
				c := r
				claimCmd = &c
			}
			mu.Unlock()
		}
		return false
	})
	env.fb.refreshIDTokenFunc = func(context.Context, string) (string, int64, error) {
		return "", 0, errors.New("firebase unavailable")
	}
	_, err := env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.Error(t, err)
	mu.Lock()
	captured := claimCmd
	mu.Unlock()
	require.NotNil(t, captured)

	_, err = env.proxy.Send(captured.Raw) // the delayed copy lands now
	require.NoError(t, err)

	env.fb.refreshIDTokenFunc = func(context.Context, string) (string, int64, error) { return validFirebaseResult() }
	got, err := env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, err, "the abandoned attempt's late claim must not hold the token")
	assert.True(t, usable(t, env.direct, got.AccessToken))
}

// ===== A claim that ran out =====

// The claim lasts two minutes. A refresh that is still running after that, and
// meets a revocation, must not publish: the revocation has to see the token
// whether or not a claim is still in place.
func TestFault_AClaimThatRanOutCannotPublishAfterARevocation(t *testing.T) {
	stateManager, mr := setupTestStateManager(t)
	fb := newMockFirebaseClient()
	m := NewManager(stateManager, fb, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
	ctx := context.Background()
	issued := issueFor(t, m, clientA)

	var revokeErr error
	fb.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		mr.FastForward(state.RefreshClaimTTL + time.Second) // Firebase was slow
		revokeErr = m.RevokeToken(ctx, issued.RefreshToken, "refresh_token")
		return validFirebaseResult()
	}

	got, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, revokeErr)
	assert.Error(t, err, "a revoked token must not be refreshed, whatever happened to the claim")
	assert.Nil(t, got)
	assert.Empty(t, liveTokenKeys(mr))
}

// A refresh whose claim ran out and was taken over by another refresh must not
// publish a second family of tokens when it wakes up. It is not told the grant is
// dead either: it is handed what the retry published (see refresh_grace_test.go).
func TestFault_AClaimThatRanOutAndWasTakenOverCannotPublish(t *testing.T) {
	stateManager, mr := setupTestStateManager(t)
	fb := newMockFirebaseClient()
	m := NewManager(stateManager, fb, testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
	ctx := context.Background()
	issued := issueFor(t, m, clientA)

	var calls atomic.Int32
	var second refreshResult
	fb.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		if calls.Add(1) == 1 { // the first refresh is slow; its claim runs out and the client retries
			mr.FastForward(state.RefreshClaimTTL + time.Second)
			second.resp, second.err = m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
		}
		return validFirebaseResult()
	}

	first, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, second.err, "the retry owns the token now")
	require.NoError(t, err, "the slow refresh lost the token, published nothing, and is handed what the retry published")
	assert.Equal(t, second.resp, first, "the same pair, not a second one")
	assert.True(t, usable(t, m, second.resp.AccessToken))
	var refreshKeys []string
	for _, k := range liveTokenKeys(mr) {
		if strings.HasPrefix(k, state.RefreshPrefix) {
			refreshKeys = append(refreshKeys, k)
		}
	}
	assert.Equal(t, []string{state.RefreshPrefix + second.resp.RefreshToken}, refreshKeys, "one refresh token, not two families")
}

// ===== Revocation is all or nothing =====

// A command lost on its way to Redis, or answered into the void, in the middle
// of a revocation. Whatever happens: when RevokeToken says success the grant is
// dead; when it fails nothing is half done; and repeating it finishes the job.
func TestFault_RevocationIsAllOrNothing(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"request lost", "reply lost"} {
		for n := 1; n <= 6; n++ {
			t.Run(fmt.Sprintf("%s/command %d", mode, n), func(t *testing.T) {
				env := newFaultEnv(t, -1) // no retries: the failure reaches RevokeToken
				issued := issueFor(t, env.direct, clientA)
				rt, err := env.sm.GetRefreshTokenData(ctx, issued.RefreshToken)
				require.NoError(t, err)
				require.NotNil(t, rt)
				family := rt.FamilyID

				var count, current atomic.Int32
				env.proxy.OnRequest(func(faultproxy.Request) bool {
					i := count.Add(1)
					current.Store(i)
					return mode == "request lost" && i == int32(n)
				})
				env.proxy.OnReply(func(faultproxy.Request, faultproxy.Reply) faultproxy.Verdict {
					if mode == "reply lost" && current.Load() == int32(n) {
						return faultproxy.DropReply()
					}
					return faultproxy.Pass()
				})

				err = env.via.RevokeToken(ctx, issued.RefreshToken, "refresh_token")
				dead := !usable(t, env.direct, issued.AccessToken)
				if err == nil {
					assert.True(t, dead, "RevokeToken reported success but the access token still works")
					gone, _ := env.sm.GetRefreshTokenData(ctx, issued.RefreshToken)
					assert.Nil(t, gone, "RevokeToken reported success but the refresh token still exists")
				}

				// The caller was told to retry (or was told success): either way a
				// repeat must leave the whole grant dead.
				env.proxy.Reset()
				require.NoError(t, env.via.RevokeToken(ctx, issued.RefreshToken, "refresh_token"))
				assert.False(t, usable(t, env.direct, issued.AccessToken), "the access token survived a repeated revocation")
				gone, _ := env.sm.GetRefreshTokenData(ctx, issued.RefreshToken)
				assert.Nil(t, gone)
				revoked, err := env.sm.IsFamilyRevoked(ctx, family)
				require.NoError(t, err)
				assert.True(t, revoked, "the family was never marked revoked")
			})
		}
	}
}

// The Redis client sends a command again when its reply is lost, so a
// revocation can run twice. The grant must be dead afterwards and the caller
// told success, whichever command's reply was lost.
func TestFault_RevocationWhoseReplyIsLostIsRetriedToCompletion(t *testing.T) {
	ctx := context.Background()
	for n := 1; n <= 6; n++ {
		t.Run(fmt.Sprintf("reply of command %d lost", n), func(t *testing.T) {
			env := newFaultEnv(t, 0)
			issued := issueFor(t, env.direct, clientA)
			rt, err := env.sm.GetRefreshTokenData(ctx, issued.RefreshToken)
			require.NoError(t, err)

			var count, current atomic.Int32
			var dropped atomic.Bool
			env.proxy.OnRequest(func(faultproxy.Request) bool {
				current.Store(count.Add(1))
				return false
			})
			env.proxy.OnReply(func(r faultproxy.Request, rep faultproxy.Reply) faultproxy.Verdict {
				if current.Load() == int32(n) && !rep.IsError() && dropped.CompareAndSwap(false, true) {
					return faultproxy.DropReply()
				}
				return faultproxy.Pass()
			})

			require.NoError(t, env.via.RevokeToken(ctx, issued.RefreshToken, "refresh_token"))
			assert.False(t, usable(t, env.direct, issued.AccessToken), "the access token survived (a command ran, its reply was lost, and the retry found nothing to do)")
			gone, _ := env.sm.GetRefreshTokenData(ctx, issued.RefreshToken)
			assert.Nil(t, gone)
			revoked, err := env.sm.IsFamilyRevoked(ctx, rt.FamilyID)
			require.NoError(t, err)
			assert.True(t, revoked, "the family was never marked revoked")
		})
	}
}

// A backend failure must not be reported as an unknown token.
func TestFault_RevokeReportsBackendFailure(t *testing.T) {
	ctx := context.Background()
	stateManager, mr := setupTestStateManager(t)
	m := NewManager(stateManager, newMockFirebaseClient(), testLogger()).WithJWTExchange(mockJWTExchange("jwt", nil))
	issued := issueFor(t, m, clientA)

	mr.SetError("ERR redis is down")
	for _, tok := range []string{issued.RefreshToken, issued.AccessToken, "unknown"} {
		for _, hint := range []string{"", "refresh_token", "access_token"} {
			assert.Error(t, m.RevokeToken(ctx, tok, hint), "a failed revocation must be an error (hint %q)", hint)
		}
	}
	mr.SetError("")

	assert.True(t, usable(t, m, issued.AccessToken), "nothing was revoked")
	require.NoError(t, m.RevokeToken(ctx, issued.RefreshToken, "refresh_token"))
	assert.False(t, usable(t, m, issued.AccessToken))
}

// An unknown token is a success (RFC 7009), a real one is revoked whatever the
// hint says.
func TestRevoke_HintIsOnlyAHint(t *testing.T) {
	m, sm, _ := setupTestManager(t)
	ctx := context.Background()

	for _, tc := range []struct{ name, hint string }{
		{"refresh token under an access token hint", "access_token"},
		{"refresh token under a refresh token hint", "refresh_token"},
		{"refresh token under a made-up hint", "bogus"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issued := issueFor(t, m, clientA)
			require.NoError(t, m.RevokeToken(ctx, issued.RefreshToken, tc.hint))
			rt, _ := sm.GetRefreshTokenData(ctx, issued.RefreshToken)
			assert.Nil(t, rt)
			assert.False(t, usable(t, m, issued.AccessToken))
		})
	}
	t.Run("access token under a refresh token hint", func(t *testing.T) {
		issued := issueFor(t, m, clientA)
		require.NoError(t, m.RevokeToken(ctx, issued.AccessToken, "refresh_token"))
		assert.False(t, usable(t, m, issued.AccessToken))
	})
	t.Run("unknown token", func(t *testing.T) {
		assert.NoError(t, m.RevokeToken(ctx, "never-issued", "access_token"))
		assert.NoError(t, m.RevokeToken(ctx, "never-issued", ""))
	})
}

// ===== A lost reply must not lose the token =====

// The reply of the claim is lost; the Redis client sends the claim again. It
// must find the claim is the same attempt's and go on, not conclude the token
// is gone.
func TestFault_ALostClaimReplyDoesNotLoseTheToken(t *testing.T) {
	env := newFaultEnv(t, 0)
	ctx := context.Background()
	issued := issueFor(t, env.direct, clientA)

	var dropped atomic.Bool
	env.proxy.OnReply(func(r faultproxy.Request, rep faultproxy.Reply) faultproxy.Verdict {
		if isClaim(r) && !rep.IsError() && dropped.CompareAndSwap(false, true) {
			return faultproxy.DropReply()
		}
		return faultproxy.Pass()
	})

	got, err := env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.True(t, dropped.Load(), "the claim's reply was lost")
	require.NoError(t, err, "the refresh token must not be lost with the reply")
	assert.True(t, usable(t, env.direct, got.AccessToken))
	old, _ := env.sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	assert.Nil(t, old, "the old refresh token was rotated")
}

// The reply of the publish is lost; the Redis client sends the publish again.
// It must be recognised as a repeat and answer success: reporting failure would
// have the cleanup put the old refresh token back while the successors stay
// stored (two live generations of one grant).
func TestFault_ALostPublishReplyIsNotAFailure(t *testing.T) {
	env := newFaultEnv(t, 0)
	ctx := context.Background()
	issued := issueFor(t, env.direct, clientA)

	var dropped atomic.Bool
	env.proxy.OnReply(func(r faultproxy.Request, rep faultproxy.Reply) faultproxy.Verdict {
		if isPublish(r) && !rep.IsError() && dropped.CompareAndSwap(false, true) {
			return faultproxy.DropReply()
		}
		return faultproxy.Pass()
	})

	got, err := env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.True(t, dropped.Load(), "the publish's reply was lost")
	require.NoError(t, err, "the publish ran; the repeat must be recognised")
	assert.True(t, usable(t, env.direct, got.AccessToken))
	old, _ := env.sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	assert.Nil(t, old, "the old refresh token must not come back")
	assert.Len(t, liveTokenKeys(env.mr), 2, "one access token and one refresh token: a single generation")
}

// Issuing the first tokens of a grant survives a lost reply as well.
func TestFault_ALostIssueReplyIsNotAFailure(t *testing.T) {
	env := newFaultEnv(t, 0)
	ctx := context.Background()

	var dropped atomic.Bool
	env.proxy.OnReply(func(r faultproxy.Request, rep faultproxy.Reply) faultproxy.Verdict {
		for _, a := range r.Args {
			if strings.HasPrefix(a, state.TokenPrefix) && !rep.IsError() && dropped.CompareAndSwap(false, true) {
				return faultproxy.DropReply()
			}
		}
		return faultproxy.Pass()
	})

	issued, err := env.via.CreateTokenResponse(ctx, "user", "fb-id", "fb-refresh", time.Now().Add(time.Hour).Unix(), "openid", "", clientA)
	require.True(t, dropped.Load())
	require.NoError(t, err)
	assert.True(t, usable(t, env.direct, issued.AccessToken))
	rt, _ := env.sm.GetRefreshTokenData(ctx, issued.RefreshToken)
	assert.NotNil(t, rt)
}

// One lost reply, wherever it happens in a refresh, is invisible to the client.
func TestFault_ALostReplyAnywhereInARefreshIsInvisible(t *testing.T) {
	ctx := context.Background()
	for n := 1; n <= 6; n++ {
		t.Run(fmt.Sprintf("reply of command %d lost", n), func(t *testing.T) {
			env := newFaultEnv(t, 0)
			issued := issueFor(t, env.direct, clientA)

			var count, current atomic.Int32
			var dropped atomic.Bool
			env.proxy.OnRequest(func(faultproxy.Request) bool {
				current.Store(count.Add(1))
				return false
			})
			env.proxy.OnReply(func(r faultproxy.Request, rep faultproxy.Reply) faultproxy.Verdict {
				if current.Load() == int32(n) && !rep.IsError() && dropped.CompareAndSwap(false, true) {
					return faultproxy.DropReply()
				}
				return faultproxy.Pass()
			})

			got, err := env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
			require.NoError(t, err)
			assert.True(t, usable(t, env.direct, got.AccessToken))
			old, _ := env.sm.GetRefreshTokenData(ctx, issued.RefreshToken)
			assert.Nil(t, old)
			next, err := env.direct.RefreshAccessToken(ctx, got.RefreshToken, clientA, nil)
			require.NoError(t, err, "the client carries on with what it was given")
			assert.True(t, usable(t, env.direct, next.AccessToken))
		})
	}
}

// With the client's retries off every fault reaches the refresh. Whatever it
// does then, a refresh never leaves two generations of a grant alive, never
// reports success without tokens that work, and a failure that happened before
// anything was published leaves the old token usable.
func TestFault_ARefreshHitByAFaultNeverLeavesTwoGenerations(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"request lost", "reply lost"} {
		for n := 1; n <= 6; n++ {
			t.Run(fmt.Sprintf("%s/command %d", mode, n), func(t *testing.T) {
				env := newFaultEnv(t, -1)
				issued := issueFor(t, env.direct, clientA)

				var count, current atomic.Int32
				env.proxy.OnRequest(func(faultproxy.Request) bool {
					i := count.Add(1)
					current.Store(i)
					return mode == "request lost" && i == int32(n)
				})
				env.proxy.OnReply(func(faultproxy.Request, faultproxy.Reply) faultproxy.Verdict {
					if mode == "reply lost" && current.Load() == int32(n) {
						return faultproxy.DropReply()
					}
					return faultproxy.Pass()
				})

				got, err := env.via.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
				if err == nil {
					assert.True(t, usable(t, env.direct, got.AccessToken), "success must come with tokens that work")
				}

				oldAlive := false
				if rt, _ := env.sm.GetRefreshTokenData(ctx, issued.RefreshToken); rt != nil {
					oldAlive = true
				}
				var refreshTokens int
				for _, k := range liveTokenKeys(env.mr) {
					if strings.HasPrefix(k, state.RefreshPrefix) {
						refreshTokens++
					}
				}
				assert.Equal(t, 1, refreshTokens, "exactly one refresh token of the grant is stored (old alive: %v)", oldAlive)

				if err != nil && oldAlive {
					// The refresh failed and the client still has its token: it can go on.
					env.proxy.Reset()
					again, err := env.direct.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
					require.NoError(t, err, "the old refresh token must still work after a failed refresh")
					assert.True(t, usable(t, env.direct, again.AccessToken))
				}
			})
		}
	}
}

// ===== Races =====

// Refreshes and revocations of one grant, started together. Whatever order they
// land in: the grant has at most one generation of successors, and once the
// revocation has returned the grant has no live credential.
//
// More than one refresh may succeed: a request that arrives after another one
// rotated the token is handed the same successors (the refresh grace window), so
// the number of successes says nothing. What matters is how many distinct
// successor refresh tokens were issued.
func TestFault_RefreshesRacingARevocationLeaveNothingAlive(t *testing.T) {
	ctx := context.Background()
	for i := 0; i < 25; i++ {
		m, sm, fb := setupTestManager(t)
		_ = sm
		issued := issueFor(t, m, clientA)
		fb.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
			// Varies the interleaving with the revocation; the assertions below
			// hold in every order.
			time.Sleep(time.Duration(i%3) * time.Millisecond)
			return validFirebaseResult()
		}

		const refreshers = 4
		start := make(chan struct{})
		results := make([]refreshResult, refreshers)
		var wg sync.WaitGroup
		for j := 0; j < refreshers; j++ {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				<-start
				results[j].resp, results[j].err = m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
			}(j)
		}
		var revokeErr error
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			revokeErr = m.RevokeToken(ctx, issued.RefreshToken, "refresh_token")
		}()
		close(start)
		wg.Wait()

		require.NoError(t, revokeErr)
		successors := map[string]bool{}
		for _, r := range results {
			if r.err == nil {
				successors[r.resp.RefreshToken] = true
				assert.False(t, usable(t, m, r.resp.AccessToken), "iteration %d: a token issued by a refresh survives the revocation", i)
				_, err := m.RefreshAccessToken(ctx, r.resp.RefreshToken, clientA, nil)
				assert.Error(t, err, "iteration %d", i)
			}
		}
		assert.LessOrEqual(t, len(successors), 1, "iteration %d: one refresh token never fathers two generations", i)
		assert.False(t, usable(t, m, issued.AccessToken), "iteration %d", i)
	}
}

// The order the race above can produce, pinned: one refresh rotates the token, a
// second one arrives after it and is handed the same successors, and the
// revocation runs last. Two refreshes succeeded and there is still one
// generation, which the revocation kills.
func TestFault_ALateRefreshIsHandedTheSamePairAndTheRevocationStillKillsIt(t *testing.T) {
	ctx := context.Background()
	m, _, fb := setupTestManager(t)
	var firebaseCalls atomic.Int32
	fb.refreshIDTokenFunc = func(ctx context.Context, _ string) (string, int64, error) {
		firebaseCalls.Add(1)
		return validFirebaseResult()
	}
	issued := issueFor(t, m, clientA)

	first, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, err)
	late, err := m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	require.NoError(t, err, "within the grace window a replay is handed the successors")
	assert.Equal(t, first.RefreshToken, late.RefreshToken, "one generation, however many requests got it")
	assert.Equal(t, first.AccessToken, late.AccessToken)
	assert.EqualValues(t, 1, firebaseCalls.Load())

	require.NoError(t, m.RevokeToken(ctx, issued.RefreshToken, "refresh_token"))
	assert.False(t, usable(t, m, first.AccessToken))
	_, err = m.RefreshAccessToken(ctx, first.RefreshToken, clientA, nil)
	assert.Error(t, err)
	_, err = m.RefreshAccessToken(ctx, issued.RefreshToken, clientA, nil)
	assert.Error(t, err, "the revoked grant cannot be replayed either")
}
