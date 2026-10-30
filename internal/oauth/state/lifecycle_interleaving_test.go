package state

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"
)

// Random interleavings of everything that can happen to one grant: several
// refresh attempts claiming, publishing and giving up, revocations by any token
// the grant ever had, claims running out, and late copies of any earlier command
// (what the Redis client does with a command whose reply was lost). After every
// step the grant must satisfy the lifecycle's invariants. The walks are seeded,
// so a failure names the seed that reproduces it.

type simAttempt struct {
	owner string
	token string
	claim *RefreshClaim
	call  *scriptCall
	pubRT string
	ended bool // the attempt gave its claim up
}

type sim struct {
	t        *testing.T
	m        *Manager
	mr       *miniredis.Miniredis
	rng      *rand.Rand
	seed     int64
	n        int
	tokens   []string // every credential the grant has had or been offered
	attempts []*simAttempt
	replays  []func()
	trace    []string
	revoked  bool
}

const simFamily = "fam"

func (s *sim) logf(format string, a ...any) { s.trace = append(s.trace, fmt.Sprintf(format, a...)) }

func (s *sim) fatalf(format string, a ...any) {
	s.t.Helper()
	s.t.Fatalf("seed %d: %s\ntrace:\n  %s", s.seed, fmt.Sprintf(format, a...), strings.Join(s.trace, "\n  "))
}

func (s *sim) get(key string) string {
	v, err := s.mr.Get(key)
	if err != nil {
		return ""
	}
	return v
}

func (s *sim) liveKeys(prefix string) []string {
	var out []string
	for _, k := range s.mr.Keys() {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out
}

// currentRefresh is the grant's live refresh token, or any token the grant had
// when none is live (so claims also run on tokens that are gone).
func (s *sim) currentRefresh() string {
	if live := s.liveKeys(RefreshPrefix); len(live) > 0 {
		return strings.TrimPrefix(live[0], RefreshPrefix)
	}
	return s.tokens[s.rng.Intn(len(s.tokens))]
}

func (s *sim) step(ctx context.Context) {
	switch op := s.rng.Intn(100); {
	case op < 22:
		s.claim(ctx)
	case op < 46:
		s.publish(ctx)
	case op < 58:
		s.release(ctx)
	case op < 72:
		s.revoke(ctx)
	case op < 78:
		s.logf("claims run out")
		s.mr.FastForward(RefreshClaimTTL + time.Second)
	default:
		if len(s.replays) > 0 {
			i := s.rng.Intn(len(s.replays))
			s.logf("late copy of earlier command #%d", i)
			s.replays[i]()
		}
	}
	s.check()
}

func (s *sim) claim(ctx context.Context) {
	rt := s.currentRefresh()
	s.n++
	owner := fmt.Sprintf("attempt-%d", s.n)
	h := tokenHash(rt)
	// What the claim must answer, from the state it will run against.
	free := s.mr.Exists(RefreshPrefix+rt) && !s.mr.Exists(RevokedTokenPrefix+h) && !s.mr.Exists(RevokedFamilyPrefix+simFamily) && !s.mr.Exists(RefreshClaimPrefix+h)

	claim, err := s.m.claimAs(ctx, rt, owner)
	s.logf("claim %s on %s -> %v", owner, rt, err)
	if (err == nil) != free {
		s.fatalf("claim %s on %s answered %v, but the token was free=%v", owner, rt, err, free)
	}
	s.replays = append(s.replays, func() { s.m.claimAs(ctx, rt, owner) })
	if err != nil {
		return
	}
	at, next := fmt.Sprintf("at-%d", s.n), fmt.Sprintf("rt-%d", s.n)
	call, err := s.m.preparePublish(claim, newAccess(at, simFamily), newRefresh(next, at, simFamily))
	require.NoError(s.t, err)
	s.tokens = append(s.tokens, at, next)
	s.attempts = append(s.attempts, &simAttempt{owner: owner, token: rt, claim: claim, call: call, pubRT: next})
}

func (s *sim) publish(ctx context.Context) {
	if len(s.attempts) == 0 {
		return
	}
	a := s.attempts[s.rng.Intn(len(s.attempts))]
	h := tokenHash(a.token)
	next := a.pubRT
	// What the publish must answer, from the state it will run against.
	var want error
	switch rec := s.get(RotationPrefix + h); {
	case rec != "":
		if !strings.HasPrefix(rec, a.owner+":") {
			want = ErrAlreadyRotated
		}
	case s.mr.Exists(RevokedTokenPrefix+h) || s.mr.Exists(RevokedFamilyPrefix+simFamily):
		want = ErrTokenRevoked
	case !s.mr.Exists(RefreshPrefix + a.token):
		want = ErrTokenRevoked // gone and not rotated: the claim does not matter
	case a.ended || s.get(RefreshClaimPrefix+h) != a.owner:
		want = ErrClaimLost // an attempt that gave up is over, whatever its claim key holds
	case s.mr.Exists(RefreshPrefix + next):
		want = ErrAlreadyExists
	}

	err := s.m.publish(ctx, a.call)
	s.logf("publish by %s of %s -> %v", a.owner, a.token, err)
	if !errors.Is(err, want) || (want == nil && err != nil) {
		s.fatalf("publish by %s answered %v, want %v", a.owner, err, want)
	}
	s.replays = append(s.replays, func() { s.m.publish(ctx, a.call) })
}

func (s *sim) release(ctx context.Context) {
	if len(s.attempts) == 0 {
		return
	}
	a := s.attempts[s.rng.Intn(len(s.attempts))]
	s.logf("release by %s", a.owner)
	s.releaseChecked(ctx, a)
	a.ended = true
	s.replays = append(s.replays, func() { s.releaseChecked(ctx, a) })
}

// releaseChecked gives an attempt's claim up and checks that a claim held by
// another attempt is left alone.
func (s *sim) releaseChecked(ctx context.Context, a *simAttempt) {
	key := RefreshClaimPrefix + tokenHash(a.token)
	before := s.get(key)
	s.m.ReleaseRefreshClaim(ctx, a.claim)
	if after := s.get(key); before != "" && before != a.owner && after != before {
		s.fatalf("the release by %s cleared the claim of %s", a.owner, before)
	}
}

func (s *sim) revoke(ctx context.Context) {
	tok := s.tokens[s.rng.Intn(len(s.tokens))]
	out, err := s.m.RevokeToken(ctx, tok)
	s.logf("revoke %s -> %v", tok, out)
	require.NoError(s.t, err)
	if out == RevokedRefreshToken || out == RevokedAccessToken || out == RevokedGrantByToken {
		s.revoked = true
	}
	s.replays = append(s.replays, func() { s.m.RevokeToken(ctx, tok) })
}

// check is the lifecycle's invariants.
func (s *sim) check() {
	rts, ats := s.liveKeys(RefreshPrefix), s.liveKeys(TokenPrefix)
	if len(rts) > 1 || len(ats) > 1 {
		s.fatalf("two generations are alive: refresh %v, access %v", rts, ats)
	}
	marked := s.mr.Exists(RevokedFamilyPrefix + simFamily)
	if marked && (len(rts) > 0 || len(ats) > 0) {
		s.fatalf("the grant is revoked but credentials are live: %v %v", rts, ats)
	}
	if s.revoked && !marked {
		s.fatalf("a revocation found the grant but the grant is not marked revoked")
	}
	if s.revoked && (len(rts) > 0 || len(ats) > 0) {
		s.fatalf("a revocation found the grant but credentials are live: %v %v", rts, ats)
	}
	if len(rts) == 1 {
		rt := strings.TrimPrefix(rts[0], RefreshPrefix)
		if got := s.get(TokenFamilyPrefix + tokenHash(rt)); got != simFamily {
			s.fatalf("live refresh token %s is not indexed under its grant (%q)", rt, got)
		}
		if s.mr.Exists(FamilyPrefix+simFamily) && s.mr.HGet(FamilyPrefix+simFamily, "rt") != rt {
			s.fatalf("the family record names %q, the live refresh token is %q", s.mr.HGet(FamilyPrefix+simFamily, "rt"), rt)
		}
	}
	if len(ats) == 1 {
		at := strings.TrimPrefix(ats[0], TokenPrefix)
		if got := s.get(TokenFamilyPrefix + tokenHash(at)); got != simFamily {
			s.fatalf("live access token %s is not indexed under its grant (%q)", at, got)
		}
		if s.mr.Exists(FamilyPrefix+simFamily) && s.mr.HGet(FamilyPrefix+simFamily, "at") != at {
			s.fatalf("the family record names %q, the live access token is %q", s.mr.HGet(FamilyPrefix+simFamily, "at"), at)
		}
	}
}

func TestLifecycle_RandomInterleavingsKeepTheInvariants(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()
	const walks, steps = 400, 16

	for seed := int64(1); seed <= walks; seed++ {
		mr.FlushAll()
		s := &sim{t: t, m: m, mr: mr, rng: rand.New(rand.NewSource(seed)), seed: seed}

		issue, err := m.prepareIssue(newAccess("at-0", simFamily), newRefresh("rt-0", "at-0", simFamily))
		require.NoError(t, err)
		require.NoError(t, m.issue(ctx, issue))
		s.tokens = []string{"at-0", "rt-0"}
		s.replays = append(s.replays, func() { m.issue(ctx, issue) }) // the first tokens' own late copy

		for i := 0; i < steps; i++ {
			s.step(ctx)
		}
	}
}
