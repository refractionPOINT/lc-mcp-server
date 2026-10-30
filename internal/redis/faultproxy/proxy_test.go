package faultproxy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newClient(t *testing.T, p *Proxy, maxRetries int) *goredis.Client {
	t.Helper()
	c := goredis.NewClient(&goredis.Options{
		Addr:            p.Addr(),
		MaxRetries:      maxRetries,
		MinRetryBackoff: time.Millisecond,
		MaxRetryBackoff: 5 * time.Millisecond,
		ReadTimeout:     5 * time.Second,
	})
	t.Cleanup(func() { c.Close() })
	return c
}

func isIncr(r Request) bool { return r.Name() == "INCR" }

func TestProxyPassesTraffic(t *testing.T) {
	mr := miniredis.RunT(t)
	p := New(t, mr.Addr())
	c := newClient(t, p, 0)
	ctx := context.Background()

	require.NoError(t, c.Set(ctx, "k", "v", 0).Err())
	got, err := c.Get(ctx, "k").Result()
	require.NoError(t, err)
	assert.Equal(t, "v", got)
	_, err = c.Get(ctx, "missing").Result()
	assert.ErrorIs(t, err, goredis.Nil)
}

func TestProxyRequestThatIsLostNeverRuns(t *testing.T) {
	mr := miniredis.RunT(t)
	p := New(t, mr.Addr())
	c := newClient(t, p, -1)
	ctx := context.Background()

	p.OnRequest(func(r Request) bool { return isIncr(r) })
	require.Error(t, c.Incr(ctx, "n").Err(), "the client sees its connection die")
	assert.False(t, mr.Exists("n"), "the command never reached the server")
}

// The reply is lost after the server acted: with retries off the client has an
// error although the command ran; with retries on it sends the command again,
// so it runs twice. That second run is what scripts must be safe against.
func TestProxyLostReply(t *testing.T) {
	ctx := context.Background()
	drop := func(p *Proxy) *int {
		runs := 0
		p.OnReply(func(r Request, rep Reply) Verdict {
			if isIncr(r) {
				runs++
				if runs == 1 {
					return DropReply()
				}
			}
			return Pass()
		})
		return &runs
	}

	t.Run("without retries the client only has an error", func(t *testing.T) {
		mr := miniredis.RunT(t)
		p := New(t, mr.Addr())
		c := newClient(t, p, -1)
		drop(p)
		require.Error(t, c.Incr(ctx, "n").Err())
		v, _ := mr.Get("n")
		assert.Equal(t, "1", v, "the command ran")
	})

	t.Run("with retries the command runs twice", func(t *testing.T) {
		mr := miniredis.RunT(t)
		p := New(t, mr.Addr())
		c := newClient(t, p, 3)
		runs := drop(p)
		n, err := c.Incr(ctx, "n").Result()
		require.NoError(t, err)
		assert.EqualValues(t, 2, n, "the retried command saw the first run's effect")
		assert.Equal(t, 2, *runs)
	})
}

func TestProxyWithholdsAReplyUntilReleased(t *testing.T) {
	mr := miniredis.RunT(t)
	p := New(t, mr.Addr())
	c := newClient(t, p, -1)
	ctx := context.Background()

	hold := NewHold()
	p.OnReply(func(r Request, rep Reply) Verdict {
		if isIncr(r) {
			return WithholdReply(hold)
		}
		return Pass()
	})
	done := make(chan error, 1)
	go func() { done <- c.Incr(ctx, "n").Err() }()

	select {
	case <-hold.Executed():
	case <-time.After(5 * time.Second):
		t.Fatal("the command did not run")
	}
	v, _ := mr.Get("n")
	assert.Equal(t, "1", v, "the command ran while its reply is withheld")
	select {
	case err := <-done:
		t.Fatalf("the client got an answer too early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	hold.Release()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the reply was not delivered")
	}
}

func TestProxyScriptRequestsExposeTheirKeys(t *testing.T) {
	mr := miniredis.RunT(t)
	p := New(t, mr.Addr())
	c := newClient(t, p, 0)
	ctx := context.Background()

	var seen []Request
	p.OnRequest(func(r Request) bool {
		if r.IsScript() {
			seen = append(seen, r)
		}
		return false
	})
	_, err := goredis.NewScript(`return redis.call('SET', KEYS[1], ARGV[1])`).Run(ctx, c, []string{"oauth:a:1", "x:2"}, "v").Result()
	require.NoError(t, err)

	require.NotEmpty(t, seen)
	last := seen[len(seen)-1]
	assert.Equal(t, []string{"oauth:a:1", "x:2"}, last.Keys())
	assert.True(t, last.HasKeyPrefix("oauth:"))
	assert.False(t, last.HasKeyPrefix("nope:"))
}

func TestProxySendReplaysARequest(t *testing.T) {
	mr := miniredis.RunT(t)
	p := New(t, mr.Addr())
	c := newClient(t, p, 0)
	ctx := context.Background()

	var captured Request
	p.OnRequest(func(r Request) bool {
		if isIncr(r) {
			captured = r
		}
		return false
	})
	require.NoError(t, c.Incr(ctx, "n").Err())
	require.True(t, strings.EqualFold(captured.Args[0], "INCR"))

	rep, err := p.Send(captured.Raw)
	require.NoError(t, err)
	assert.False(t, rep.IsError())
	v, _ := mr.Get("n")
	assert.Equal(t, "2", v, "the late copy of the command ran again")
}
