package redis

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newGenTestClient(t *testing.T) (*Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	c, err := New(&Config{URL: "redis://" + mr.Addr(), MaxRetries: -1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c, mr
}

// A step whose reply was lost is retried with the same arguments (same nonce).
// The replay must not put back a generation value that a later step already
// replaced, or a writer holding that old value could publish again.
func TestGeneration_ReplayedInvalidationNeverRestoresAnOldGeneration(t *testing.T) {
	c, mr := newGenTestClient(t)
	ctx := context.Background()
	const gen, doc = "g", "d"
	bump := func(nonce string) {
		require.NoError(t, bumpGeneration.Run(ctx, c.client, []string{gen, doc}, time.Minute.Milliseconds(), 1, 0, nonce).Err())
	}

	bump("nonce-A") // invalidation A
	g1, _ := mr.Get(gen)
	readByWriter := g1 // a slow writer reads G1

	bump("nonce-B") // a later invalidation B
	g2, _ := mr.Get(gen)
	require.NotEqual(t, g1, g2)

	bump("nonce-A") // A's lost reply makes go-redis replay A
	g3, _ := mr.Get(gen)
	assert.NotEqual(t, g1, g3, "a replay must advance the generation, not restore it")

	ok, err := c.PublishIfGeneration(ctx, gen, readByWriter, time.Minute, []string{doc}, []string{"withdrawn"}, []time.Duration{time.Hour})
	require.NoError(t, err)
	assert.False(t, ok, "the writer that read G1 must stay fenced out")
	assert.False(t, mr.Exists(doc))
}

func TestGeneration_ReplayedPublishDoesNotRepublish(t *testing.T) {
	c, mr := newGenTestClient(t)
	ctx := context.Background()
	const gen, doc = "g", "d"
	publish := func(expected, nonce, value string) int64 {
		n, err := publishIfGeneration.Run(ctx, c.client, []string{gen, doc}, expected, time.Minute.Milliseconds(), nonce, value, time.Hour.Milliseconds()).Int64()
		require.NoError(t, err)
		return n
	}
	require.EqualValues(t, 1, publish("", "n1", "v1"))
	require.NoError(t, bumpGeneration.Run(ctx, c.client, []string{gen, doc}, time.Minute.Milliseconds(), 1, 0, "n2").Err()) // invalidated
	assert.EqualValues(t, 0, publish("", "n1", "v1"), "a replay of the first publish is fenced out by the invalidation")
	assert.False(t, mr.Exists(doc))
}
