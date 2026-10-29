package state

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEphemeralValues(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()

	require.Error(t, m.SetEphemeral(ctx, "k", "v", 0), "a ttl is mandatory")

	require.NoError(t, m.SetEphemeral(ctx, "k", "v", time.Minute))
	got, err := m.GetEphemeral(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, "v", got)
	assert.Equal(t, time.Minute, mr.TTL("k"))

	got, err = m.ConsumeEphemeral(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, "v", got)
	got, _ = m.ConsumeEphemeral(ctx, "k")
	assert.Empty(t, got, "consume is single-use")
}

func TestIncrEphemeralStartsWindowOnce(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()

	n, err := m.IncrEphemeral(ctx, "c", time.Minute)
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	mr.FastForward(30 * time.Second)
	n, _ = m.IncrEphemeral(ctx, "c", time.Minute)
	assert.EqualValues(t, 2, n)
	assert.Equal(t, 30*time.Second, mr.TTL("c"), "later increments must not extend the window")
	mr.FastForward(31 * time.Second)
	n, _ = m.IncrEphemeral(ctx, "c", time.Minute)
	assert.EqualValues(t, 1, n)
}

func TestGetSelectionSessionDoesNotConsume(t *testing.T) {
	m, _ := setupTestManager(t)
	ctx := context.Background()
	require.NoError(t, m.StoreSelectionSession(ctx, "s1", map[string]string{"client_id": "c"}))

	for i := 0; i < 2; i++ {
		p, err := m.GetSelectionSession(ctx, "s1")
		require.NoError(t, err)
		assert.Equal(t, "c", p["client_id"])
	}
	p, err := m.ConsumeSelectionSession(ctx, "s1")
	require.NoError(t, err)
	assert.Equal(t, "c", p["client_id"])
	p, err = m.GetSelectionSession(ctx, "s1")
	require.NoError(t, err)
	assert.Nil(t, p)
}
