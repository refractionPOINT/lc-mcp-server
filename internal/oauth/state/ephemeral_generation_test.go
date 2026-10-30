package state

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublishDocIfGeneration(t *testing.T) {
	m, mr := setupTestManager(t)
	ctx := context.Background()
	const gen, doc, known = "g", "d", "k"

	// Absent generation matches "".
	ok, err := m.PublishDocIfGeneration(ctx, gen, "", time.Minute, doc, "v1", time.Hour, known, 24*time.Hour)
	require.NoError(t, err)
	require.True(t, ok)
	v, _ := m.GetEphemeral(ctx, gen)
	assert.Equal(t, "1", v, "publishing bumps the generation")
	assert.Equal(t, time.Minute, mr.TTL(gen))
	assert.Equal(t, time.Hour, mr.TTL(doc))
	assert.Equal(t, 24*time.Hour, mr.TTL(known))

	// A writer that read the old generation is refused and writes nothing.
	ok, err = m.PublishDocIfGeneration(ctx, gen, "", time.Minute, doc, "stale", time.Hour, known, time.Hour)
	require.NoError(t, err)
	assert.False(t, ok)
	v, _ = m.GetEphemeral(ctx, doc)
	assert.Equal(t, "v1", v)
	assert.Equal(t, 24*time.Hour, mr.TTL(known))

	// Without a known key only the document is written.
	ok, err = m.PublishDocIfGeneration(ctx, gen, "1", time.Minute, doc, "v2", time.Hour, "", 0)
	require.NoError(t, err)
	assert.True(t, ok)
	v, _ = m.GetEphemeral(ctx, doc)
	assert.Equal(t, "v2", v)
}

func TestInvalidateDoc(t *testing.T) {
	ctx := context.Background()
	const gen, doc, known = "g", "d", "k"
	seed := func(t *testing.T) *Manager {
		m, _ := setupTestManager(t)
		require.NoError(t, m.SetEphemeral(ctx, doc, "v", time.Hour))
		require.NoError(t, m.SetEphemeral(ctx, known, "1", time.Hour))
		return m
	}

	t.Run("drop known", func(t *testing.T) {
		m := seed(t)
		require.NoError(t, m.InvalidateDoc(ctx, gen, time.Minute, doc, known, true, 24*time.Hour))
		for _, k := range []string{doc, known} {
			v, _ := m.GetEphemeral(ctx, k)
			assert.Empty(t, v, k)
		}
		v, _ := m.GetEphemeral(ctx, gen)
		assert.Equal(t, "1", v)
	})

	t.Run("keep known", func(t *testing.T) {
		m, mr := setupTestManager(t)
		require.NoError(t, m.SetEphemeral(ctx, doc, "v", time.Hour))
		require.NoError(t, m.SetEphemeral(ctx, known, "1", time.Hour))
		require.NoError(t, m.InvalidateDoc(ctx, gen, time.Minute, doc, known, false, 24*time.Hour))
		v, _ := m.GetEphemeral(ctx, doc)
		assert.Empty(t, v)
		assert.Equal(t, 24*time.Hour, mr.TTL(known), "the marker is kept and renewed")
	})

	t.Run("keep known does not create it", func(t *testing.T) {
		m, mr := setupTestManager(t)
		require.NoError(t, m.InvalidateDoc(ctx, gen, time.Minute, doc, known, false, 24*time.Hour))
		assert.False(t, mr.Exists(known))
		assert.True(t, mr.Exists(gen))
	})
}
