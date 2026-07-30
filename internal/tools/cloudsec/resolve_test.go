package cloudsec

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChunkStrings(t *testing.T) {
	t.Run("a batch at or under the chunk size stays one request", func(t *testing.T) {
		values := make([]string, resolveChunkSize)
		for i := range values {
			values[i] = fmt.Sprintf("sid-%d", i)
		}
		chunks := chunkStrings(values, resolveChunkSize)
		require.Len(t, chunks, 1)
		assert.Len(t, chunks[0], resolveChunkSize)
	})

	t.Run("a larger batch splits with the remainder last", func(t *testing.T) {
		values := make([]string, 250)
		for i := range values {
			values[i] = fmt.Sprintf("sid-%d", i)
		}
		chunks := chunkStrings(values, resolveChunkSize)
		require.Len(t, chunks, 3)
		assert.Len(t, chunks[0], 100)
		assert.Len(t, chunks[1], 100)
		assert.Len(t, chunks[2], 50)

		// Nothing may be dropped or reordered: the caller pairs the merged answer
		// back up with the ids it sent.
		var flat []string
		for _, c := range chunks {
			flat = append(flat, c...)
		}
		assert.Equal(t, values, flat)
	})
}

// resolver_ready answers "is the resolver provisioned here at all", which is not the
// same question as "did anything match". It is merged pessimistically and must stay
// absent when no chunk reported it rather than being invented as false.
func TestResolveMergeResolverReady(t *testing.T) {
	t.Run("absent from every chunk stays absent", func(t *testing.T) {
		m := resolveMerge{}
		m.add(map[string]interface{}{"resolved": []interface{}{"a"}})
		m.add(map[string]interface{}{"resolved": []interface{}{"b"}})

		out := m.result()
		assert.NotContains(t, out, "resolver_ready")
		assert.Equal(t, []interface{}{"a", "b"}, out["resolved"])
	})

	t.Run("one not-ready chunk makes the whole answer not ready", func(t *testing.T) {
		m := resolveMerge{}
		m.add(map[string]interface{}{"resolver_ready": true})
		m.add(map[string]interface{}{"resolver_ready": false})
		m.add(map[string]interface{}{"resolver_ready": true})

		assert.Equal(t, false, m.result()["resolver_ready"])
	})

	t.Run("all-ready chunks report ready", func(t *testing.T) {
		m := resolveMerge{}
		m.add(map[string]interface{}{"resolver_ready": true})
		m.add(map[string]interface{}{"resolver_ready": true})

		assert.Equal(t, true, m.result()["resolver_ready"])
	})

	t.Run("a partially-reporting walk is judged on the chunks that answered", func(t *testing.T) {
		m := resolveMerge{}
		m.add(map[string]interface{}{"resolved": []interface{}{"a"}})
		m.add(map[string]interface{}{"resolver_ready": false})

		assert.Equal(t, false, m.result()["resolver_ready"])
	})
}

func TestResolveMergeConcatenatesBothLists(t *testing.T) {
	m := resolveMerge{}
	m.add(map[string]interface{}{
		"resolved":   []interface{}{map[string]interface{}{"sid": "s1"}},
		"unresolved": []interface{}{"s2"},
	})
	m.add(map[string]interface{}{
		"resolved":   []interface{}{map[string]interface{}{"sid": "s3"}},
		"unresolved": []interface{}{"s4", "s5"},
	})

	out := m.result()
	assert.Len(t, out["resolved"], 2)
	assert.Equal(t, []interface{}{"s2", "s4", "s5"}, out["unresolved"])
}

// An empty walk must still answer with both keys present, so a caller can read
// len(resolved)==0 instead of having to handle a missing key.
func TestResolveMergeEmptyResultHasBothKeys(t *testing.T) {
	out := (&resolveMerge{}).result()
	assert.Equal(t, []interface{}{}, out["resolved"])
	assert.Equal(t, []interface{}{}, out["unresolved"])
}
