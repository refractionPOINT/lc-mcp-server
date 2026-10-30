package cimd

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// heldServer serves /client.json. Requests are numbered from 1; request 1
// announces itself on arrived and blocks until release is closed, then serves
// the "old" document. Later requests are served by next.
type heldServer struct {
	arrived chan struct{}
	release chan struct{}
	n       atomic.Int64
	next    func(w http.ResponseWriter, r *http.Request, self string)
	once    sync.Once
}

// unblock releases the held request; safe to call more than once.
func (h *heldServer) unblock() { h.once.Do(func() { close(h.release) }) }

func newHeldServer(next func(w http.ResponseWriter, r *http.Request, self string)) *heldServer {
	return &heldServer{arrived: make(chan struct{}), release: make(chan struct{}), next: next}
}

const oldRedirectURI = "https://old.example.com/callback"

func (h *heldServer) serve(w http.ResponseWriter, r *http.Request, self string) {
	if h.n.Add(1) != 1 {
		h.next(w, r, self)
		return
	}
	close(h.arrived)
	<-h.release
	w.Header().Set("Cache-Control", "max-age=3600")
	writeDoc(w, self, func(m map[string]any) {
		m["redirect_uris"] = []string{"https://app.example.com/callback", oldRedirectURI}
	})
}

// secondReplica returns a fetcher that shares env's Redis but nothing else
// (notably not the single-flight group), like another replica.
func secondReplica(env *testEnv) *Fetcher {
	return NewFetcherForTesting(env.fetcher.store, testLogger(), env.srv.Client().Transport)
}

// startSlow resolves id on f in the background and waits until the (held)
// request reached the server.
func startSlow(t *testing.T, f *Fetcher, h *heldServer, id string) <-chan error {
	t.Helper()
	// If the test fails before it releases the held request, unblock it at
	// cleanup (registered after newTestEnv's srv.Close, so it runs first),
	// or srv.Close would wait on that handler forever and hide the failure.
	t.Cleanup(h.unblock)
	done := make(chan error, 1)
	go func() {
		_, err := f.Resolve(context.Background(), id)
		done <- err
	}()
	select {
	case <-h.arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("slow fetch never reached the server")
	}
	return done
}

func TestGeneration_SlowReplicaCannotRepublishAWithdrawnDocument(t *testing.T) {
	// Review repro: replica A's fetch is slow and returns the old document;
	// meanwhile replica B gets a 410 and invalidates; A then finishes. A must
	// not write the old document back, or the removed redirect URI becomes
	// acceptable again (even while rate-limited).
	h := newHeldServer(func(w http.ResponseWriter, _ *http.Request, _ string) { w.WriteHeader(http.StatusGone) })
	env := newTestEnv(t, h.serve)
	id := env.url("/client.json")
	replicaB := secondReplica(env)

	slow := startSlow(t, env.fetcher, h, id)

	_, err := replicaB.Resolve(context.Background(), id)
	require.Equal(t, KindFetch, kindOf(t, err), "replica B sees the 410")

	h.unblock()
	require.NoError(t, <-slow, "the caller that fetched still gets what it fetched")

	assert.False(t, env.hasDoc(id), "the withdrawn document must not be republished")
	assert.False(t, env.hasKnown(id))
	requireNoDocumentCopies(t, env)

	// Throttled lookups fail closed instead of serving an older copy.
	env.setLimiters(rate.NewLimiter(0, 0))
	_, err = env.fetcher.Resolve(context.Background(), id)
	assert.Equal(t, KindBusy, kindOf(t, err))
}

func TestGeneration_SlowReplicaCannotOverwriteANewerDocument(t *testing.T) {
	// A's slow fetch returns the old document after B already published the
	// newer one; the old one must not replace it.
	h := newHeldServer(func(w http.ResponseWriter, _ *http.Request, self string) {
		w.Header().Set("Cache-Control", "max-age=3600")
		writeDoc(w, self, nil) // the new document: no oldRedirectURI
	})
	env := newTestEnv(t, h.serve)
	id := env.url("/client.json")
	replicaB := secondReplica(env)

	slow := startSlow(t, env.fetcher, h, id)

	doc, err := replicaB.Resolve(context.Background(), id)
	require.NoError(t, err)
	require.False(t, doc.HasRedirectURI(oldRedirectURI))
	require.True(t, env.hasDoc(id))

	h.unblock()
	require.NoError(t, <-slow)

	cached, ok := env.fetcher.cachedDoc(context.Background(), cacheKey(id))
	require.True(t, ok)
	assert.False(t, cached.HasRedirectURI(oldRedirectURI), "the older in-flight fetch must not overwrite the newer document")
}

func TestGeneration_NoStoreSlowReplicaCannotRepublish(t *testing.T) {
	// Same race, invalidated by a valid no-store answer instead of a 410.
	h := newHeldServer(func(w http.ResponseWriter, _ *http.Request, self string) {
		w.Header().Set("Cache-Control", "no-store")
		writeDoc(w, self, nil)
	})
	env := newTestEnv(t, h.serve)
	id := env.url("/client.json")
	replicaB := secondReplica(env)

	slow := startSlow(t, env.fetcher, h, id)
	_, err := replicaB.Resolve(context.Background(), id)
	require.NoError(t, err)
	h.unblock()
	require.NoError(t, <-slow)

	assert.False(t, env.hasDoc(id), "the older document must not be cached after a no-store answer")
}

func TestGeneration_UncontendedFetchStillCaches(t *testing.T) {
	// The generation must not get in the way of the normal path, including after
	// an earlier invalidation of the same URL.
	var gone atomic.Bool
	env := newTestEnv(t, func(w http.ResponseWriter, _ *http.Request, self string) {
		if gone.Load() {
			w.WriteHeader(http.StatusGone)
			return
		}
		w.Header().Set("Cache-Control", "max-age=300")
		writeDoc(w, self, nil)
	})
	env.setLimiters(rate.NewLimiter(rate.Inf, 1))
	id := env.url("/client.json")

	gone.Store(true)
	_, err := env.fetcher.Resolve(context.Background(), id)
	require.Equal(t, KindFetch, kindOf(t, err))
	gone.Store(false)
	for i := 0; i < 2; i++ {
		_, err = env.fetcher.Resolve(context.Background(), id)
		require.NoError(t, err)
	}
	assert.True(t, env.hasDoc(id))
	assert.True(t, env.hasKnown(id))
	assert.EqualValues(t, 2, env.hits.Load(), "second lookup is a cache hit")
}

func TestKnown_NoStoreAnswerKeepsTheKnownMarker(t *testing.T) {
	// Review repro: a previously known client publishing valid no-store
	// metadata lost its separate fetch budget, so junk lookups on its host
	// could shed it.
	var noStore atomic.Bool
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request, self string) {
		if len(r.URL.Path) >= 5 && r.URL.Path[:5] == "/junk" {
			http.NotFound(w, r)
			return
		}
		if noStore.Load() {
			w.Header().Set("Cache-Control", "no-store")
		} else {
			w.Header().Set("Cache-Control", "max-age=300")
		}
		writeDoc(w, self, nil)
	})
	env.setLimiters(rate.NewLimiter(rate.Inf, 1))
	id := env.url("/client.json")
	resolveThenExpire(t, env, id)
	noStore.Store(true)

	_, err := env.fetcher.Resolve(context.Background(), id)
	require.NoError(t, err)
	assert.False(t, env.hasDoc(id), "not cacheable")
	assert.True(t, env.hasKnown(id), "a valid answer keeps the client known")
	assert.Equal(t, knownTTL, env.mr.TTL(KnownPrefix+cacheKey(id)), "and renews the marker")

	// Junk on the host exhausts the host budget; the known client still resolves.
	for i := 0; i < perHostFetchesPerMin+5; i++ {
		_, _ = env.fetcher.Resolve(context.Background(), env.url("/junk"+string(rune('a'+i%26))+string(rune('a'+i/26))))
	}
	_, err = env.fetcher.Resolve(context.Background(), id)
	require.NoError(t, err, "known clients are budgeted per URL, not per host")
}
