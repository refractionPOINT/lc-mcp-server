package gcs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

// ---- helpers ----

func ctxFor(oid, apiKey string) context.Context {
	return auth.WithAuthContext(context.Background(), &auth.AuthContext{
		Mode:   auth.AuthModeNormal,
		OID:    oid,
		APIKey: apiKey,
	})
}

type fakeObject struct {
	data       []byte
	generation int64
}

// fakeStore is an in-memory objectStore enforcing create-only semantics like GCS
// does with a DoesNotExist precondition.
type fakeStore struct {
	mu      sync.Mutex
	objects map[string]fakeObject
	nextGen int64

	// preexisting names that the next Create calls collide with, in order.
	collideFirst int
	createErr    error
	signErr      error

	createCalls int
	creates     []string
	signed      []signCall
}

type signCall struct {
	name       string
	generation int64
	expires    time.Time
}

func newFakeStore() *fakeStore {
	return &fakeStore{objects: map[string]fakeObject{}, nextGen: 1000}
}

func (f *fakeStore) Create(_ context.Context, name string, data []byte) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createCalls++
	f.creates = append(f.creates, name)
	if f.createErr != nil {
		return 0, f.createErr
	}
	if f.collideFirst > 0 {
		f.collideFirst--
		return 0, errObjectExists
	}
	if _, ok := f.objects[name]; ok {
		return 0, errObjectExists
	}
	f.nextGen++
	f.objects[name] = fakeObject{data: append([]byte(nil), data...), generation: f.nextGen}
	return f.nextGen, nil
}

func (f *fakeStore) SignGetURL(_ context.Context, name string, generation int64, expires time.Time) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.signErr != nil {
		return "", f.signErr
	}
	f.signed = append(f.signed, signCall{name, generation, expires})
	return fmt.Sprintf("https://signed.invalid/%s?generation=%d", name, generation), nil
}

func newTestManager(t *testing.T, store objectStore) *Manager {
	t.Helper()
	key, err := newNameKey()
	require.NoError(t, err)
	return &Manager{
		config:  &Config{BucketName: "b", TokenThreshold: 10, URLExpiryHours: 24, Enabled: true},
		store:   store,
		nameKey: key,
	}
}

func largeData() map[string]interface{} {
	d := map[string]interface{}{}
	for i := 0; i < 50; i++ {
		d[fmt.Sprintf("k%d", i)] = "a fairly long value to exceed the token threshold"
	}
	return d
}

// ---- name generation ----

func TestRandomID_UniqueUnderConcurrency(t *testing.T) {
	const goroutines = 16
	const perG = 1_000_000 / goroutines

	results := make([][]string, goroutines)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ids := make([]string, perG)
			for i := range ids {
				id, err := randomID()
				if err != nil {
					t.Error(err)
					return
				}
				ids[i] = id
			}
			results[g] = ids
		}(g)
	}
	wg.Wait()

	seen := make(map[string]struct{}, goroutines*perG)
	for _, ids := range results {
		for _, id := range ids {
			_, dup := seen[id]
			require.False(t, dup, "duplicate id generated")
			seen[id] = struct{}{}
		}
	}
	assert.Len(t, seen, goroutines*perG)
}

func TestRandomID_Format(t *testing.T) {
	id, err := randomID()
	require.NoError(t, err)
	// 16 bytes -> 22 unpadded base64url chars: >= 128 bits of entropy.
	assert.Len(t, id, 22)
	assert.Regexp(t, `^[A-Za-z0-9_-]+$`, id)
}

func TestNewObjectName_UniqueSameTenantConcurrent(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]struct{}{}
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]string, 0, 5000)
			for i := 0; i < 5000; i++ {
				n, err := newObjectName("pfx/cred", "list_sensors")
				if err != nil {
					t.Error(err)
					return
				}
				local = append(local, n)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, n := range local {
				if _, dup := seen[n]; dup {
					t.Errorf("duplicate object name")
				}
				seen[n] = struct{}{}
			}
		}()
	}
	wg.Wait()
	assert.Len(t, seen, 16*5000)
}

func TestSanitizeToolName(t *testing.T) {
	assert.Equal(t, "list_sensors", sanitizeToolName("list_sensors"))
	assert.Equal(t, "a_b_c_d", sanitizeToolName("a/b\\c d"))
	assert.Equal(t, "_______", sanitizeToolName("../../."))
	assert.Equal(t, "result", sanitizeToolName(""))
	assert.Len(t, sanitizeToolName(strings.Repeat("x", 500)), maxToolNameLen)
	assert.NotContains(t, sanitizeToolName("../etc/passwd"), "/")
}

func TestTenantPrefix(t *testing.T) {
	key, err := newNameKey()
	require.NoError(t, err)

	t.Run("differs per tenant", func(t *testing.T) {
		a, err := tenantPrefix(ctxFor("oid-aaaa", "key-1"), key)
		require.NoError(t, err)
		b, err := tenantPrefix(ctxFor("oid-bbbb", "key-1"), key)
		require.NoError(t, err)
		assert.NotEqual(t, a, b)
		// The tenant segment itself must differ, not just the credential one.
		assert.NotEqual(t, strings.Split(a, "/")[0], strings.Split(b, "/")[0])
	})

	t.Run("differs per credential of the same tenant", func(t *testing.T) {
		a, _ := tenantPrefix(ctxFor("oid-aaaa", "key-1"), key)
		b, _ := tenantPrefix(ctxFor("oid-aaaa", "key-2"), key)
		assert.NotEqual(t, a, b)
		assert.Equal(t, strings.Split(a, "/")[0], strings.Split(b, "/")[0])
	})

	t.Run("stable for the same identity and key", func(t *testing.T) {
		a, _ := tenantPrefix(ctxFor("oid-aaaa", "key-1"), key)
		b, _ := tenantPrefix(ctxFor("oid-aaaa", "key-1"), key)
		assert.Equal(t, a, b)
	})

	t.Run("depends on the key", func(t *testing.T) {
		key2, _ := newNameKey()
		a, _ := tenantPrefix(ctxFor("oid-aaaa", "key-1"), key)
		b, _ := tenantPrefix(ctxFor("oid-aaaa", "key-1"), key2)
		assert.NotEqual(t, a, b)
	})

	t.Run("contains no raw identifiers or secrets", func(t *testing.T) {
		actx := auth.WithAuthContext(context.Background(), &auth.AuthContext{
			Mode:     auth.AuthModeNormal,
			OID:      "11111111-2222-3333-4444-555555555555",
			APIKey:   "super-secret-api-key",
			UID:      "user-uid-9999",
			JWTToken: "eyJhbGciOi.secretjwt.sig",
		})
		p, err := tenantPrefix(actx, key)
		require.NoError(t, err)
		name, err := newObjectName(p, "list_sensors")
		require.NoError(t, err)
		for _, secret := range []string{
			"11111111-2222-3333-4444-555555555555", "super-secret-api-key",
			"user-uid-9999", "eyJhbGciOi", "secretjwt",
		} {
			assert.NotContains(t, name, secret)
		}
		assert.Regexp(t, `^[0-9a-f]{32}/[0-9a-f]{32}/list_sensors_[A-Za-z0-9_-]{22}\.json\.gz$`, name)
	})

	t.Run("UID-only context uses the UID", func(t *testing.T) {
		mk := func(uid string) context.Context {
			return auth.WithAuthContext(context.Background(), &auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: uid, APIKey: "k"})
		}
		a, err := tenantPrefix(mk("uid-1"), key)
		require.NoError(t, err)
		b, err := tenantPrefix(mk("uid-2"), key)
		require.NoError(t, err)
		assert.NotEqual(t, a, b)
		assert.NotContains(t, a, "uid-1")
	})

	t.Run("OID and UID namespaces do not alias", func(t *testing.T) {
		o, _ := tenantPrefix(auth.WithAuthContext(context.Background(), &auth.AuthContext{Mode: auth.AuthModeNormal, OID: "same", APIKey: "k"}), key)
		u, _ := tenantPrefix(auth.WithAuthContext(context.Background(), &auth.AuthContext{Mode: auth.AuthModeUIDKey, UID: "same", APIKey: "k"}), key)
		assert.NotEqual(t, strings.Split(o, "/")[0], strings.Split(u, "/")[0])
	})

	t.Run("fails closed without identity", func(t *testing.T) {
		_, err := tenantPrefix(context.Background(), key)
		assert.ErrorIs(t, err, errNoTenantIdentity)
		_, err = tenantPrefix(auth.WithAuthContext(context.Background(), &auth.AuthContext{Mode: auth.AuthModeNormal}), key)
		assert.ErrorIs(t, err, errNoTenantIdentity)
	})
}

// ---- upload logic ----

func TestUploadToGCS_CreateOnlyAndGenerationBoundURL(t *testing.T) {
	store := newFakeStore()
	mgr := newTestManager(t, store)

	before := time.Now()
	res, err := mgr.UploadToGCS(ctxFor("oid-a", "key-a"), largeData(), "list_sensors")
	require.NoError(t, err)
	require.Len(t, store.creates, 1)
	require.Len(t, store.signed, 1)

	name := store.creates[0]
	obj := store.objects[name]
	assert.Equal(t, name, store.signed[0].name)
	assert.Equal(t, obj.generation, store.signed[0].generation, "URL must be bound to the generation written")
	assert.Contains(t, res.URL, fmt.Sprintf("generation=%d", obj.generation))
	assert.False(t, res.IsTemp)
	assert.Equal(t, int64(len(obj.data)), res.FileSize)

	exp := store.signed[0].expires
	assert.WithinDuration(t, before.Add(24*time.Hour), exp, time.Minute)

	assert.NotContains(t, name, "oid-a")
	assert.NotContains(t, name, "key-a")
}

func TestUploadToGCS_RetriesOnPreconditionFailure(t *testing.T) {
	store := newFakeStore()
	store.collideFirst = 3
	mgr := newTestManager(t, store)

	res, err := mgr.UploadToGCS(ctxFor("oid-a", "k"), largeData(), "tool")
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 4, store.createCalls)

	// Every attempt used a fresh name.
	seen := map[string]bool{}
	for _, n := range store.creates {
		assert.False(t, seen[n], "retry reused an object name")
		seen[n] = true
	}
	// Only the successful attempt was signed.
	require.Len(t, store.signed, 1)
	assert.Equal(t, store.creates[3], store.signed[0].name)
}

func TestUploadToGCS_RetryIsBounded(t *testing.T) {
	store := newFakeStore()
	store.collideFirst = 1000
	mgr := newTestManager(t, store)

	res, err := mgr.UploadToGCS(ctxFor("oid-a", "k"), largeData(), "tool")
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Equal(t, maxCreateAttempts, store.createCalls)
	assert.Empty(t, store.signed, "no URL may be produced when nothing was written")
	assert.Empty(t, store.objects)
}

func TestUploadToGCS_NonPreconditionErrorNotRetried(t *testing.T) {
	store := newFakeStore()
	store.createErr = errors.New("storage request failed (HTTP 503)")
	mgr := newTestManager(t, store)

	_, err := mgr.UploadToGCS(ctxFor("oid-a", "k"), largeData(), "tool")
	require.Error(t, err)
	assert.Equal(t, 1, store.createCalls)
	assert.Empty(t, store.signed)
}

func TestUploadToGCS_SignFailure(t *testing.T) {
	store := newFakeStore()
	store.signErr = errors.New("signing broke")
	mgr := newTestManager(t, store)

	res, err := mgr.UploadToGCS(ctxFor("oid-a", "k"), largeData(), "tool")
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestUploadToGCS_NoAuthContextFailsClosed(t *testing.T) {
	store := newFakeStore()
	mgr := newTestManager(t, store)

	res, err := mgr.UploadToGCS(context.Background(), largeData(), "tool")
	assert.ErrorIs(t, err, errNoTenantIdentity)
	assert.Nil(t, res)
	assert.Zero(t, store.createCalls, "must not write anything without a tenant identity")
}

func TestUploadToGCS_TenantsNeverShareNames(t *testing.T) {
	store := newFakeStore()
	mgr := newTestManager(t, store)

	const tenants = 8
	const perTenant = 200
	var wg sync.WaitGroup
	var failures atomic.Int32
	for tn := 0; tn < tenants; tn++ {
		wg.Add(1)
		go func(tn int) {
			defer wg.Done()
			ctx := ctxFor(fmt.Sprintf("oid-%d", tn), "key")
			for i := 0; i < perTenant; i++ {
				if _, err := mgr.UploadToGCS(ctx, map[string]interface{}{"t": tn, "pad": strings.Repeat("x", 100)}, "tool"); err != nil {
					failures.Add(1)
				}
			}
		}(tn)
	}
	wg.Wait()
	require.Zero(t, failures.Load())
	assert.Len(t, store.objects, tenants*perTenant, "every upload must create its own object")
	assert.Equal(t, tenants*perTenant, store.createCalls, "no retries expected with 128-bit names")

	prefixes := map[string]bool{}
	for name := range store.objects {
		prefixes[name[:strings.LastIndex(name, "/")]] = true
	}
	assert.Len(t, prefixes, tenants)
}

func TestExpiryBounds(t *testing.T) {
	assert.Equal(t, 24*time.Hour, signedURLExpiry(0))
	assert.Equal(t, 24*time.Hour, signedURLExpiry(-5))
	assert.Equal(t, time.Hour, signedURLExpiry(1))
	assert.Equal(t, 24*time.Hour, signedURLExpiry(24))
	assert.Equal(t, 7*24*time.Hour, signedURLExpiry(100000))
}

// ---- WrapResult / WrapMCPResult failure behaviour ----

func TestWrapResult_UploadFailureReturnsErrorNotLocalPath(t *testing.T) {
	store := newFakeStore()
	store.createErr = errors.New("storage request failed")
	mgr := newTestManager(t, store)

	wrapped, err := mgr.WrapResult(ctxFor("oid-a", "k"), largeData(), "tool")
	require.Error(t, err)
	assert.Nil(t, wrapped)
}

func TestWrapMCPResult_UploadFailureReturnsOriginalInline(t *testing.T) {
	store := newFakeStore()
	store.createErr = errors.New("storage request failed")
	mgr := newTestManager(t, store)
	ctx := WithGCSManager(ctxFor("oid-a", "k"), mgr)

	text, _ := json.Marshal(largeData())
	mcp := map[string]interface{}{
		"isError": false,
		"content": []interface{}{map[string]interface{}{"type": "text", "text": string(text)}},
	}
	result := WrapMCPResult(ctx, mcp, "tool")
	assert.Equal(t, mcp, result, "the caller's own result is returned unchanged")
}

func TestWrapMCPResult_Success(t *testing.T) {
	store := newFakeStore()
	mgr := newTestManager(t, store)
	ctx := WithGCSManager(ctxFor("oid-a", "k"), mgr)

	text, _ := json.Marshal(largeData())
	mcp := map[string]interface{}{
		"isError": false,
		"content": []interface{}{map[string]interface{}{"type": "text", "text": string(text)}},
	}
	result := WrapMCPResult(ctx, mcp, "tool").(map[string]interface{})
	item := result["content"].([]interface{})[0].(map[string]interface{})
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(item["text"].(string)), &body))
	assert.Contains(t, body["resource_link"], "generation=")
	assert.Equal(t, false, body["is_temp_file"])
}

func TestWrapMCPResult_NoAuthContextReturnsInline(t *testing.T) {
	store := newFakeStore()
	mgr := newTestManager(t, store)
	ctx := WithGCSManager(context.Background(), mgr)

	text, _ := json.Marshal(largeData())
	mcp := map[string]interface{}{
		"isError": false,
		"content": []interface{}{map[string]interface{}{"type": "text", "text": string(text)}},
	}
	assert.Equal(t, mcp, WrapMCPResult(ctx, mcp, "tool"))
	assert.Zero(t, store.createCalls)
}

// ---- error sanitisation ----

func TestSanitizeStoreError(t *testing.T) {
	// Raw storage errors can embed object paths and URLs; none may survive.
	raw := &googleapiErrorForTest{code: 403, msg: "access denied to tenantX/secret_object.json.gz at https://storage.googleapis.com/b/tenantX/secret_object.json.gz"}
	err := sanitizeStoreError(raw.toError())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "tenantX")
	assert.NotContains(t, err.Error(), "https://")
	assert.Contains(t, err.Error(), "403")

	other := sanitizeStoreError(errors.New("Put https://storage.googleapis.com/b/obj: boom"))
	assert.NotContains(t, other.Error(), "obj")
	assert.NotContains(t, other.Error(), "https://")

	assert.ErrorIs(t, sanitizeStoreError(context.Canceled), context.Canceled)
	assert.ErrorIs(t, sanitizeStoreError((&googleapiErrorForTest{code: 412, msg: "x"}).toError()), errObjectExists)
	assert.NoError(t, sanitizeStoreError(nil))
}

// ---- signed URL options ----

func TestBuildSignedURLOptions(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	opts := buildSignedURLOptions("signer@example.iam.gserviceaccount.com", exp, 1700000000123456, func(b []byte) ([]byte, error) { return b, nil })
	assert.Equal(t, http.MethodGet, opts.Method)
	assert.Equal(t, storage.SigningSchemeV4, opts.Scheme)
	assert.Equal(t, exp, opts.Expires)
	assert.Equal(t, "1700000000123456", opts.QueryParameters.Get("generation"))
	assert.Empty(t, opts.Headers)
}

func TestSignedURL_GenerationIsSigned(t *testing.T) {
	sign := func(gen int64, payloads *[][]byte) string {
		opts := buildSignedURLOptions("signer@example.iam.gserviceaccount.com", time.Now().Add(time.Hour), gen, func(b []byte) ([]byte, error) {
			*payloads = append(*payloads, append([]byte(nil), b...))
			return []byte("sig"), nil
		})
		u, err := storage.SignedURL("bucket", "tenant/cred/obj.json.gz", opts)
		require.NoError(t, err)
		return u
	}

	// The signed payload embeds a per-second timestamp, so retry until the three
	// URLs share one second, then require that only the generation differs.
	for attempt := 0; attempt < 10; attempt++ {
		var pa1, pa2, pb [][]byte
		ua1 := sign(111, &pa1)
		ua2 := sign(111, &pa2)
		ub := sign(222, &pb)

		parse := func(s string) url.Values {
			u, err := url.Parse(s)
			require.NoError(t, err)
			return u.Query()
		}
		qa1, qa2, qb := parse(ua1), parse(ua2), parse(ub)
		if qa1.Get("X-Goog-Date") != qb.Get("X-Goog-Date") || qa1.Get("X-Goog-Date") != qa2.Get("X-Goog-Date") {
			continue
		}

		assert.Equal(t, "111", qa1.Get("generation"))
		assert.Equal(t, "222", qb.Get("generation"))
		assert.Equal(t, "GOOG4-RSA-SHA256", qa1.Get("X-Goog-Algorithm"))
		assert.Equal(t, "host", qa1.Get("X-Goog-SignedHeaders"), "GET with no extra signed headers")
		assert.Contains(t, []string{"3599", "3600"}, qa1.Get("X-Goog-Expires"))
		assert.True(t, strings.HasPrefix(ua1, "https://storage.googleapis.com/bucket/tenant/cred/obj.json.gz?"))

		assert.Equal(t, pa1[0], pa2[0], "identical inputs sign identical payloads")
		assert.NotEqual(t, pa1[0], pb[0], "changing the generation must change what is signed")
		return
	}
	t.Fatal("could not obtain three signed URLs within one second")
}

// A different HTTP method signs a different payload, so a GET URL is not
// reusable for PUT/DELETE.
func TestSignedURL_MethodIsSigned(t *testing.T) {
	for attempt := 0; attempt < 10; attempt++ {
		var pg, pp []byte
		og := buildSignedURLOptions("s@x.iam.gserviceaccount.com", time.Now().Add(time.Hour), 5, func(b []byte) ([]byte, error) { pg = b; return []byte("s"), nil })
		ug, err := storage.SignedURL("b", "o", og)
		require.NoError(t, err)
		op := buildSignedURLOptions("s@x.iam.gserviceaccount.com", time.Now().Add(time.Hour), 5, func(b []byte) ([]byte, error) { pp = b; return []byte("s"), nil })
		op.Method = http.MethodPut
		up, err := storage.SignedURL("b", "o", op)
		require.NoError(t, err)
		d1, d2 := dateOf(t, ug), dateOf(t, up)
		if d1 != d2 {
			continue
		}
		assert.NotEqual(t, pg, pp)
		return
	}
	t.Fatal("timing")
}

func dateOf(t *testing.T, s string) string {
	u, err := url.Parse(s)
	require.NoError(t, err)
	return u.Query().Get("X-Goog-Date")
}

type fakeSigner struct {
	names    []string
	payloads [][]byte
	closed   bool
}

func (f *fakeSigner) SignBlob(_ context.Context, name string, payload []byte) ([]byte, error) {
	f.names = append(f.names, name)
	f.payloads = append(f.payloads, payload)
	return []byte("fake-signature"), nil
}
func (f *fakeSigner) Close() error { f.closed = true; return nil }

func TestGCSStore_SignGetURL(t *testing.T) {
	fs := &fakeSigner{}
	s := &gcsStore{
		bucket:     "bkt",
		signerAcct: "signer@example.iam.gserviceaccount.com",
		newIAMClient: func(context.Context) (signer, error) {
			return fs, nil
		},
	}
	u, err := s.SignGetURL(context.Background(), "t/c/obj.json.gz", 4242, time.Now().Add(2*time.Hour))
	require.NoError(t, err)

	parsed, err := url.Parse(u)
	require.NoError(t, err)
	assert.Equal(t, "/bkt/t/c/obj.json.gz", parsed.Path)
	q := parsed.Query()
	assert.Equal(t, "4242", q.Get("generation"))
	assert.Contains(t, q.Get("X-Goog-Credential"), "signer@example.iam.gserviceaccount.com/")
	assert.Equal(t, []string{"projects/-/serviceAccounts/signer@example.iam.gserviceaccount.com"}, fs.names)
	assert.True(t, fs.closed)
}

func TestGCSStore_SignGetURL_SignerFailureIsSanitised(t *testing.T) {
	s := &gcsStore{
		bucket:     "bkt",
		signerAcct: "signer@example.iam.gserviceaccount.com",
		newIAMClient: func(context.Context) (signer, error) {
			return nil, errors.New("dial credentials for projects/secret-project failed")
		},
	}
	_, err := s.SignGetURL(context.Background(), "t/c/obj", 1, time.Now().Add(time.Hour))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "secret-project")
}

// ---- the real storage writer against a local HTTP fake ----

// TestGCSStore_Create_SendsDoesNotExistPrecondition drives the real
// cloud.google.com/go/storage writer against a local server and asserts it
// sends ifGenerationMatch=0 (the DoesNotExist precondition), and that a 412 is
// mapped to errObjectExists without leaking the response body.
func TestGCSStore_Create_SendsDoesNotExistPrecondition(t *testing.T) {
	var gotQuery url.Values
	var gotPath string
	respondWith := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		if respondWith == 412 {
			w.WriteHeader(412)
			_, _ = w.Write([]byte(`{"error":{"code":412,"message":"conditionNotMet for tenantX/secret.json.gz","errors":[{"reason":"conditionNotMet"}]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"name":"obj","bucket":"bkt","generation":"1234567890"}`))
	}))
	defer srv.Close()

	client, err := storage.NewClient(context.Background(),
		option.WithEndpoint(srv.URL+"/storage/v1/"),
		option.WithoutAuthentication())
	require.NoError(t, err)
	defer client.Close()

	s := newGCSStore(client, "bkt", "signer@example.iam.gserviceaccount.com")

	gen, err := s.Create(context.Background(), "pfx/obj.json.gz", []byte("gzdata"))
	require.NoError(t, err)
	assert.Equal(t, int64(1234567890), gen)
	assert.Contains(t, gotPath, "/bkt/o")
	assert.Equal(t, "0", gotQuery.Get("ifGenerationMatch"), "create-only precondition must be sent")

	respondWith = 412
	_, err = s.Create(context.Background(), "pfx/obj.json.gz", []byte("gzdata"))
	assert.ErrorIs(t, err, errObjectExists)

	respondWith = 500
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"error":{"code":403,"message":"denied for tenantX/secret.json.gz"}}`))
	})
	_, err = s.Create(context.Background(), "pfx/obj.json.gz", []byte("gzdata"))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "tenantX")
	assert.NotContains(t, err.Error(), "secret")
}

type googleapiErrorForTest struct {
	code int
	msg  string
}

func (g *googleapiErrorForTest) toError() error {
	return &googleapi.Error{Code: g.code, Message: g.msg}
}
