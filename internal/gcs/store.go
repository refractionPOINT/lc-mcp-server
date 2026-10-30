package gcs

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	"cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

const (
	// maxCreateAttempts bounds how many times an upload is retried with a freshly
	// generated object name when the create-only precondition fails.
	maxCreateAttempts = 5

	// objectIDBytes is the entropy of the random part of an object name (128 bits).
	objectIDBytes = 16

	// maxToolNameLen caps the tool name component of an object name.
	maxToolNameLen = 64

	// maxSignedURLExpiry is the V4 signing limit.
	maxSignedURLExpiry = 7 * 24 * time.Hour

	// defaultSignedURLExpiry is used when the configured expiry is not positive.
	defaultSignedURLExpiry = 24 * time.Hour
)

// errObjectExists is returned by objectStore.Create when the create-only
// precondition fails because an object with that name already exists.
var errObjectExists = errors.New("object already exists")

// errNoTenantIdentity is returned when the request context carries no usable
// tenant/credential identity. Uploads fail closed: the caller returns the
// result inline instead.
var errNoTenantIdentity = errors.New("no tenant identity in request context")

// objectStore is the narrow storage surface the Manager needs. It exists so the
// upload logic can be tested without talking to real GCS.
type objectStore interface {
	// Create writes data under name only if no object with that name exists, and
	// returns the generation of the object it wrote. It returns errObjectExists
	// when the name is taken.
	Create(ctx context.Context, name string, data []byte) (generation int64, err error)

	// SignGetURL returns a V4 signed GET URL bound to exactly this generation of
	// the object.
	SignGetURL(ctx context.Context, name string, generation int64, expires time.Time) (string, error)
}

// gcsStore is the real objectStore backed by Cloud Storage.
type gcsStore struct {
	client       *storage.Client
	bucket       string
	signerAcct   string
	newIAMClient func(ctx context.Context) (signer, error)
}

// signer signs a V4 payload on behalf of the signer service account.
type signer interface {
	SignBlob(ctx context.Context, name string, payload []byte) ([]byte, error)
	Close() error
}

type iamSigner struct {
	c *credentials.IamCredentialsClient
}

func (s *iamSigner) SignBlob(ctx context.Context, name string, payload []byte) ([]byte, error) {
	resp, err := s.c.SignBlob(ctx, &credentialspb.SignBlobRequest{Name: name, Payload: payload})
	if err != nil {
		return nil, err
	}
	return resp.SignedBlob, nil
}

func (s *iamSigner) Close() error { return s.c.Close() }

func newGCSStore(client *storage.Client, bucket, signerAcct string) *gcsStore {
	return &gcsStore{
		client:     client,
		bucket:     bucket,
		signerAcct: signerAcct,
		newIAMClient: func(ctx context.Context) (signer, error) {
			c, err := credentials.NewIamCredentialsClient(ctx)
			if err != nil {
				return nil, err
			}
			return &iamSigner{c: c}, nil
		},
	}
}

// Create implements objectStore with a DoesNotExist precondition, so an existing
// object (any tenant's) can never be overwritten.
func (s *gcsStore) Create(ctx context.Context, name string, data []byte) (int64, error) {
	obj := s.client.Bucket(s.bucket).Object(name).If(storage.Conditions{DoesNotExist: true})
	w := obj.NewWriter(ctx)
	w.ContentType = "application/json"
	w.ContentEncoding = "gzip"
	w.CacheControl = "private, no-store"

	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		return 0, sanitizeStoreError(err)
	}
	if err := w.Close(); err != nil {
		return 0, sanitizeStoreError(err)
	}
	attrs := w.Attrs()
	if attrs == nil || attrs.Generation == 0 {
		// Without the generation we cannot bind the URL; treat as a failure.
		return 0, errors.New("storage did not report an object generation")
	}
	return attrs.Generation, nil
}

// SignGetURL implements objectStore.
func (s *gcsStore) SignGetURL(ctx context.Context, name string, generation int64, expires time.Time) (string, error) {
	iam, err := s.newIAMClient(ctx)
	if err != nil {
		return "", errors.New("failed to create signing client")
	}
	defer iam.Close()

	resource := fmt.Sprintf("projects/-/serviceAccounts/%s", s.signerAcct)
	opts := buildSignedURLOptions(s.signerAcct, expires, generation, func(b []byte) ([]byte, error) {
		signed, err := iam.SignBlob(ctx, resource, b)
		if err != nil {
			return nil, errors.New("signBlob failed")
		}
		return signed, nil
	})

	u, err := storage.SignedURL(s.bucket, name, opts)
	if err != nil {
		return "", errors.New("failed to generate signed URL")
	}
	return u, nil
}

// buildSignedURLOptions returns the V4 options for a GET-only URL that is valid
// for exactly one object generation. The generation is passed as a query
// parameter, which V4 signing includes in the canonical query string, so it
// cannot be altered or dropped without invalidating the signature.
func buildSignedURLOptions(accessID string, expires time.Time, generation int64, signBytes func([]byte) ([]byte, error)) *storage.SignedURLOptions {
	return &storage.SignedURLOptions{
		GoogleAccessID:  accessID,
		Method:          http.MethodGet,
		Expires:         expires,
		Scheme:          storage.SigningSchemeV4,
		QueryParameters: url.Values{"generation": {strconv.FormatInt(generation, 10)}},
		SignBytes:       signBytes,
	}
}

// signedURLExpiry converts the configured expiry in hours into a bounded duration.
func signedURLExpiry(hours int) time.Duration {
	d := time.Duration(hours) * time.Hour
	if d <= 0 {
		return defaultSignedURLExpiry
	}
	if d > maxSignedURLExpiry {
		return maxSignedURLExpiry
	}
	return d
}

// sanitizeStoreError reduces a storage error to something that carries no object
// names, URLs or response bodies, while still letting callers detect an
// existing-object precondition failure and context cancellation.
func sanitizeStoreError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		if gerr.Code == http.StatusPreconditionFailed {
			return errObjectExists
		}
		return fmt.Errorf("storage request failed (HTTP %d)", gerr.Code)
	}
	return errors.New("storage request failed")
}

// newNameKey returns a fresh random key for hashing tenant identity into object
// name prefixes.
func newNameKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate name key: %w", err)
	}
	return key, nil
}

// tenantPrefix derives the per-tenant, per-credential object name prefix from
// the authenticated request context. Each component is a keyed hash (HMAC-SHA256
// under a per-process random key, truncated to 128 bits), so names never contain
// raw OIDs, UIDs, API keys or tokens and cannot be correlated or guessed from
// outside the process. Different tenants, or different credentials of the same
// tenant, always land under different prefixes.
func tenantPrefix(ctx context.Context, key []byte) (string, error) {
	ac, err := auth.FromContext(ctx)
	if err != nil || ac == nil {
		return "", errNoTenantIdentity
	}
	tenant := ac.OID
	kind := "oid"
	if tenant == "" {
		tenant = ac.UID
		kind = "uid"
	}
	if tenant == "" {
		return "", errNoTenantIdentity
	}
	cred := ac.CacheKey()
	return mac(key, "tenant:"+kind, tenant) + "/" + mac(key, "cred", cred), nil
}

func mac(key []byte, domain, value string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// randomID returns a URL-safe identifier with 128 bits of crypto/rand entropy.
func randomID() (string, error) {
	b := make([]byte, objectIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate object id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// sanitizeToolName restricts the tool name to a safe, bounded character set so
// it can neither inject path segments into object names nor break temp file
// patterns.
func sanitizeToolName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() >= maxToolNameLen {
			break
		}
	}
	if b.Len() == 0 {
		return "result"
	}
	return b.String()
}

// newObjectName builds <tenantHash>/<credHash>/<tool>_<randomID>.json.gz.
func newObjectName(prefix, toolName string) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%s_%s.json.gz", prefix, sanitizeToolName(toolName), id), nil
}
