package cimd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

// Cache key prefixes (Redis).
const (
	DocPrefix  = "oauth:cimd:doc:"
	HostPrefix = "oauth:cimd:host:"
)

// Defaults. The 5 KiB suggested by the draft is too tight for real documents
// with long redirect lists, so we allow 64 KiB; still tiny.
const (
	maxBodyBytes   = 64 << 10
	maxHeaderBytes = 16 << 10
	dialTimeout    = 4 * time.Second
	requestTimeout = 5 * time.Second

	minCacheTTL     = 5 * time.Minute
	maxCacheTTL     = 24 * time.Hour
	defaultCacheTTL = time.Hour

	maxConcurrentFetches = 16
	globalRatePerSecond  = 20
	globalRateBurst      = 40
	perHostFetchesPerMin = 30
	userAgent            = "LimaCharlie-MCP-OAuth/1 (client metadata document fetcher)"
)

// ErrorKind classifies a resolution failure.
type ErrorKind int

const (
	KindInvalidClientID ErrorKind = iota + 1 // the client_id string itself is unacceptable
	KindFetch                                // the document could not be retrieved
	KindInvalidDocument                      // retrieved but not a valid document
	KindUnsupported                          // valid document asking for something we don't do
	KindBusy                                 // we are shedding load; try again later
)

// Error is a resolution failure. Message is safe to show to the end user and
// never contains network-level detail about our infrastructure.
type Error struct {
	Kind    ErrorKind
	Message string
}

func (e *Error) Error() string { return e.Message }

// Store is the cache backend, implemented by the OAuth state manager (Redis).
type Store interface {
	GetEphemeral(ctx context.Context, key string) (string, error)
	SetEphemeral(ctx context.Context, key, value string, ttl time.Duration) error
	// IncrEphemeral increments a counter, starting a new window of the given
	// length when the counter is created, and returns the new value.
	IncrEphemeral(ctx context.Context, key string, window time.Duration) (int64, error)
}

// Fetcher resolves CIMD client_ids to validated documents.
type Fetcher struct {
	store  Store
	logger *slog.Logger
	client *http.Client
	policy urlPolicy

	group   singleflight.Group
	sem     chan struct{}
	limiter *rate.Limiter
}

// NewFetcher builds the production fetcher: SSRF-guarded dialer, no proxy, no
// redirects, no cookies, bounded time and size.
func NewFetcher(store Store, logger *slog.Logger) *Fetcher {
	return newFetcher(store, logger, newSafeClient(), urlPolicy{})
}

// NewFetcherForTesting builds a fetcher around a caller-supplied transport
// (typically httptest.Server.Client().Transport) and relaxes the URL rules that
// would otherwise rule out httptest servers (IP literal host, arbitrary port).
// The supplied transport replaces the SSRF-guarded one, so this must never be
// used outside tests. There is deliberately no configuration path (flag,
// environment variable) to reach it. Timeouts, redirect refusal and the
// absence of cookies are still the production ones.
func NewFetcherForTesting(store Store, logger *slog.Logger, transport http.RoundTripper) *Fetcher {
	return newFetcher(store, logger, clientWithTransport(transport), urlPolicy{allowAnyPort: true, allowIPLiteral: true})
}

func newFetcher(store Store, logger *slog.Logger, client *http.Client, pol urlPolicy) *Fetcher {
	return &Fetcher{
		store:   store,
		logger:  logger,
		client:  client,
		policy:  pol,
		sem:     make(chan struct{}, maxConcurrentFetches),
		limiter: rate.NewLimiter(globalRatePerSecond, globalRateBurst),
	}
}

// newSafeClient returns the HTTP client used for production fetches.
func newSafeClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: dialTimeout,
		Control: ssrfDialControl,
	}
	transport := &http.Transport{
		Proxy:                  nil, // never honour HTTP(S)_PROXY for this client
		DialContext:            dialer.DialContext,
		TLSHandshakeTimeout:    dialTimeout,
		ResponseHeaderTimeout:  requestTimeout,
		MaxResponseHeaderBytes: maxHeaderBytes,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           -1,
	}
	return clientWithTransport(transport)
}

func clientWithTransport(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		Jar:       nil, // no cookies, in or out
		// Redirects are refused: the 3xx response is returned and rejected.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Resolve returns the validated metadata document for clientID, from cache
// when possible. The returned error is an *Error.
func (f *Fetcher) Resolve(ctx context.Context, clientID string) (*Document, error) {
	if _, err := validateClientID(clientID, f.policy); err != nil {
		return nil, err
	}
	key := cacheKey(clientID)

	if doc, ok := f.cachedDoc(ctx, key); ok {
		return doc, nil
	}

	// One fetch per URL no matter how many requests want it. The shared fetch
	// is detached from any single caller's cancellation but keeps its own
	// deadline; callers still stop waiting when their own context ends.
	ch := f.group.DoChan(clientID, func() (any, error) {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), requestTimeout+time.Second)
		defer cancel()
		return f.fetchAndCache(fctx, clientID, key)
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*Document), nil
	case <-ctx.Done():
		return nil, &Error{Kind: KindFetch, Message: "request cancelled while fetching the client metadata document"}
	}
}

func (f *Fetcher) fetchAndCache(ctx context.Context, clientID, key string) (*Document, error) {
	host := hostOf(clientID)

	// Another request may have populated the cache while we queued.
	if doc, ok := f.cachedDoc(ctx, key); ok {
		return doc, nil
	}

	// Abuse bounds: a global rate and concurrency cap on this process, and a
	// per-host cap (shared across replicas) so we can't be used to hammer a
	// third-party host by varying the path.
	if !f.limiter.Allow() {
		f.logger.Warn("CIMD fetch shed: global rate limit", "client_host", host)
		return nil, &Error{Kind: KindBusy, Message: "too many client metadata lookups in progress; try again shortly"}
	}
	n, err := f.store.IncrEphemeral(ctx, HostPrefix+hashHex(strings.ToLower(host)), time.Minute)
	if err != nil {
		f.logger.Warn("CIMD per-host counter unavailable", "error", err)
	} else if n > perHostFetchesPerMin {
		f.logger.Warn("CIMD fetch shed: per-host limit", "client_host", host)
		return nil, &Error{Kind: KindBusy, Message: "too many lookups for this client's host; try again shortly"}
	}
	select {
	case f.sem <- struct{}{}:
		defer func() { <-f.sem }()
	case <-ctx.Done():
		return nil, &Error{Kind: KindBusy, Message: "too many client metadata lookups in progress; try again shortly"}
	}

	doc, ttl, err := f.fetch(ctx, clientID)
	if err != nil {
		var e *Error
		if !errors.As(err, &e) {
			e = &Error{Kind: KindFetch, Message: "could not fetch the client metadata document"}
		}
		// Failures are never cached (draft-ietf-oauth-client-id-metadata-
		// document section 4.4: the AS MUST NOT cache error responses or
		// invalid documents). Repeated lookups of a failing client_id are
		// bounded by the single-flight above and the rate limits here.
		f.logger.Info("CIMD client rejected", "client_host", host, "outcome", "error", "kind", int(e.Kind), "reason", e.Message)
		return nil, e
	}
	f.logger.Info("CIMD client resolved", "client_host", host, "outcome", "ok", "cache_ttl_seconds", int(ttl.Seconds()))
	if ttl > 0 {
		f.storeDoc(ctx, key, doc, ttl)
	}
	return doc, nil
}

// fetch performs the HTTP exchange and validates the document. A zero ttl
// means "do not cache".
func (f *Fetcher) fetch(ctx context.Context, clientID string) (*Document, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, 0, &Error{Kind: KindInvalidClientID, Message: "invalid client_id URL"}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := f.client.Do(req)
	if err != nil {
		// err can name the destination address; keep it in the log only.
		f.logger.Debug("CIMD fetch failed", "client_host", hostOf(clientID), "error", err)
		return nil, 0, &Error{Kind: KindFetch, Message: "could not fetch the client metadata document"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// This also covers 3xx: redirects are not followed.
		return nil, 0, &Error{Kind: KindFetch, Message: fmt.Sprintf("client metadata document request returned HTTP %d", resp.StatusCode)}
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil ||
		!(mt == "application/json" || strings.HasSuffix(mt, "+json")) {
		return nil, 0, invalidDoc("content type must be application/json")
	}
	if resp.ContentLength > maxBodyBytes {
		return nil, 0, invalidDoc("document is too large")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, 0, &Error{Kind: KindFetch, Message: "could not read the client metadata document"}
	}
	if len(body) > maxBodyBytes {
		return nil, 0, invalidDoc("document is too large")
	}

	doc, err := parseDocument(clientID, body)
	if err != nil {
		return nil, 0, err
	}
	return doc, cacheTTL(resp.Header.Get("Cache-Control")), nil
}

// cacheTTL derives how long to keep a document from Cache-Control, bounded to
// [minCacheTTL, maxCacheTTL]. Zero means do not cache. Our cache is shared
// between users, so "private" and "no-cache" (which requires revalidation we
// don't do) are treated like "no-store".
func cacheTTL(cacheControl string) time.Duration {
	var maxAge, sMaxAge time.Duration = -1, -1
	for _, part := range strings.Split(cacheControl, ",") {
		name, val, _ := strings.Cut(strings.TrimSpace(part), "=")
		val = strings.Trim(val, `"`)
		switch strings.ToLower(name) {
		case "no-store", "no-cache", "private":
			return 0
		case "max-age", "s-maxage":
			secs, err := strconv.ParseInt(val, 10, 64)
			if err != nil || secs < 0 {
				continue
			}
			d := time.Duration(min(secs, int64(maxCacheTTL/time.Second))) * time.Second
			if strings.EqualFold(name, "s-maxage") {
				sMaxAge = d
			} else {
				maxAge = d
			}
		}
	}
	ttl := defaultCacheTTL
	switch {
	case sMaxAge >= 0:
		ttl = sMaxAge
	case maxAge >= 0:
		ttl = maxAge
	}
	return min(max(ttl, minCacheTTL), maxCacheTTL)
}

func (f *Fetcher) cachedDoc(ctx context.Context, key string) (*Document, bool) {
	raw, err := f.store.GetEphemeral(ctx, DocPrefix+key)
	if err != nil {
		f.logger.Warn("CIMD cache read failed", "error", err)
		return nil, false
	}
	if raw == "" {
		return nil, false
	}
	var doc Document
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return nil, false
	}
	return &doc, true
}

func (f *Fetcher) storeDoc(ctx context.Context, key string, doc *Document, ttl time.Duration) {
	b, err := json.Marshal(doc)
	if err != nil {
		return
	}
	if err := f.store.SetEphemeral(ctx, DocPrefix+key, string(b), ttl); err != nil {
		f.logger.Warn("CIMD cache write failed", "error", err)
	}
}

func cacheKey(clientID string) string { return hashHex(clientID) }

func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hostOf(clientID string) string {
	if u, err := url.Parse(clientID); err == nil {
		return u.Hostname()
	}
	return ""
}
