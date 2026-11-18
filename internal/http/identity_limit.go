package http

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/ratelimit"
)

// identityKey names the caller behind a resolved credential, for per-identity
// rate limiting, or "" when there is nothing to key on (server-wide credentials,
// which are not a caller).
//
//   - OAuth access token and LimaCharlie JWT: the uid. Both are verified before
//     this point, so a caller cannot name someone else's bucket.
//   - Org JWT without a uid: the org it is pinned to.
//   - API key headers: a hash of the key. These credentials are verified only
//     downstream by the LimaCharlie API, so the uid/oid headers are not trusted
//     here; the key is a secret the caller must know, so it cannot be used to
//     drain another caller's bucket. The key itself never reaches Redis.
func identityKey(a *resolvedAuth) string {
	if a == nil || a.authCtx == nil {
		return ""
	}
	c := a.authCtx
	switch {
	case c.APIKey != "":
		sum := sha256.Sum256([]byte(c.APIKey))
		return "key:" + hex.EncodeToString(sum[:16])
	case c.Mode == auth.AuthModeUIDOAuth && c.UID != "":
		return "uid:" + c.UID
	case c.JWTToken != "" && c.OID != "":
		return "oid:" + c.OID
	}
	return ""
}

// allowIdentity charges the per-identity MCP limit, in addition to the
// per-address limit already charged by rateLimitMiddleware. It answers 429 and
// returns false when the caller is over the limit. Like the address limiter it
// fails open on a Redis error.
func (s *Server) allowIdentity(w http.ResponseWriter, r *http.Request, a *resolvedAuth) bool {
	if s.rateLimiter == nil {
		return true
	}
	id := identityKey(a)
	if id == "" {
		return true
	}
	cfg := ratelimit.DefaultConfigs["mcp_request"]
	allowed, err := s.rateLimiter.Allow(r.Context(), id+":mcp_request", cfg)
	if err != nil {
		s.logger.Warn("Identity rate limit check error", "error", err)
	}
	if !allowed {
		writeRateLimited(w)
		return false
	}
	return true
}
