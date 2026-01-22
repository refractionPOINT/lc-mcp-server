package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// contextKey is an unexported type for context keys to prevent collisions
type contextKey string

const (
	authContextKey       contextKey = "lc_auth_context"
	sdkCacheKey          contextKey = "lc_sdk_cache"
	requestIDKey         contextKey = "lc_request_id"
	metaToolFilterKey    contextKey = "lc_meta_tool_filter"
	permissionCacheKey   contextKey = "lc_permission_cache"
	permissionEnforceKey contextKey = "lc_permission_enforce"
)

// AuthMode represents the authentication mode
type AuthMode int

const (
	// AuthModeNormal is single-org mode with OID + API Key
	AuthModeNormal AuthMode = iota
	// AuthModeUIDKey is multi-org mode with UID + API Key
	AuthModeUIDKey
	// AuthModeUIDOAuth is multi-org mode with UID + OAuth (future)
	AuthModeUIDOAuth
)

func (m AuthMode) String() string {
	switch m {
	case AuthModeNormal:
		return "normal"
	case AuthModeUIDKey:
		return "uid_key"
	case AuthModeUIDOAuth:
		return "uid_oauth"
	default:
		return "unknown"
	}
}

// AuthContext holds authentication credentials for a request
// This is stored in context.Context to ensure request-scoped isolation
type AuthContext struct {
	Mode            AuthMode
	OID             string
	APIKey          string
	UID             string
	JWTToken        string
	FirebaseIDToken string // Firebase ID token for JWT regeneration in UID mode
	Environment     string
}

// Clone creates a deep copy of the AuthContext
func (a *AuthContext) Clone() *AuthContext {
	return &AuthContext{
		Mode:            a.Mode,
		OID:             a.OID,
		APIKey:          a.APIKey,
		UID:             a.UID,
		JWTToken:        a.JWTToken,
		FirebaseIDToken: a.FirebaseIDToken,
		Environment:     a.Environment,
	}
}

// HasCredentials returns true if the AuthContext has valid credentials configured
// This is used to determine if server-wide credentials are available
func (a *AuthContext) HasCredentials() bool {
	if a == nil {
		return false
	}
	switch a.Mode {
	case AuthModeNormal:
		return a.OID != "" && a.APIKey != ""
	case AuthModeUIDKey:
		return a.UID != "" && a.APIKey != ""
	case AuthModeUIDOAuth:
		return a.UID != "" && (a.JWTToken != "" || a.Environment != "")
	default:
		return false
	}
}

// CacheKey generates a unique cache key based on credentials
// CRITICAL: This prevents credential cross-contamination in the SDK cache
func (a *AuthContext) CacheKey() string {
	h := sha256.New()
	h.Write([]byte(a.Mode.String()))
	h.Write([]byte("|"))
	h.Write([]byte(a.OID))
	h.Write([]byte("|"))
	h.Write([]byte(a.APIKey))
	h.Write([]byte("|"))
	h.Write([]byte(a.UID))
	h.Write([]byte("|"))
	h.Write([]byte(a.JWTToken))
	h.Write([]byte("|"))
	h.Write([]byte(a.Environment))
	return hex.EncodeToString(h.Sum(nil))
}

// Validate checks if the AuthContext is valid
func (a *AuthContext) Validate() error {
	switch a.Mode {
	case AuthModeNormal:
		if a.OID == "" {
			return errors.New("OID is required for normal mode")
		}
		if a.APIKey == "" {
			return errors.New("API key is required for normal mode")
		}
	case AuthModeUIDKey:
		if a.UID == "" {
			return errors.New("UID is required for UID mode")
		}
		if a.APIKey == "" {
			return errors.New("API key is required for UID+Key mode")
		}
	case AuthModeUIDOAuth:
		if a.UID == "" {
			return errors.New("UID is required for UID mode")
		}
		if a.JWTToken == "" && a.Environment == "" {
			return errors.New("JWT token or environment is required for UID+OAuth mode")
		}
	default:
		return fmt.Errorf("unknown auth mode: %d", a.Mode)
	}
	return nil
}

// GetClientOptions creates LimaCharlie client options from the auth context
func (a *AuthContext) GetClientOptions() lc.ClientOptions {
	opts := lc.ClientOptions{
		OID:         a.OID,
		APIKey:      a.APIKey,
		UID:         a.UID,
		JWT:         a.JWTToken,
		Environment: a.Environment,
	}
	return opts
}

// WithAuthContext adds an AuthContext to the context
func WithAuthContext(ctx context.Context, auth *AuthContext) context.Context {
	return context.WithValue(ctx, authContextKey, auth)
}

// FromContext retrieves the AuthContext from the context
func FromContext(ctx context.Context) (*AuthContext, error) {
	auth, ok := ctx.Value(authContextKey).(*AuthContext)
	if !ok || auth == nil {
		return nil, errors.New("no authentication context found")
	}
	return auth, nil
}

// MustFromContext retrieves the AuthContext from the context and panics if not found
// This should only be used in handler code where the presence of auth is guaranteed
func MustFromContext(ctx context.Context) *AuthContext {
	auth, err := FromContext(ctx)
	if err != nil {
		panic("authentication context is required but not found: " + err.Error())
	}
	return auth
}

// WithOID creates a new context with the specified OID
// This is used for multi-org tools that accept an oid parameter
// In UID OAuth mode, this regenerates the JWT with the OID claim
func WithOID(ctx context.Context, oid string, logger *slog.Logger) (context.Context, error) {
	auth, err := FromContext(ctx)
	if err != nil {
		return ctx, err
	}

	// In normal mode, only allow the same OID (not really a switch)
	if auth.Mode == AuthModeNormal {
		if oid == auth.OID {
			return ctx, nil // Same OID, no switch needed
		}
		return ctx, errors.New("cannot switch OID in normal mode")
	}

	// Validate OID format before switching
	if err := ValidateOID(oid); err != nil {
		return ctx, fmt.Errorf("invalid OID: %w", err)
	}

	// Clone auth context and update OID
	newAuth := auth.Clone()
	newAuth.OID = oid

	// In UID OAuth mode with Firebase token, regenerate JWT with the OID claim
	// This ensures the JWT contains the proper oid claim for API authorization
	// For JWT passthrough mode (no Firebase token), just update the OID
	// The JWT already has permissions, we just need to set the org context
	if auth.Mode == AuthModeUIDOAuth && auth.FirebaseIDToken != "" {
		if logger == nil {
			logger = slog.Default()
		}

		// Exchange Firebase token for LimaCharlie JWT with OID
		limaCharlieJWT, err := ExchangeFirebaseTokenForJWT(auth.FirebaseIDToken, oid, logger)
		if err != nil {
			return ctx, fmt.Errorf("failed to generate JWT for OID %s: %w", oid, err)
		}

		// Update JWT with org-specific token
		newAuth.JWTToken = limaCharlieJWT

		logger.Debug("Regenerated JWT with OID for org switching",
			"oid", oid,
			"jwt_prefix", safePrefix(limaCharlieJWT, 20))
	} else if logger != nil {
		// JWT passthrough mode - just update OID without regenerating JWT
		logger.Debug("Using existing JWT with new OID (passthrough mode)",
			"oid", oid)
	}

	return WithAuthContext(ctx, newAuth), nil
}

// WithSDKCache adds an SDKCache to the context
// This uses a typed key to prevent context key collisions
func WithSDKCache(ctx context.Context, cache *SDKCache) context.Context {
	return context.WithValue(ctx, sdkCacheKey, cache)
}

// GetSDKCache retrieves the SDKCache from the context
// Returns error if cache is not found
func GetSDKCache(ctx context.Context) (*SDKCache, error) {
	cache, ok := ctx.Value(sdkCacheKey).(*SDKCache)
	if !ok || cache == nil {
		return nil, errors.New("SDK cache not found in context")
	}
	return cache, nil
}

// WithRequestID adds a request ID to the context for tracing
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// GetRequestID retrieves the request ID from the context
// Returns empty string if not found
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(requestIDKey).(string); ok {
		return requestID
	}
	return ""
}

// MetaToolFilter defines allow/deny lists for the lc_call_tool meta-tool
// When AllowList is non-empty, only those tools can be called (ALLOW takes precedence)
// When AllowList is empty and DenyList is non-empty, those tools cannot be called
type MetaToolFilter struct {
	AllowList []string // If non-empty, only these tools are allowed
	DenyList  []string // If AllowList is empty, these tools are denied
}

// WithMetaToolFilter adds a MetaToolFilter to the context
func WithMetaToolFilter(ctx context.Context, filter *MetaToolFilter) context.Context {
	return context.WithValue(ctx, metaToolFilterKey, filter)
}

// GetMetaToolFilter retrieves the MetaToolFilter from the context
// Returns nil if no filter is set
func GetMetaToolFilter(ctx context.Context) *MetaToolFilter {
	filter, _ := ctx.Value(metaToolFilterKey).(*MetaToolFilter)
	return filter
}

// IsToolAllowed checks if a tool is allowed by the filter
// Returns true if no filter is set or if the tool passes the filter
func IsToolAllowed(filter *MetaToolFilter, toolName string) bool {
	if filter == nil {
		return true // No filter, allow all
	}
	// ALLOW takes precedence - if AllowList is non-empty, tool must be in it
	if len(filter.AllowList) > 0 {
		for _, allowed := range filter.AllowList {
			if allowed == toolName {
				return true
			}
		}
		return false
	}
	// If no AllowList, check DenyList - tool must NOT be in it
	if len(filter.DenyList) > 0 {
		for _, denied := range filter.DenyList {
			if denied == toolName {
				return false
			}
		}
	}
	return true // Both empty or tool not in DenyList
}

// WithPermissionCache adds a PermissionCache to the context
func WithPermissionCache(ctx context.Context, cache *PermissionCache) context.Context {
	return context.WithValue(ctx, permissionCacheKey, cache)
}

// GetPermissionCache retrieves the PermissionCache from the context
// Returns nil if no cache is set (permission checking disabled)
func GetPermissionCache(ctx context.Context) *PermissionCache {
	cache, _ := ctx.Value(permissionCacheKey).(*PermissionCache)
	return cache
}

// WithPermissionEnforcement sets whether ai_agent.operate permission should be enforced
func WithPermissionEnforcement(ctx context.Context, enforce bool) context.Context {
	return context.WithValue(ctx, permissionEnforceKey, enforce)
}

// IsPermissionEnforcementEnabled checks if permission enforcement is enabled
// Returns true by default if not explicitly set
func IsPermissionEnforcementEnabled(ctx context.Context) bool {
	enforce, ok := ctx.Value(permissionEnforceKey).(bool)
	if !ok {
		return true // Default to enabled
	}
	return enforce
}
