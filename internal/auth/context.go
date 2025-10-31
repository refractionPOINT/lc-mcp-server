package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// contextKey is an unexported type for context keys to prevent collisions
type contextKey string

const (
	authContextKey contextKey = "lc_auth_context"
	sdkCacheKey    contextKey = "lc_sdk_cache"
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
	Mode        AuthMode
	OID         string
	APIKey      string
	UID         string
	JWTToken    string
	Environment string
}

// Clone creates a deep copy of the AuthContext
func (a *AuthContext) Clone() *AuthContext {
	return &AuthContext{
		Mode:        a.Mode,
		OID:         a.OID,
		APIKey:      a.APIKey,
		UID:         a.UID,
		JWTToken:    a.JWTToken,
		Environment: a.Environment,
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
func WithOID(ctx context.Context, oid string) (context.Context, error) {
	auth, err := FromContext(ctx)
	if err != nil {
		return ctx, err
	}

	// Can only switch OID in UID mode
	if auth.Mode == AuthModeNormal {
		return ctx, errors.New("cannot switch OID in normal mode")
	}

	// Validate OID format before switching
	if err := ValidateOID(oid); err != nil {
		return ctx, fmt.Errorf("invalid OID: %w", err)
	}

	// Clone auth context and update OID
	newAuth := auth.Clone()
	newAuth.OID = oid

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
