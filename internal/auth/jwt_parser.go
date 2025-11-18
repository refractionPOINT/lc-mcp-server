package auth

import (
	"crypto/rsa"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// LimaCharlie API public key for JWT signature validation
// This is the same public key used by the LimaCharlie platform to sign JWTs
const apiPublicKeyPem = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAl54PWGrA2o9RPOf+0ruI
GTjKa5oz7wweJ2XZuhsUHJq1wPN8iCVkgmZEK32AJQnoQcXiWlsCHptI4vw4m1r9
1gNcovE9YrTgg/x2UKVF63SyOYZo4340Lvp7cKxnGq/pu0w0tle+PcKgEJzU/awn
Tg6TfqZf4ovpGBjq+dz8XDj9QvJXJyUkScv62EyvRkLRY4RCjJrYjls0oKDfmayU
xLRqIjcyyz3B+YiwfcFcZilnseiQyK3YMOJxzW0TU5QrlE0zTQ9MBUq0woqFHHaW
0nVuwKAU8RpqHikrK1xchCo3iVZgAhfdkj7fawwR94bTf3M1rwOejL2JDJQli6Dh
D4zEoG4aX6lZQMccmuiPTmi9bi0MvyvEC8Wm2dQjKzRE0t1nZGrJEyIV+u9awe4x
rnK6Ob147KhK/SoK6p44rn1mp93PYP2ABXydvIn9x7NWT2ljD0PanBLj/ycbpdXy
nOTo6DvwARBkYG7YnYXgsV7Bey3GjyjE9jQ7D+GwewrycR1ATbhQfj7s5tGaRplg
lvPfUnO3HzHaXg/bsq8JAzbQvZLTBW8SjqTIh+bRIzoas+fWCcWkqz7Rv1hj5S/i
mdqlJTq1Hjg7++v/VSu48hRf7V2N2Os621JntU9M0ALs8Wpn8F/9CR1La8Y0u/1B
gJDw5tgbRlQW9Q7oRT7Y5ZMCAwEAAQ==
-----END PUBLIC KEY-----`

// lcOrgClaims represents organization-level JWT claims
// This matches the structure from go-ironlegionprotocol/ilp/jwt.go
type lcOrgClaims struct {
	jwt.RegisteredClaims

	Ident       string   `json:"email"`
	OID         []string `json:"oid"`
	Permissions []string `json:"perms"`
	UID         string   `json:"uid"`
	KeyID       string   `json:"kid"`
	SourceIP    string   `json:"sip"`
}

// lcUserClaims represents user-level JWT claims
// This matches the structure from go-ironlegionprotocol/ilp/jwt.go
type lcUserClaims struct {
	jwt.RegisteredClaims

	Ident          string              `json:"email"`
	UID            string              `json:"uid"`
	OrgPermissions map[string][]string `json:"oid"`
	KeyID          string              `json:"kid"`
	SourceIP       string              `json:"sip"`
}

// LCClaims represents a unified view of LimaCharlie JWT claims
// This provides a common interface for both org and user tokens
type LCClaims struct {
	UID         string              // User ID (present in both org and user tokens)
	Ident       string              // Email or identifier
	OIDs        []string            // List of organization IDs
	IsUserToken bool                // True if this is a user token (multi-org)
	ExpiresAt   time.Time           // Token expiration time
	KeyID       string              // Key ID used to sign the token
	SourceIP    string              // Source IP that requested the token
	Permissions map[string][]string // Org ID -> permissions mapping
}

// Expected audience claim for LimaCharlie JWTs
// This ensures tokens are intended for the LimaCharlie control plane
const expectedAudience = "lce_control_plane"

var (
	apiPublicKey        *rsa.PublicKey
	loadApiKeyOnce      sync.Once
	errLoadingPublicKey error
)

// ParseAndValidateLimaCharlieJWT parses and validates a LimaCharlie JWT token
// It validates the signature using the LimaCharlie public key and checks expiration
// Returns unified claims that work for both org and user tokens
func ParseAndValidateLimaCharlieJWT(jwtString string) (*LCClaims, error) {
	// Load the public key once
	loadApiKeyOnce.Do(func() {
		var err error
		apiPublicKey, err = jwt.ParseRSAPublicKeyFromPEM([]byte(apiPublicKeyPem))
		if err != nil {
			apiPublicKey = nil
			errLoadingPublicKey = err
		}
	})

	if errLoadingPublicKey != nil {
		return nil, fmt.Errorf("failed to load API public key: %w", errLoadingPublicKey)
	}

	// Try parsing as org claims first (single org with permissions)
	token, err1 := jwt.ParseWithClaims(jwtString, &lcOrgClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return apiPublicKey, nil
	}, jwt.WithAudience(expectedAudience)) // Validate audience claim for security

	if err1 == nil && token.Valid {
		if claims, ok := token.Claims.(*lcOrgClaims); ok {
			// Check expiration
			if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
				return nil, fmt.Errorf("token has expired")
			}

			// Convert to unified claims
			permissions := make(map[string][]string)
			for _, oid := range claims.OID {
				permissions[oid] = claims.Permissions
			}

			return &LCClaims{
				UID:         claims.UID,
				Ident:       claims.Ident,
				OIDs:        claims.OID,
				IsUserToken: false,
				ExpiresAt:   claims.ExpiresAt.Time,
				KeyID:       claims.KeyID,
				SourceIP:    claims.SourceIP,
				Permissions: permissions,
			}, nil
		}
	}

	// Try parsing as user claims (multi-org with per-org permissions)
	token, err2 := jwt.ParseWithClaims(jwtString, &lcUserClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return apiPublicKey, nil
	}, jwt.WithAudience(expectedAudience)) // Validate audience claim for security

	if err2 == nil && token.Valid {
		if claims, ok := token.Claims.(*lcUserClaims); ok {
			// Check expiration
			if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
				return nil, fmt.Errorf("token has expired")
			}

			// Extract OID list from org permissions map
			oids := make([]string, 0, len(claims.OrgPermissions))
			for oid := range claims.OrgPermissions {
				oids = append(oids, oid)
			}

			return &LCClaims{
				UID:         claims.UID,
				Ident:       claims.Ident,
				OIDs:        oids,
				IsUserToken: true,
				ExpiresAt:   claims.ExpiresAt.Time,
				KeyID:       claims.KeyID,
				SourceIP:    claims.SourceIP,
				Permissions: claims.OrgPermissions,
			}, nil
		}
	}

	// Both parsing attempts failed
	return nil, fmt.Errorf("failed to parse JWT as org or user token: org_error=%v, user_error=%v", err1, err2)
}

// IsJWTFormat checks if a token string looks like a JWT (3 parts separated by dots)
func IsJWTFormat(token string) bool {
	if token == "" {
		return false
	}

	// JWT format: header.payload.signature
	dotCount := 0
	for _, c := range token {
		if c == '.' {
			dotCount++
		}
	}

	return dotCount == 2
}
