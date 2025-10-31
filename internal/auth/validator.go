package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrInvalidUID is returned when a UID fails validation
	ErrInvalidUID = errors.New("invalid UID format")

	// ErrSuspiciousUID is returned when a UID looks like a token or secret
	ErrSuspiciousUID = errors.New("UID appears to be a token or secret")

	// Regular expressions for detecting suspicious patterns
	jwtPattern    = regexp.MustCompile(`^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$`)
	hexPattern    = regexp.MustCompile(`^[0-9a-fA-F]{32,}$`)
	base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]{32,}={0,2}$`)
	uidPattern    = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	emailPattern  = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
)

// ValidateUID validates a UID to prevent security issues
// This prevents users from accidentally passing tokens or API keys as UIDs
func ValidateUID(uid string) error {
	if uid == "" {
		return ErrInvalidUID
	}

	// Check length - UIDs should be reasonable length
	if len(uid) < 3 {
		return errors.New("UID too short (minimum 3 characters)")
	}

	if len(uid) > 128 {
		return errors.New("UID too long (maximum 128 characters)")
	}

	// Check if it looks like a JWT (three base64 parts separated by dots)
	if jwtPattern.MatchString(uid) {
		return ErrSuspiciousUID
	}

	// Check if it's a long hex string (might be a token)
	if hexPattern.MatchString(uid) {
		return ErrSuspiciousUID
	}

	// Check if it's a long base64 string (might be a token)
	if base64Pattern.MatchString(uid) {
		_, err := base64.StdEncoding.DecodeString(uid)
		if err == nil {
			// It's valid base64 and long enough to be suspicious
			return ErrSuspiciousUID
		}
	}

	// Email addresses are valid UIDs - check this before character validation
	if emailPattern.MatchString(uid) {
		return nil
	}

	// Check if it contains only allowed characters
	if !uidPattern.MatchString(uid) {
		return errors.New("UID contains invalid characters (allowed: a-z, A-Z, 0-9, ., -, _)")
	}

	return nil
}

// ValidateOID validates an organization ID
func ValidateOID(oid string) error {
	if oid == "" {
		return errors.New("OID cannot be empty")
	}

	// OIDs should be reasonable length
	if len(oid) > 128 {
		return errors.New("OID too long (maximum 128 characters)")
	}

	// OIDs typically contain alphanumeric and hyphens
	// Allow more flexibility than UID since these are system-generated
	if !regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(oid) {
		return errors.New("OID contains invalid characters")
	}

	return nil
}

// ValidateSID validates a sensor ID (must be a valid UUID)
func ValidateSID(sid string) error {
	if sid == "" {
		return errors.New("SID cannot be empty")
	}

	// UUID format: 8-4-4-4-12 hex digits
	// Example: 550e8400-e29b-41d4-a716-446655440000
	uuidPattern := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

	if !uuidPattern.MatchString(sid) {
		return errors.New("SID must be a valid UUID format (8-4-4-4-12 hex digits)")
	}

	return nil
}

// ValidateAPIKey performs basic validation on an API key
// NOTE: We can't validate the format strictly as the actual format may vary
func ValidateAPIKey(apiKey string) error {
	if apiKey == "" {
		return errors.New("API key cannot be empty")
	}

	if len(apiKey) < 16 {
		return errors.New("API key too short")
	}

	if len(apiKey) > 512 {
		return errors.New("API key too long")
	}

	// API keys should not contain whitespace
	if strings.ContainsAny(apiKey, " \t\n\r") {
		return errors.New("API key contains whitespace")
	}

	return nil
}

// JWTValidationConfig holds JWT validation configuration
type JWTValidationConfig struct {
	// ExpectedIssuer is the expected "iss" claim value (empty means don't validate)
	ExpectedIssuer string
	// ExpectedAudience is the expected "aud" claim value (empty means don't validate)
	ExpectedAudience string
	// SigningKey is used for HMAC signature validation (optional)
	SigningKey []byte
	// PublicKey is used for RSA/ECDSA signature validation (optional)
	PublicKey *rsa.PublicKey
	// SkipSignatureValidation skips signature check (UNSAFE - only for testing)
	SkipSignatureValidation bool
	// ClockSkew allows for some time drift (default: 5 minutes)
	ClockSkew time.Duration
}

// DefaultJWTValidationConfig returns a default configuration loaded from environment
func DefaultJWTValidationConfig() *JWTValidationConfig {
	cfg := &JWTValidationConfig{
		ExpectedIssuer:          os.Getenv("LC_JWT_ISSUER"),
		ExpectedAudience:        os.Getenv("LC_JWT_AUDIENCE"),
		SkipSignatureValidation: os.Getenv("LC_JWT_SKIP_SIGNATURE") == "true",
		ClockSkew:               5 * time.Minute,
	}

	// Load HMAC signing key if provided
	if signingKey := os.Getenv("LC_JWT_SIGNING_KEY"); signingKey != "" {
		cfg.SigningKey = []byte(signingKey)
	}

	// Load RSA public key if provided
	if publicKeyPEM := os.Getenv("LC_JWT_PUBLIC_KEY"); publicKeyPEM != "" {
		if pubKey, err := parseRSAPublicKey(publicKeyPEM); err == nil {
			cfg.PublicKey = pubKey
		}
	}

	// Load public key from file if path provided
	if publicKeyPath := os.Getenv("LC_JWT_PUBLIC_KEY_FILE"); publicKeyPath != "" {
		if pemData, err := os.ReadFile(publicKeyPath); err == nil {
			if pubKey, err := parseRSAPublicKey(string(pemData)); err == nil {
				cfg.PublicKey = pubKey
			}
		}
	}

	return cfg
}

// parseRSAPublicKey parses an RSA public key from PEM format
func parseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPub, nil
}

// ValidateJWT performs comprehensive JWT validation including signature, expiration, and claims
func ValidateJWT(jwtString string) error {
	return ValidateJWTWithConfig(jwtString, DefaultJWTValidationConfig())
}

// ValidateJWTWithConfig validates a JWT with specific configuration
func ValidateJWTWithConfig(jwtString string, cfg *JWTValidationConfig) error {
	if jwtString == "" {
		return errors.New("JWT cannot be empty")
	}

	// Basic format check
	parts := strings.Split(jwtString, ".")
	if len(parts) != 3 {
		return errors.New("JWT must have three parts (header.payload.signature)")
	}

	// Parse and validate JWT
	token, err := jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		// If signature validation is skipped (UNSAFE), return nil key
		if cfg.SkipSignatureValidation {
			return nil, nil
		}

		// Determine signing method and return appropriate key
		switch token.Method.(type) {
		case *jwt.SigningMethodHMAC:
			if cfg.SigningKey == nil {
				return nil, errors.New("HMAC signing key not configured")
			}
			return cfg.SigningKey, nil
		case *jwt.SigningMethodRSA:
			if cfg.PublicKey == nil {
				return nil, errors.New("RSA public key not configured")
			}
			return cfg.PublicKey, nil
		case *jwt.SigningMethodECDSA:
			return nil, errors.New("ECDSA not yet supported (use RSA or HMAC)")
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	})

	// Handle parse errors (including signature validation)
	if err != nil && !cfg.SkipSignatureValidation {
		return fmt.Errorf("JWT validation failed: %w", err)
	}

	// For skipped signature validation, we still need to parse claims
	if cfg.SkipSignatureValidation && token == nil {
		// Parse without validation
		token, _, err = jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(jwtString, jwt.MapClaims{})
		if err != nil {
			return fmt.Errorf("failed to parse JWT: %w", err)
		}
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("invalid JWT claims")
	}

	// Validate expiration (exp claim)
	if exp, ok := claims["exp"].(float64); ok {
		expiryTime := time.Unix(int64(exp), 0)
		if time.Now().After(expiryTime.Add(cfg.ClockSkew)) {
			return fmt.Errorf("JWT expired at %s", expiryTime.Format(time.RFC3339))
		}
	} else {
		return errors.New("JWT missing exp (expiration) claim")
	}

	// Validate not-before time (nbf claim)
	if nbf, ok := claims["nbf"].(float64); ok {
		notBeforeTime := time.Unix(int64(nbf), 0)
		if time.Now().Before(notBeforeTime.Add(-cfg.ClockSkew)) {
			return fmt.Errorf("JWT not yet valid (not before: %s)", notBeforeTime.Format(time.RFC3339))
		}
	}

	// Validate issued-at time (iat claim) - should not be in future
	if iat, ok := claims["iat"].(float64); ok {
		issuedAtTime := time.Unix(int64(iat), 0)
		if time.Now().Before(issuedAtTime.Add(-cfg.ClockSkew)) {
			return errors.New("JWT issued in the future")
		}
	}

	// Validate issuer (iss claim)
	if cfg.ExpectedIssuer != "" {
		iss, ok := claims["iss"].(string)
		if !ok {
			return errors.New("JWT missing iss (issuer) claim")
		}
		if iss != cfg.ExpectedIssuer {
			return fmt.Errorf("JWT issuer mismatch: expected %s, got %s", cfg.ExpectedIssuer, iss)
		}
	}

	// Validate audience (aud claim)
	if cfg.ExpectedAudience != "" {
		// Audience can be string or array of strings
		switch aud := claims["aud"].(type) {
		case string:
			if aud != cfg.ExpectedAudience {
				return fmt.Errorf("JWT audience mismatch: expected %s, got %s", cfg.ExpectedAudience, aud)
			}
		case []interface{}:
			found := false
			for _, a := range aud {
				if audStr, ok := a.(string); ok && audStr == cfg.ExpectedAudience {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("JWT audience does not include expected value: %s", cfg.ExpectedAudience)
			}
		default:
			return errors.New("JWT has invalid audience claim format")
		}
	}

	// All validation passed
	return nil
}

// ParseJWTClaims extracts claims from a JWT without full validation (for cache TTL purposes)
// WARNING: This should only be used after ValidateJWT has been called
func ParseJWTClaims(jwtString string) (jwt.MapClaims, error) {
	token, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(jwtString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid JWT claims")
	}

	return claims, nil
}

// GetJWTExpirationTime extracts the expiration time from a JWT
func GetJWTExpirationTime(jwtString string) (time.Time, error) {
	claims, err := ParseJWTClaims(jwtString)
	if err != nil {
		return time.Time{}, err
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}, errors.New("JWT missing exp claim")
	}

	return time.Unix(int64(exp), 0), nil
}

// SanitizeForLog sanitizes a string for logging by truncating and masking
// This prevents accidental logging of secrets
func SanitizeForLog(s string, showChars int) string {
	if s == "" {
		return "<empty>"
	}

	if len(s) <= showChars {
		return "<" + strings.Repeat("*", len(s)) + ">"
	}

	return s[:showChars] + "..." + "<" + strings.Repeat("*", len(s)-showChars) + ">"
}
