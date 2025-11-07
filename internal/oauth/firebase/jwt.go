package firebase

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ParseIDTokenClaims extracts claims from Firebase ID token WITHOUT full verification
// Note: This is for extracting the 'sub' claim only for defense-in-depth validation.
// Full token verification happens when we exchange the token with Firebase/LimaCharlie.
func ParseIDTokenClaims(idToken string) (map[string]interface{}, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT claims: %w", err)
	}

	return claims, nil
}

// ExtractUIDFromIDToken extracts the 'sub' claim (UID) from Firebase ID token
// The 'sub' claim in Firebase tokens contains the user's UID
func ExtractUIDFromIDToken(idToken string) (string, error) {
	if idToken == "" {
		return "", fmt.Errorf("ID token is empty")
	}

	claims, err := ParseIDTokenClaims(idToken)
	if err != nil {
		return "", err
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return "", fmt.Errorf("sub claim not found or invalid in ID token")
	}

	return sub, nil
}
