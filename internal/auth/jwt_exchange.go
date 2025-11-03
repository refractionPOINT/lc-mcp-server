package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// JWTExchangeURL is the LimaCharlie JWT generation endpoint
	JWTExchangeURL = "https://jwt.limacharlie.io"

	// DefaultJWTExpiry is the default expiration time for generated JWTs
	DefaultJWTExpiry = 30 * time.Minute
)

// jwtExchangeResponse represents the response from the JWT exchange endpoint
type jwtExchangeResponse struct {
	JWT   string `json:"jwt"`
	Error string `json:"error,omitempty"`
}

// ExchangeFirebaseTokenForJWT exchanges a Firebase ID token for a LimaCharlie JWT
// This matches the Python SDK behavior in Manager.py _refreshJWT method (lines 200-212)
func ExchangeFirebaseTokenForJWT(firebaseIDToken, oid string, logger *slog.Logger) (string, error) {
	if firebaseIDToken == "" {
		return "", errors.New("Firebase ID token cannot be empty")
	}

	if logger == nil {
		logger = slog.Default()
	}

	// Prepare form data matching Python implementation
	formData := url.Values{}
	formData.Set("fb_auth", firebaseIDToken)

	if oid != "" && oid != "-" {
		formData.Set("oid", oid)
	}

	// Set expiry in seconds
	formData.Set("expiry", fmt.Sprintf("%d", int64(DefaultJWTExpiry.Seconds())))

	// Create HTTP request
	req, err := http.NewRequest(http.MethodPost, JWTExchangeURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create JWT exchange request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "limacharlie-mcp-server")

	// Execute request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	logger.Debug("Exchanging Firebase ID token for LimaCharlie JWT",
		"oid", oid,
		"token_prefix", safePrefix(firebaseIDToken, 20))

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("JWT exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read JWT exchange response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		logger.Error("JWT exchange failed",
			"status", resp.StatusCode,
			"body", string(body))

		// Try to parse error message
		var errResp jwtExchangeResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return "", fmt.Errorf("JWT exchange failed: %s", errResp.Error)
		}

		return "", fmt.Errorf("JWT exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var jwtResp jwtExchangeResponse
	if err := json.Unmarshal(body, &jwtResp); err != nil {
		return "", fmt.Errorf("failed to parse JWT exchange response: %w", err)
	}

	if jwtResp.JWT == "" {
		return "", errors.New("JWT exchange returned empty token")
	}

	logger.Info("Successfully exchanged Firebase token for LimaCharlie JWT",
		"oid", oid,
		"jwt_prefix", safePrefix(jwtResp.JWT, 20))

	return jwtResp.JWT, nil
}

// safePrefix returns a safe prefix of a string for logging
func safePrefix(s string, length int) string {
	if len(s) <= length {
		return s[:len(s)/2] + "..."
	}
	return s[:length] + "..."
}
