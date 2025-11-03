package firebase

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"log/slog"
)

const (
	// Firebase API endpoints
	identityToolkitBase = "https://identitytoolkit.googleapis.com/v1"
	secureTokenBase     = "https://securetoken.googleapis.com/v1"

	createAuthURIEndpoint = identityToolkitBase + "/accounts:createAuthUri"
	signInWithIdpEndpoint = identityToolkitBase + "/accounts:signInWithIdp"
	finalizeMFAEndpoint   = "https://identitytoolkit.googleapis.com/v2/accounts/mfaSignIn:finalize"
	refreshTokenEndpoint  = secureTokenBase + "/token"

	// Default timeout for HTTP requests
	defaultTimeout = 10 * time.Second
)

// Client handles Firebase Authentication API interactions
type Client struct {
	apiKey     string
	httpClient *http.Client
	logger     *slog.Logger
}

// NewClient creates a new Firebase authentication client
func NewClient(logger *slog.Logger) (*Client, error) {
	// LimaCharlie's Firebase Web API key (public token)
	// NOTE: Firebase Web API keys are designed to be public and exposed in client apps
	// Security is enforced through Firebase Security Rules, not API key secrecy
	const apiKey = "AIzaSyB5VyO6qS-XlnVD3zOIuEVNBD5JFn22_1w"

	client := &Client{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
		logger: logger,
	}

	logger.Info("Firebase client initialized")

	return client, nil
}

// CreateAuthURI gets OAuth authorization URI from Firebase
// Firebase manages the OAuth flow with the provider (Google, Microsoft, etc.)
func (c *Client) CreateAuthURI(ctx context.Context, providerID, redirectURI string, scopes []string) (sessionID, authURI string, err error) {
	scopeStr := "openid email profile"
	if len(scopes) > 0 {
		scopeStr = ""
		for i, scope := range scopes {
			if i > 0 {
				scopeStr += " "
			}
			scopeStr += scope
		}
	}

	req := CreateAuthURIRequest{
		ProviderID:   providerID,
		ContinueURI:  redirectURI,
		AuthFlowType: "CODE_FLOW",
		OAuthScope:   scopeStr,
	}

	var resp CreateAuthURIResponse
	if err := c.doRequest(ctx, "POST", createAuthURIEndpoint, req, &resp); err != nil {
		return "", "", fmt.Errorf("createAuthUri failed: %w", err)
	}

	c.logger.Debug("Created Firebase auth URI")

	return resp.SessionID, resp.AuthURI, nil
}

// SignInWithIdp exchanges provider OAuth response for Firebase tokens
func (c *Client) SignInWithIdp(ctx context.Context, requestURI, queryString, sessionID, providerID string) (*SignInWithIdpResponse, error) {
	req := SignInWithIdpRequest{
		RequestURI:          requestURI,
		PostBody:            queryString,
		SessionID:           sessionID,
		ReturnSecureToken:   true,
		ReturnIdpCredential: true,
	}

	var resp SignInWithIdpResponse
	if err := c.doRequest(ctx, "POST", signInWithIdpEndpoint, req, &resp); err != nil {
		return nil, fmt.Errorf("signInWithIdp failed: %w", err)
	}

	// Check if MFA is required
	if resp.MFAPendingCredential != "" && len(resp.MFAInfo) > 0 {
		// Extract first MFA method (usually TOTP)
		mfaMethod := resp.MFAInfo[0]

		c.logger.Info("MFA required")

		return nil, &MFARequiredError{
			MFAPendingCredential: resp.MFAPendingCredential,
			MFAEnrollmentID:      mfaMethod.MFAEnrollmentID,
			DisplayName:          mfaMethod.DisplayName,
			LocalID:              resp.LocalID,
			Email:                resp.Email,
			PendingToken:         resp.PendingToken,
		}
	}

	// Check if tokens are missing
	if resp.IDToken == "" || resp.RefreshToken == "" {
		if resp.NeedConfirmation {
			return nil, fmt.Errorf("account linking required - please use an existing account")
		}
		return nil, fmt.Errorf("missing tokens in Firebase response")
	}

	c.logger.Info("Successfully signed in via Firebase")

	return &resp, nil
}

// RefreshIDToken refreshes an expired Firebase ID token
func (c *Client) RefreshIDToken(ctx context.Context, refreshToken string) (idToken string, expiresAt int64, err error) {
	// Build form data for token refresh
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)

	endpoint := refreshTokenEndpoint + "?key=" + c.apiKey

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("failed to read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	var refreshResp RefreshTokenResponse
	if err := json.Unmarshal(body, &refreshResp); err != nil {
		return "", 0, fmt.Errorf("failed to parse refresh response: %w", err)
	}

	if refreshResp.IDToken == "" {
		return "", 0, fmt.Errorf("missing id_token in refresh response")
	}

	// Calculate expiration
	expiresIn, _ := strconv.Atoi(refreshResp.ExpiresIn)
	if expiresIn == 0 {
		expiresIn = 3600 // Default to 1 hour
	}
	expiresAt = time.Now().Unix() + int64(expiresIn) - 60 // 60 second buffer

	c.logger.Debug("Successfully refreshed Firebase ID token")

	return refreshResp.IDToken, expiresAt, nil
}

// FinalizeMFASignIn completes MFA sign-in with TOTP verification code
func (c *Client) FinalizeMFASignIn(ctx context.Context, mfaPendingCredential, mfaEnrollmentID, verificationCode string) (*FinalizeMFAResponse, error) {
	req := FinalizeMFARequest{
		MFAPendingCredential: mfaPendingCredential,
		MFAEnrollmentID:      mfaEnrollmentID,
		TOTPVerificationInfo: &TOTPVerificationInfo{
			VerificationCode: verificationCode,
		},
	}

	var resp FinalizeMFAResponse
	if err := c.doRequest(ctx, "POST", finalizeMFAEndpoint, req, &resp); err != nil {
		// Check for invalid code error
		if fbErr, ok := err.(*FirebaseError); ok {
			if fbErr.ErrorDetails.Message == "INVALID_MFA_PENDING_CREDENTIAL" || fbErr.ErrorDetails.Message == "INVALID_CODE" {
				return nil, fmt.Errorf("invalid verification code")
			}
		}
		return nil, fmt.Errorf("MFA finalization failed: %w", err)
	}

	if resp.IDToken == "" || resp.RefreshToken == "" {
		return nil, fmt.Errorf("missing tokens in MFA finalization response")
	}

	c.logger.Info("Successfully completed MFA sign-in")

	return &resp, nil
}

// ValidateProviderCallback validates and extracts query string from provider callback
func (c *Client) ValidateProviderCallback(callbackPath string) (string, error) {
	if callbackPath == "" {
		return "", fmt.Errorf("empty callback path")
	}

	// Parse URL to get query string
	var parsedURL *url.URL
	var err error

	if callbackPath[0] == '/' {
		// Relative path
		parsedURL, err = url.Parse("http://localhost" + callbackPath)
	} else {
		parsedURL, err = url.Parse(callbackPath)
	}

	if err != nil {
		return "", fmt.Errorf("invalid callback URL: %w", err)
	}

	queryString := parsedURL.RawQuery
	if queryString == "" {
		queryString = parsedURL.Fragment
	}

	if queryString == "" {
		return "", fmt.Errorf("no query parameters in callback")
	}

	// Check for OAuth errors
	params, err := url.ParseQuery(queryString)
	if err != nil {
		return "", fmt.Errorf("failed to parse query string: %w", err)
	}

	if errCode := params.Get("error"); errCode != "" {
		errDesc := params.Get("error_description")
		return "", fmt.Errorf("OAuth error: %s - %s", errCode, errDesc)
	}

	// c.logger.WithField("params", len(params)).Debug("Validated provider callback")

	return queryString, nil
}

// doRequest performs an HTTP request to Firebase API
func (c *Client) doRequest(ctx context.Context, method, endpoint string, reqBody, respBody interface{}) error {
	// Add API key to endpoint
	endpointWithKey := endpoint + "?key=" + c.apiKey

	// Marshal request body
	var body io.Reader
	if reqBody != nil {
		jsonData, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		body = bytes.NewBuffer(jsonData)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, endpointWithKey, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		var fbErr FirebaseError
		if json.Unmarshal(respData, &fbErr) == nil && fbErr.ErrorDetails.Message != "" {
			c.logger.Error("Firebase API error")
			return &fbErr
		}
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respData))
	}

	// Parse response
	if respBody != nil {
		if err := json.Unmarshal(respData, respBody); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}

	return nil
}
