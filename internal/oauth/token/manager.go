package token

import (
	"context"
	"fmt"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/firebase"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"log/slog"
)

// Manager manages OAuth token validation and lifecycle
type Manager struct {
	stateManager   *state.Manager
	firebaseClient *firebase.Client
	logger         *slog.Logger
}

// ValidationResult represents the result of token validation
type ValidationResult struct {
	Valid                bool
	UID                  string
	FirebaseIDToken      string
	FirebaseRefreshToken string
	LimaCharlieJWT       string // JWT exchanged from Firebase token for LimaCharlie API
	Scope                string
	Error                string
	Refreshed            bool
}

// TokenResponse represents an OAuth 2.0 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// IntrospectionResponse represents an OAuth 2.0 token introspection response (RFC 7662)
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"` // Firebase UID
}

// NewManager creates a new OAuth token manager
func NewManager(stateManager *state.Manager, firebaseClient *firebase.Client, logger *slog.Logger) *Manager {
	return &Manager{
		stateManager:   stateManager,
		firebaseClient: firebaseClient,
		logger:         logger,
	}
}

// ValidateAccessToken validates an MCP access token and optionally refreshes Firebase tokens
func (m *Manager) ValidateAccessToken(ctx context.Context, accessToken string, autoRefresh bool) (*ValidationResult, error) {
	// Look up token in Redis
	tokenData, err := m.stateManager.GetAccessTokenData(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get token data: %w", err)
	}

	if tokenData == nil {
		m.logger.Debug("Access token not found or expired", "token", accessToken[:min(10, len(accessToken))]+"...")
		return &ValidationResult{
			Valid: false,
			Error: "invalid or expired access token",
		}, nil
	}

	// Check if Firebase token needs refresh
	firebaseExpiresIn := tokenData.FirebaseExpiresAt - time.Now().Unix()
	needsRefresh := firebaseExpiresIn < 300 // Refresh if < 5 minutes remaining

	if needsRefresh && autoRefresh && tokenData.FirebaseRefreshToken != "" {
		m.logger.Info("Firebase token expiring soon, refreshing...",
			"token", accessToken[:10]+"...",
			"expires_in", firebaseExpiresIn)

		// Refresh Firebase token
		newIDToken, newExpiresAt, err := m.firebaseClient.RefreshIDToken(ctx, tokenData.FirebaseRefreshToken)
		if err != nil {
			m.logger.Error("Failed to refresh Firebase ID token", "error", err, "uid", tokenData.UID)
			// Continue with existing token if refresh fails (might still be valid for a short time)
		} else {
			// Update token data in Redis
			if err := m.stateManager.UpdateAccessTokenFirebaseTokens(ctx, accessToken, newIDToken, newExpiresAt); err != nil {
				m.logger.Error("Failed to update access token with refreshed Firebase tokens", "error", err, "uid", tokenData.UID)
			} else {
				m.logger.Info("Successfully refreshed Firebase ID token", "uid", tokenData.UID, "expires_at", newExpiresAt)
				tokenData.FirebaseIDToken = newIDToken
				tokenData.FirebaseExpiresAt = newExpiresAt

				// Exchange Firebase token for LimaCharlie JWT
				// This matches Python SDK behavior in Manager.py _refreshJWT (lines 200-212)
				limaCharlieJWT, err := auth.ExchangeFirebaseTokenForJWT(newIDToken, "-", m.logger)
				if err != nil {
					m.logger.Error("Failed to exchange Firebase token for LimaCharlie JWT", "error", err, "uid", tokenData.UID)
					return &ValidationResult{
						Valid: false,
						Error: fmt.Sprintf("JWT exchange failed: %v", err),
					}, nil
				}

				return &ValidationResult{
					Valid:                true,
					UID:                  tokenData.UID,
					FirebaseIDToken:      newIDToken,
					FirebaseRefreshToken: tokenData.FirebaseRefreshToken,
					LimaCharlieJWT:       limaCharlieJWT,
					Scope:                tokenData.Scope,
					Refreshed:            true,
				}, nil
			}
		}
	}

	// Exchange Firebase token for LimaCharlie JWT
	// This matches Python SDK behavior in Manager.py _refreshJWT (lines 200-212)
	limaCharlieJWT, err := auth.ExchangeFirebaseTokenForJWT(tokenData.FirebaseIDToken, "-", m.logger)
	if err != nil {
		m.logger.Error("Failed to exchange Firebase token for LimaCharlie JWT", "error", err, "uid", tokenData.UID)
		return &ValidationResult{
			Valid: false,
			Error: fmt.Sprintf("JWT exchange failed: %v", err),
		}, nil
	}

	// Return validation result
	return &ValidationResult{
		Valid:                true,
		UID:                  tokenData.UID,
		FirebaseIDToken:      tokenData.FirebaseIDToken,
		FirebaseRefreshToken: tokenData.FirebaseRefreshToken,
		LimaCharlieJWT:       limaCharlieJWT,
		Scope:                tokenData.Scope,
		Refreshed:            false,
	}, nil
}

// RefreshAccessToken issues a new access token using a refresh token
// SECURITY: Implements refresh token rotation to detect token theft
func (m *Manager) RefreshAccessToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	// Look up refresh token
	refreshData, err := m.stateManager.GetRefreshTokenData(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token data: %w", err)
	}

	if refreshData == nil {
		m.logger.Warn("Refresh token not found or already used")
		return nil, fmt.Errorf("invalid or expired refresh token")
	}

	uid := refreshData.UID
	firebaseRefreshToken := refreshData.FirebaseRefreshToken
	scope := refreshData.Scope
	oldAccessToken := refreshData.AccessToken

	// Refresh Firebase token first
	newFirebaseIDToken, newFirebaseExpiresAt, err := m.firebaseClient.RefreshIDToken(ctx, firebaseRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh Firebase token: %w", err)
	}

	// Generate new MCP access token
	newAccessToken, err := m.stateManager.GenerateAccessToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// SECURITY: Generate NEW refresh token (rotation for theft detection)
	newRefreshToken, err := m.stateManager.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store new access token with refreshed Firebase tokens
	accessTokenData := state.NewAccessTokenData(
		newAccessToken,
		uid,
		newFirebaseIDToken,
		firebaseRefreshToken,
		newFirebaseExpiresAt,
		scope,
		state.TokenTTL,
	)
	if err := m.stateManager.StoreAccessToken(ctx, accessTokenData); err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	// SECURITY: Store new refresh token mapping
	refreshTokenData := state.NewRefreshTokenData(
		newRefreshToken,
		newAccessToken,
		uid,
		firebaseRefreshToken,
		scope,
	)
	if err := m.stateManager.StoreRefreshToken(ctx, refreshTokenData); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// SECURITY: Revoke old refresh token (critical for rotation)
	if err := m.stateManager.RevokeRefreshToken(ctx, refreshToken); err != nil {
		m.logger.Warn("Failed to revoke old refresh token during rotation", "error", err, "uid", uid)
	}

	// Revoke old access token (optional - could keep for grace period)
	if oldAccessToken != "" {
		if err := m.stateManager.RevokeAccessToken(ctx, oldAccessToken); err != nil {
			m.logger.Warn("Failed to revoke old access token during rotation", "error", err, "uid", uid)
		}
	}

	m.logger.Info("Issued new tokens via refresh",
		"uid", uid,
		"rotated", true)

	return &TokenResponse{
		AccessToken:  newAccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    state.TokenTTL,
		RefreshToken: newRefreshToken, // NEW TOKEN (rotated for security)
		Scope:        scope,
	}, nil
}

// RevokeToken revokes an access or refresh token
func (m *Manager) RevokeToken(ctx context.Context, token string, tokenTypeHint string) error {
	revoked := false

	// Try to revoke as access token
	if tokenTypeHint != "refresh_token" {
		if err := m.stateManager.RevokeAccessToken(ctx, token); err == nil {
			m.logger.Info("Revoked access token", "token_prefix", token[:min(10, len(token))]+"...")
			revoked = true
		}
	}

	// Try to revoke as refresh token
	if tokenTypeHint != "access_token" {
		if err := m.stateManager.RevokeRefreshToken(ctx, token); err == nil {
			m.logger.Info("Revoked refresh token", "token_prefix", token[:min(10, len(token))]+"...")
			revoked = true
		}
	}

	if !revoked {
		m.logger.Warn("Token not found for revocation (may already be revoked)", "token_prefix", token[:min(10, len(token))]+"...")
	}

	return nil // Always return success per OAuth 2.0 spec
}

// IntrospectToken gets token metadata (OAuth 2.0 Token Introspection - RFC 7662)
func (m *Manager) IntrospectToken(ctx context.Context, token string) (*IntrospectionResponse, error) {
	tokenData, err := m.stateManager.GetAccessTokenData(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get token data: %w", err)
	}

	if tokenData == nil {
		return &IntrospectionResponse{
			Active: false,
		}, nil
	}

	// Check expiration
	isActive := tokenData.ExpiresAt > time.Now().Unix()

	return &IntrospectionResponse{
		Active:    isActive,
		Scope:     tokenData.Scope,
		ClientID:  "mcp", // We don't track client_id per token currently
		TokenType: "Bearer",
		Exp:       tokenData.ExpiresAt,
		Iat:       tokenData.CreatedAt,
		Sub:       tokenData.UID, // Firebase UID as subject
	}, nil
}

// GetTokenInfoForRequest gets token information for authenticating LimaCharlie API requests
// This is the main method used by request middleware
func (m *Manager) GetTokenInfoForRequest(ctx context.Context, accessToken string) (map[string]interface{}, error) {
	validation, err := m.ValidateAccessToken(ctx, accessToken, true)
	if err != nil {
		return nil, err
	}

	if !validation.Valid {
		return nil, fmt.Errorf("%s", validation.Error)
	}

	return map[string]interface{}{
		"uid":                    validation.UID,
		"firebase_id_token":      validation.FirebaseIDToken,
		"firebase_refresh_token": validation.FirebaseRefreshToken,
		"mode":                   "oauth", // Always OAuth mode for MCP tokens
		"scope":                  validation.Scope,
		"refreshed":              validation.Refreshed,
	}, nil
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CreateTokenResponse creates OAuth token response with new MCP tokens
// Called after successful authorization to issue tokens
func (m *Manager) CreateTokenResponse(ctx context.Context, uid, firebaseIDToken, firebaseRefreshToken string, firebaseExpiresAt int64, scope string) (*TokenResponse, error) {
	// Generate MCP tokens
	accessToken, err := m.stateManager.GenerateAccessToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := m.stateManager.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store access token
	accessTokenData := state.NewAccessTokenData(
		accessToken,
		uid,
		firebaseIDToken,
		firebaseRefreshToken,
		firebaseExpiresAt,
		scope,
		state.TokenTTL,
	)
	if err := m.stateManager.StoreAccessToken(ctx, accessTokenData); err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	// Store refresh token
	refreshTokenData := state.NewRefreshTokenData(
		refreshToken,
		accessToken,
		uid,
		firebaseRefreshToken,
		scope,
	)
	if err := m.stateManager.StoreRefreshToken(ctx, refreshTokenData); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	m.logger.Info("Successfully created new token pair", "uid", uid, "scope", scope)

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    state.TokenTTL,
		RefreshToken: refreshToken,
		Scope:        scope,
	}, nil
}
