package state

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/crypto"
	"github.com/refractionpoint/lc-mcp-go/internal/redis"
	"log/slog"
)

// Manager manages OAuth state and token storage in Redis
type Manager struct {
	redis      *redis.Client
	encryption *crypto.TokenEncryption
	logger     *slog.Logger
}

// NewManager creates a new OAuth state manager
func NewManager(redisClient *redis.Client, encryption *crypto.TokenEncryption, logger *slog.Logger) *Manager {
	return &Manager{
		redis:      redisClient,
		encryption: encryption,
		logger:     logger,
	}
}

// ===== OAuth State Management =====

// GenerateState generates a secure random state parameter (32 bytes)
func (m *Manager) GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// StoreOAuthState stores OAuth authorization request state
func (m *Manager) StoreOAuthState(ctx context.Context, state *OAuthState) error {
	key := StatePrefix + state.State

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal OAuth state: %w", err)
	}

	if err := m.redis.SetEX(ctx, key, string(data), StateTTL); err != nil {
		return fmt.Errorf("failed to store OAuth state: %w", err)
	}

	m.logger.Debug("Stored OAuth state")

	return nil
}

// GetOAuthState retrieves OAuth state
func (m *Manager) GetOAuthState(ctx context.Context, state string) (*OAuthState, error) {
	key := StatePrefix + state

	data, err := m.redis.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get OAuth state: %w", err)
	}

	if data == "" {
		return nil, nil
	}

	var oauthState OAuthState
	if err := json.Unmarshal([]byte(data), &oauthState); err != nil {
		return nil, fmt.Errorf("failed to unmarshal OAuth state: %w", err)
	}

	return &oauthState, nil
}

// ConsumeOAuthState retrieves and deletes OAuth state (single-use)
func (m *Manager) ConsumeOAuthState(ctx context.Context, state string) (*OAuthState, error) {
	key := StatePrefix + state

	// Use atomic get-and-delete
	data, err := m.redis.AtomicGetAndDelete(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to consume OAuth state: %w", err)
	}

	if data == "" {
		return nil, nil
	}

	var oauthState OAuthState
	if err := json.Unmarshal([]byte(data), &oauthState); err != nil {
		return nil, fmt.Errorf("failed to unmarshal OAuth state: %w", err)
	}

	m.logger.Debug("Consumed OAuth state")

	return &oauthState, nil
}

// AtomicConsumeOAuthStateAndMappings atomically consumes OAuth state and session mappings
// SECURITY: Prevents TOCTOU race conditions
func (m *Manager) AtomicConsumeOAuthStateAndMappings(ctx context.Context, stateKey, sessionKey, oauthStateKey string) (string, string, string, error) {
	keys := []string{stateKey, sessionKey, oauthStateKey}

	results, err := m.redis.AtomicMultiGetAndDelete(ctx, keys)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to consume state and mappings: %w", err)
	}

	if len(results) != 3 {
		return "", "", "", fmt.Errorf("unexpected number of results: %d", len(results))
	}

	return results[0], results[1], results[2], nil
}

// ===== Authorization Code Management =====

// GenerateAuthorizationCode generates a secure random authorization code
func (m *Manager) GenerateAuthorizationCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate code: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// StoreAuthorizationCode stores an authorization code with encrypted Firebase tokens
func (m *Manager) StoreAuthorizationCode(ctx context.Context, code *AuthorizationCode) error {
	// Encrypt Firebase tokens before storage
	encryptedIDToken, err := m.encryption.Encrypt(code.FirebaseIDToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt ID token: %w", err)
	}

	encryptedRefreshToken, err := m.encryption.Encrypt(code.FirebaseRefreshToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt refresh token: %w", err)
	}

	// Create copy with encrypted tokens
	encrypted := *code
	encrypted.FirebaseIDToken = encryptedIDToken
	encrypted.FirebaseRefreshToken = encryptedRefreshToken

	key := CodePrefix + code.Code

	data, err := json.Marshal(encrypted)
	if err != nil {
		return fmt.Errorf("failed to marshal authorization code: %w", err)
	}

	if err := m.redis.SetEX(ctx, key, string(data), CodeTTL); err != nil {
		return fmt.Errorf("failed to store authorization code: %w", err)
	}

	m.logger.Debug("Stored authorization code")

	return nil
}

// ConsumeAuthorizationCode atomically retrieves and deletes an authorization code
func (m *Manager) ConsumeAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	key := CodePrefix + code

	// Use atomic get-and-delete
	data, err := m.redis.AtomicGetAndDelete(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to consume authorization code: %w", err)
	}

	if data == "" {
		return nil, nil
	}

	var authCode AuthorizationCode
	if err := json.Unmarshal([]byte(data), &authCode); err != nil {
		return nil, fmt.Errorf("failed to unmarshal authorization code: %w", err)
	}

	// Decrypt Firebase tokens
	authCode.FirebaseIDToken, err = m.encryption.Decrypt(authCode.FirebaseIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ID token: %w", err)
	}

	authCode.FirebaseRefreshToken, err = m.encryption.Decrypt(authCode.FirebaseRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
	}

	m.logger.Debug("Consumed authorization code")

	return &authCode, nil
}

// ===== Access Token Management =====

// GenerateAccessToken generates a secure random access token
func (m *Manager) GenerateAccessToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate access token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// StoreAccessToken stores an access token with encrypted Firebase tokens
func (m *Manager) StoreAccessToken(ctx context.Context, token *AccessTokenData) error {
	// Encrypt Firebase tokens before storage
	encryptedIDToken, err := m.encryption.Encrypt(token.FirebaseIDToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt ID token: %w", err)
	}

	encryptedRefreshToken, err := m.encryption.Encrypt(token.FirebaseRefreshToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt refresh token: %w", err)
	}

	// Create copy with encrypted tokens
	encrypted := *token
	encrypted.FirebaseIDToken = encryptedIDToken
	encrypted.FirebaseRefreshToken = encryptedRefreshToken

	key := TokenPrefix + token.AccessToken

	data, err := json.Marshal(encrypted)
	if err != nil {
		return fmt.Errorf("failed to marshal access token: %w", err)
	}

	// Add grace period to Redis TTL so token data persists beyond logical expiration
	// This allows the server to auto-refresh expired tokens transparently
	ttl := int(token.ExpiresAt - time.Now().Unix() + TokenGracePeriod)
	if ttl <= 0 {
		return fmt.Errorf("token already expired")
	}

	if err := m.redis.SetEX(ctx, key, string(data), ttl); err != nil {
		return fmt.Errorf("failed to store access token: %w", err)
	}

	m.logger.Debug("Stored access token", "expires_at", token.ExpiresAt, "redis_ttl", ttl)

	return nil
}

// GetAccessTokenData retrieves and decrypts access token data
// Returns token data even if expired (within grace period) to allow automatic refresh
func (m *Manager) GetAccessTokenData(ctx context.Context, accessToken string) (*AccessTokenData, error) {
	key := TokenPrefix + accessToken

	data, err := m.redis.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	if data == "" {
		return nil, nil
	}

	var tokenData AccessTokenData
	if err := json.Unmarshal([]byte(data), &tokenData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal access token: %w", err)
	}

	// NOTE: We no longer return nil for expired tokens here
	// The token data is kept in Redis beyond ExpiresAt (with grace period)
	// This allows the caller to check expiration and auto-refresh if needed

	// Decrypt Firebase tokens
	tokenData.FirebaseIDToken, err = m.encryption.Decrypt(tokenData.FirebaseIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ID token: %w", err)
	}

	tokenData.FirebaseRefreshToken, err = m.encryption.Decrypt(tokenData.FirebaseRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
	}

	return &tokenData, nil
}

// ExtendAccessTokenExpiration extends the expiration time of an access token
// This is used for transparent token refresh without changing the token string
func (m *Manager) ExtendAccessTokenExpiration(ctx context.Context, accessToken string, newExpiresAt int64) error {
	// Get existing token data
	tokenData, err := m.GetAccessTokenData(ctx, accessToken)
	if tokenData == nil || err != nil {
		return fmt.Errorf("access token not found: %w", err)
	}

	// Update expiration time
	tokenData.ExpiresAt = newExpiresAt

	// Re-store with updated expiration (StoreAccessToken handles Redis TTL)
	return m.StoreAccessToken(ctx, tokenData)
}

// UpdateAccessTokenFirebaseTokens updates Firebase tokens for an existing access token
func (m *Manager) UpdateAccessTokenFirebaseTokens(ctx context.Context, accessToken, newIDToken string, newExpiresAt int64) error {
	// Get existing token data
	tokenData, err := m.GetAccessTokenData(ctx, accessToken)
	if tokenData == nil || err != nil {
		return fmt.Errorf("access token not found: %w", err)
	}

	// Update Firebase tokens
	tokenData.FirebaseIDToken = newIDToken
	tokenData.FirebaseExpiresAt = newExpiresAt

	// Store updated token (encryption happens in StoreAccessToken)
	return m.StoreAccessToken(ctx, tokenData)
}

// RevokeAccessToken deletes an access token
func (m *Manager) RevokeAccessToken(ctx context.Context, accessToken string) error {
	key := TokenPrefix + accessToken

	if err := m.redis.Delete(ctx, key); err != nil {
		return fmt.Errorf("failed to revoke access token: %w", err)
	}

	m.logger.Info("Revoked access token")

	return nil
}

// ===== Refresh Token Management =====

// GenerateRefreshToken generates a secure random refresh token
func (m *Manager) GenerateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// StoreRefreshToken stores a refresh token with encrypted Firebase refresh token
func (m *Manager) StoreRefreshToken(ctx context.Context, token *RefreshTokenData) error {
	// Encrypt Firebase refresh token before storage
	encryptedFBRefreshToken, err := m.encryption.Encrypt(token.FirebaseRefreshToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt refresh token: %w", err)
	}

	// Create copy with encrypted token
	encrypted := *token
	encrypted.FirebaseRefreshToken = encryptedFBRefreshToken

	key := RefreshPrefix + token.RefreshToken

	data, err := json.Marshal(encrypted)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh token: %w", err)
	}

	if err := m.redis.SetEX(ctx, key, string(data), RefreshTTL); err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	m.logger.Debug("Stored refresh token")

	return nil
}

// GetRefreshTokenData retrieves and decrypts refresh token data
func (m *Manager) GetRefreshTokenData(ctx context.Context, refreshToken string) (*RefreshTokenData, error) {
	key := RefreshPrefix + refreshToken

	data, err := m.redis.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	if data == "" {
		return nil, nil
	}

	var tokenData RefreshTokenData
	if err := json.Unmarshal([]byte(data), &tokenData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal refresh token: %w", err)
	}

	// Decrypt Firebase refresh token
	tokenData.FirebaseRefreshToken, err = m.encryption.Decrypt(tokenData.FirebaseRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
	}

	return &tokenData, nil
}

// RevokeRefreshToken deletes a refresh token
func (m *Manager) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	key := RefreshPrefix + refreshToken

	if err := m.redis.Delete(ctx, key); err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	m.logger.Info("Revoked refresh token")

	return nil
}

// ===== Client Registration Management =====

// GenerateClientID generates a unique client ID for dynamic registration
func (m *Manager) GenerateClientID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate client ID: %w", err)
	}
	return "mcp_" + base64.URLEncoding.EncodeToString(b), nil
}

// StoreClientRegistration stores a client registration (no expiration)
func (m *Manager) StoreClientRegistration(ctx context.Context, client *ClientRegistration) error {
	key := ClientPrefix + client.ClientID

	data, err := json.Marshal(client)
	if err != nil {
		return fmt.Errorf("failed to marshal client registration: %w", err)
	}

	// No expiration for client registrations
	if err := m.redis.Set(ctx, key, string(data), 0); err != nil {
		return fmt.Errorf("failed to store client registration: %w", err)
	}

	m.logger.Info("Stored client registration")

	return nil
}

// GetClientRegistration retrieves a client registration
func (m *Manager) GetClientRegistration(ctx context.Context, clientID string) (*ClientRegistration, error) {
	key := ClientPrefix + clientID

	data, err := m.redis.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get client registration: %w", err)
	}

	if data == "" {
		return nil, nil
	}

	var client ClientRegistration
	if err := json.Unmarshal([]byte(data), &client); err != nil {
		return nil, fmt.Errorf("failed to unmarshal client registration: %w", err)
	}

	return &client, nil
}

// ===== Provider Selection Session Management =====

// GenerateSelectionSessionID generates a session ID for provider selection
func (m *Manager) GenerateSelectionSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate selection session ID: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// StoreSelectionSession stores OAuth parameters for provider selection
func (m *Manager) StoreSelectionSession(ctx context.Context, sessionID string, params map[string]string) error {
	key := SelectionPrefix + sessionID

	data, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("failed to marshal selection session: %w", err)
	}

	if err := m.redis.SetEX(ctx, key, string(data), SelectionTTL); err != nil {
		return fmt.Errorf("failed to store selection session: %w", err)
	}

	m.logger.Debug("Stored selection session")

	return nil
}

// ConsumeSelectionSession atomically retrieves and deletes a selection session
func (m *Manager) ConsumeSelectionSession(ctx context.Context, sessionID string) (map[string]string, error) {
	key := SelectionPrefix + sessionID

	data, err := m.redis.AtomicGetAndDelete(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to consume selection session: %w", err)
	}

	if data == "" {
		return nil, nil
	}

	var params map[string]string
	if err := json.Unmarshal([]byte(data), &params); err != nil {
		return nil, fmt.Errorf("failed to unmarshal selection session: %w", err)
	}

	return params, nil
}

// ConsumeOAuthStateMappings atomically consumes OAuth state and all related mappings
// SECURITY FIX: Prevents TOCTOU race conditions during OAuth callback processing
func (m *Manager) ConsumeOAuthStateMappings(ctx context.Context, firebaseState string) (oauthState string, sessionID string, err error) {
	// Build keys for atomic multi-get-and-delete
	keys := []string{
		SelectionPrefix + "oauth:state:" + firebaseState,
		SelectionPrefix + "oauth:fbsession:" + firebaseState,
	}

	results, err := m.redis.AtomicMultiGetAndDelete(ctx, keys)
	if err != nil {
		return "", "", fmt.Errorf("failed to consume OAuth state mappings: %w", err)
	}

	if len(results) != 2 {
		return "", "", fmt.Errorf("unexpected number of results: %d", len(results))
	}

	// Parse OAuth state mapping
	if results[0] != "" {
		var stateData map[string]string
		if err := json.Unmarshal([]byte(results[0]), &stateData); err == nil {
			oauthState = stateData["oauth_state"]
		}
	}

	// Parse session ID mapping
	if results[1] != "" {
		var sessionData map[string]string
		if err := json.Unmarshal([]byte(results[1]), &sessionData); err == nil {
			sessionID = sessionData["session_id"]
		}
	}

	if oauthState == "" || sessionID == "" {
		m.logger.Warn("OAuth state mappings incomplete",
			"oauth_state", oauthState,
			"session_id", sessionID,
			"firebase_state", firebaseState)
		return "", "", fmt.Errorf("invalid or incomplete OAuth state mappings")
	}

	m.logger.Debug("Atomically consumed OAuth state mappings",
		"firebase_state", firebaseState,
		"oauth_state", oauthState)

	return oauthState, sessionID, nil
}

// ===== MFA Session Management =====

// GenerateMFASessionID generates a session ID for MFA challenge
func (m *Manager) GenerateMFASessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate MFA session ID: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// StoreMFASession stores an MFA challenge session with encryption and integrity protection
func (m *Manager) StoreMFASession(ctx context.Context, sessionID string, session *MFASession) error {
	key := MFAPrefix + sessionID

	// Marshal session data
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal MFA session: %w", err)
	}

	// SECURITY FIX: Encrypt session data for confidentiality and integrity protection
	// AES-256-GCM provides both encryption and authentication tag verification
	encryptedData, err := m.encryption.Encrypt(string(data))
	if err != nil {
		return fmt.Errorf("failed to encrypt MFA session: %w", err)
	}

	if err := m.redis.SetEX(ctx, key, encryptedData, MFATTL); err != nil {
		return fmt.Errorf("failed to store MFA session: %w", err)
	}

	m.logger.Debug("Stored MFA session with AES-256-GCM encryption and integrity protection")

	return nil
}

// GetMFASession retrieves an MFA session (non-destructive) with decryption and integrity verification
func (m *Manager) GetMFASession(ctx context.Context, sessionID string) (*MFASession, error) {
	key := MFAPrefix + sessionID

	encryptedData, err := m.redis.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get MFA session: %w", err)
	}

	if encryptedData == "" {
		return nil, nil
	}

	// SECURITY FIX: Decrypt and verify integrity of MFA session data
	// AES-256-GCM will fail if data has been tampered with
	data, err := m.encryption.Decrypt(encryptedData)
	if err != nil {
		m.logger.Error("SECURITY ALERT: MFA session decryption failed - possible tampering",
			"session_id", sessionID,
			"error", err)
		return nil, fmt.Errorf("MFA session integrity check failed: %w", err)
	}

	var session MFASession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MFA session: %w", err)
	}

	return &session, nil
}

// GetMFAAttemptCount retrieves the current attempt count without incrementing
func (m *Manager) GetMFAAttemptCount(ctx context.Context, sessionID string) (int, error) {
	counterKey := MFAPrefix + sessionID + ":attempts"

	data, err := m.redis.Get(ctx, counterKey)
	if err != nil || data == "" {
		return 0, nil
	}

	var count int
	fmt.Sscanf(data, "%d", &count)
	return count, nil
}

// IncrementMFAAttempts atomically increments the MFA attempt counter
// SECURITY: Uses Redis INCR for atomic increment to prevent race conditions
func (m *Manager) IncrementMFAAttempts(ctx context.Context, sessionID string) (int, error) {
	// Verify session exists first
	session, err := m.GetMFASession(ctx, sessionID)
	if err != nil || session == nil {
		return 0, fmt.Errorf("MFA session not found: %w", err)
	}

	// Use separate counter key for atomic increment
	counterKey := MFAPrefix + sessionID + ":attempts"

	// Atomically increment the counter
	attempts, err := m.redis.Incr(ctx, counterKey)
	if err != nil {
		return 0, fmt.Errorf("failed to increment MFA attempts: %w", err)
	}

	// Set expiration on first increment
	if attempts == 1 {
		if err := m.redis.Expire(ctx, counterKey, time.Duration(MFATTL)*time.Second); err != nil {
			m.logger.Warn("Failed to set MFA attempt counter expiration")
		}
	}

	return int(attempts), nil
}

// ConsumeMFASession atomically retrieves and deletes an MFA session with decryption and integrity verification
func (m *Manager) ConsumeMFASession(ctx context.Context, sessionID string) (*MFASession, error) {
	key := MFAPrefix + sessionID
	counterKey := MFAPrefix + sessionID + ":attempts"

	encryptedData, err := m.redis.AtomicGetAndDelete(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to consume MFA session: %w", err)
	}

	if encryptedData == "" {
		return nil, nil
	}

	// SECURITY FIX: Decrypt and verify integrity of MFA session data during consumption
	// AES-256-GCM will fail if data has been tampered with
	data, err := m.encryption.Decrypt(encryptedData)
	if err != nil {
		m.logger.Error("SECURITY ALERT: MFA session decryption failed during consumption - possible tampering",
			"session_id", sessionID,
			"error", err)
		return nil, fmt.Errorf("MFA session integrity check failed: %w", err)
	}

	var session MFASession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MFA session: %w", err)
	}

	// Also delete the attempt counter
	m.redis.Delete(ctx, counterKey)

	m.logger.Debug("Consumed MFA session with verified integrity")

	return &session, nil
}
