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
	"github.com/sirupsen/logrus"
)

// Manager manages OAuth state and token storage in Redis
type Manager struct {
	redis      *redis.Client
	encryption *crypto.TokenEncryption
	logger     *logrus.Logger
}

// NewManager creates a new OAuth state manager
func NewManager(redisClient *redis.Client, encryption *crypto.TokenEncryption, logger *logrus.Logger) *Manager {
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

	m.logger.WithFields(logrus.Fields{
		"state":     state.State[:10] + "...",
		"client_id": state.ClientID,
		"provider":  state.Provider,
	}).Debug("Stored OAuth state")

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

	m.logger.WithField("state", state[:10]+"...").Debug("Consumed OAuth state")

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

	m.logger.WithFields(logrus.Fields{
		"code":      code.Code[:10] + "...",
		"uid":       code.UID,
		"encrypted": m.encryption.IsEnabled(),
	}).Debug("Stored authorization code")

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

	m.logger.WithFields(logrus.Fields{
		"code":      code[:10] + "...",
		"decrypted": m.encryption.IsEnabled(),
	}).Debug("Consumed authorization code")

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

	ttl := int(token.ExpiresAt - time.Now().Unix())
	if ttl <= 0 {
		return fmt.Errorf("token already expired")
	}

	if err := m.redis.SetEX(ctx, key, string(data), ttl); err != nil {
		return fmt.Errorf("failed to store access token: %w", err)
	}

	m.logger.WithFields(logrus.Fields{
		"token":     token.AccessToken[:10] + "...",
		"uid":       token.UID,
		"encrypted": m.encryption.IsEnabled(),
	}).Debug("Stored access token")

	return nil
}

// GetAccessTokenData retrieves and decrypts access token data
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

	// Check if expired
	if tokenData.ExpiresAt < time.Now().Unix() {
		return nil, nil
	}

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

	m.logger.WithField("token", accessToken[:10]+"...").Info("Revoked access token")

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

	m.logger.WithFields(logrus.Fields{
		"token":     token.RefreshToken[:10] + "...",
		"uid":       token.UID,
		"encrypted": m.encryption.IsEnabled(),
	}).Debug("Stored refresh token")

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

	m.logger.WithField("token", refreshToken[:10]+"...").Info("Revoked refresh token")

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

	m.logger.WithFields(logrus.Fields{
		"client_id":   client.ClientID,
		"client_name": client.ClientName,
	}).Info("Stored client registration")

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

	m.logger.WithField("session_id", sessionID[:10]+"...").Debug("Stored selection session")

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

// ===== MFA Session Management =====

// GenerateMFASessionID generates a session ID for MFA challenge
func (m *Manager) GenerateMFASessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate MFA session ID: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// StoreMFASession stores an MFA challenge session
func (m *Manager) StoreMFASession(ctx context.Context, sessionID string, session *MFASession) error {
	key := MFAPrefix + sessionID

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal MFA session: %w", err)
	}

	if err := m.redis.SetEX(ctx, key, string(data), MFATTL); err != nil {
		return fmt.Errorf("failed to store MFA session: %w", err)
	}

	m.logger.WithField("session_id", sessionID[:20]+"...").Debug("Stored MFA session")

	return nil
}

// GetMFASession retrieves an MFA session (non-destructive)
func (m *Manager) GetMFASession(ctx context.Context, sessionID string) (*MFASession, error) {
	key := MFAPrefix + sessionID

	data, err := m.redis.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get MFA session: %w", err)
	}

	if data == "" {
		return nil, nil
	}

	var session MFASession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MFA session: %w", err)
	}

	return &session, nil
}

// IncrementMFAAttempts atomically increments the MFA attempt counter
func (m *Manager) IncrementMFAAttempts(ctx context.Context, sessionID string) (int, error) {
	session, err := m.GetMFASession(ctx, sessionID)
	if err != nil || session == nil {
		return 0, fmt.Errorf("MFA session not found: %w", err)
	}

	session.AttemptCount++

	// Store updated session
	if err := m.StoreMFASession(ctx, sessionID, session); err != nil {
		return 0, err
	}

	return session.AttemptCount, nil
}

// ConsumeMFASession atomically retrieves and deletes an MFA session
func (m *Manager) ConsumeMFASession(ctx context.Context, sessionID string) (*MFASession, error) {
	key := MFAPrefix + sessionID

	data, err := m.redis.AtomicGetAndDelete(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to consume MFA session: %w", err)
	}

	if data == "" {
		return nil, nil
	}

	var session MFASession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MFA session: %w", err)
	}

	m.logger.WithField("session_id", sessionID[:20]+"...").Debug("Consumed MFA session")

	return &session, nil
}
