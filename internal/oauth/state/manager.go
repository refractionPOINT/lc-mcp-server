package state

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// GenerateState generates a secure random identifier (32 bytes).
func (m *Manager) GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// ErrAlreadyExists is returned when a create-only record already exists.
var ErrAlreadyExists = errors.New("record already exists")

// createOnly stores value under key only if the key is free (SET NX).
func (m *Manager) createOnly(ctx context.Context, key, value string, ttlSeconds int) error {
	ok, err := m.redis.SetNX(ctx, key, value, time.Duration(ttlSeconds)*time.Second)
	if err != nil {
		return err
	}
	if !ok {
		return ErrAlreadyExists
	}
	return nil
}

// maxCreateAttempts bounds retries on an id collision, which with 256-bit
// random ids only a broken random source or a Redis fault can cause.
const maxCreateAttempts = 3

// CreateOAuthState stores an OAuth authorization transaction under a
// server-generated, unguessable transaction id and returns that id.
//
// SECURITY: the transaction is never keyed by anything the client supplied.
// The client's own "state" is only data (OAuthState.State) that is echoed back
// to its redirect URI. The write is create-only, so no request can replace a
// transaction that is in flight. Everything that continues the flow (the
// provider round trip, MFA) refers to the transaction by this id.
func (m *Manager) CreateOAuthState(ctx context.Context, st *OAuthState) (string, error) {
	for attempt := 0; attempt < maxCreateAttempts; attempt++ {
		txID, err := m.GenerateState()
		if err != nil {
			return "", err
		}
		st.TxID = txID
		data, err := json.Marshal(st)
		if err != nil {
			return "", fmt.Errorf("failed to marshal OAuth state: %w", err)
		}
		err = m.createOnly(ctx, StatePrefix+txID, string(data), StateTTL)
		if errors.Is(err, ErrAlreadyExists) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("failed to store OAuth state: %w", err)
		}
		m.logger.Debug("Stored OAuth state")
		return txID, nil
	}
	return "", fmt.Errorf("failed to store OAuth state: transaction id collision")
}

// GetOAuthState retrieves an OAuth transaction by its transaction id.
func (m *Manager) GetOAuthState(ctx context.Context, txID string) (*OAuthState, error) {
	key := StatePrefix + txID

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

// ConsumeOAuthState retrieves and deletes an OAuth transaction by its
// transaction id (single-use).
func (m *Manager) ConsumeOAuthState(ctx context.Context, txID string) (*OAuthState, error) {
	key := StatePrefix + txID

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

	// Create-only: a code is never replaced once issued.
	if err := m.createOnly(ctx, key, string(data), CodeTTL); err != nil {
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

// ErrTokenRevoked is returned when a write was refused because the token, or
// the grant (family) it belongs to, has been revoked.
var ErrTokenRevoked = errors.New("token revoked")

// tokenHash is the identifier revocation records use for a token, so the keys
// carry no usable credential.
func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// GenerateFamilyID generates the id of a new token family (one grant).
func (m *Manager) GenerateFamilyID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate family id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// IsFamilyRevoked reports whether the grant has been revoked. An empty family
// id (legacy token) is never revoked this way.
func (m *Manager) IsFamilyRevoked(ctx context.Context, familyID string) (bool, error) {
	if familyID == "" {
		return false, nil
	}
	n, err := m.redis.Exists(ctx, RevokedFamilyPrefix+familyID)
	if err != nil {
		return false, fmt.Errorf("failed to check family revocation: %w", err)
	}
	return n > 0, nil
}

// encodeAccessToken serializes an access token with its Firebase tokens
// encrypted, and returns the Redis TTL: the logical lifetime plus the grace
// period that lets the server recover an expired token transparently.
func (m *Manager) encodeAccessToken(token *AccessTokenData) (string, time.Duration, error) {
	encryptedIDToken, err := m.encryption.Encrypt(token.FirebaseIDToken)
	if err != nil {
		return "", 0, fmt.Errorf("failed to encrypt ID token: %w", err)
	}

	encryptedRefreshToken, err := m.encryption.Encrypt(token.FirebaseRefreshToken)
	if err != nil {
		return "", 0, fmt.Errorf("failed to encrypt refresh token: %w", err)
	}

	encrypted := *token
	encrypted.FirebaseIDToken = encryptedIDToken
	encrypted.FirebaseRefreshToken = encryptedRefreshToken

	data, err := json.Marshal(encrypted)
	if err != nil {
		return "", 0, fmt.Errorf("failed to marshal access token: %w", err)
	}

	ttl := token.ExpiresAt - time.Now().Unix() + TokenGracePeriod
	if ttl <= 0 {
		return "", 0, fmt.Errorf("token already expired")
	}
	return string(data), time.Duration(ttl) * time.Second, nil
}

// StoreAccessToken stores a new access token with encrypted Firebase tokens.
// It is create-only: an existing record is never overwritten, so it cannot be
// used to resurrect a revoked token. Changing a stored token goes through
// UpdateAccessToken. It writes the record alone; a new grant is stored with
// IssueTokens.
func (m *Manager) StoreAccessToken(ctx context.Context, token *AccessTokenData) error {
	data, ttl, err := m.encodeAccessToken(token)
	if err != nil {
		return err
	}

	if err := m.createOnly(ctx, TokenPrefix+token.AccessToken, data, int(ttl/time.Second)); err != nil {
		return fmt.Errorf("failed to store access token: %w", err)
	}

	m.logger.Debug("Stored access token", "expires_at", token.ExpiresAt, "redis_ttl", int(ttl/time.Second))

	return nil
}

// UpdateAccessToken writes back a changed access token (lifetime extension,
// refreshed Firebase tokens) only if the record still exists and its family has
// not been revoked, in one atomic step. It reports whether the record was
// updated; false means it was revoked or expired meanwhile, and nothing was
// written, so an update that raced a revocation can never bring the token back.
// The token's index and its family record are kept alive at least as long as the
// token itself.
func (m *Manager) UpdateAccessToken(ctx context.Context, token *AccessTokenData) (bool, error) {
	data, ttl, err := m.encodeAccessToken(token)
	if err != nil {
		return false, err
	}
	keys := []string{TokenPrefix + token.AccessToken}
	if fam := token.FamilyID; fam != "" {
		keys = append(keys, RevokedFamilyPrefix+fam, TokenFamilyPrefix+tokenHash(token.AccessToken), FamilyPrefix+fam)
	}
	n, err := scriptInt(m.redis.Run(ctx, updateAccessScript, keys, data, ms(ttl), token.FamilyID))
	if err != nil {
		return false, fmt.Errorf("failed to update access token: %w", err)
	}
	return n == updateDone, nil
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
	tokenData, err := m.GetAccessTokenData(ctx, accessToken)
	if tokenData == nil || err != nil {
		return fmt.Errorf("access token not found: %w", err)
	}

	tokenData.ExpiresAt = newExpiresAt

	updated, err := m.UpdateAccessToken(ctx, tokenData)
	if err != nil {
		return err
	}
	if !updated {
		return fmt.Errorf("access token not found or revoked")
	}
	return nil
}

// UpdateAccessTokenFirebaseTokens updates Firebase tokens for an existing access token
func (m *Manager) UpdateAccessTokenFirebaseTokens(ctx context.Context, accessToken, newIDToken string, newExpiresAt int64) error {
	tokenData, err := m.GetAccessTokenData(ctx, accessToken)
	if tokenData == nil || err != nil {
		return fmt.Errorf("access token not found: %w", err)
	}

	tokenData.FirebaseIDToken = newIDToken
	tokenData.FirebaseExpiresAt = newExpiresAt

	updated, err := m.UpdateAccessToken(ctx, tokenData)
	if err != nil {
		return err
	}
	if !updated {
		return fmt.Errorf("access token not found or revoked")
	}
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

// encodeRefreshToken serializes a refresh token with its Firebase refresh
// token encrypted.
func (m *Manager) encodeRefreshToken(token *RefreshTokenData) (string, error) {
	encryptedFBRefreshToken, err := m.encryption.Encrypt(token.FirebaseRefreshToken)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt refresh token: %w", err)
	}

	encrypted := *token
	encrypted.FirebaseRefreshToken = encryptedFBRefreshToken

	data, err := json.Marshal(encrypted)
	if err != nil {
		return "", fmt.Errorf("failed to marshal refresh token: %w", err)
	}
	return string(data), nil
}

// StoreRefreshToken stores a new refresh token with encrypted Firebase refresh
// token. It is create-only, so an existing record is never overwritten. It
// writes the record alone; a new grant is stored with IssueTokens.
func (m *Manager) StoreRefreshToken(ctx context.Context, token *RefreshTokenData) error {
	data, err := m.encodeRefreshToken(token)
	if err != nil {
		return err
	}

	if err := m.createOnly(ctx, RefreshPrefix+token.RefreshToken, data, RefreshTTL); err != nil {
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

	return m.decodeRefreshToken(data)
}

func (m *Manager) decodeRefreshToken(data string) (*RefreshTokenData, error) {
	var tokenData RefreshTokenData
	if err := json.Unmarshal([]byte(data), &tokenData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal refresh token: %w", err)
	}

	var err error
	tokenData.FirebaseRefreshToken, err = m.encryption.Decrypt(tokenData.FirebaseRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
	}

	return &tokenData, nil
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

	// No expiration for client registrations. Create-only: a registration (and
	// so the redirect URIs it vouches for) is never replaced under its id.
	ok, err := m.redis.SetNX(ctx, key, string(data), 0)
	if err != nil {
		return fmt.Errorf("failed to store client registration: %w", err)
	}
	if !ok {
		return fmt.Errorf("failed to store client registration: %w", ErrAlreadyExists)
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

// CreateSelectionSession stores OAuth parameters for provider selection under
// a server-generated session id. Create-only.
func (m *Manager) CreateSelectionSession(ctx context.Context, sessionID string, params map[string]string) error {
	data, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("failed to marshal selection session: %w", err)
	}

	if err := m.createOnly(ctx, SelectionPrefix+sessionID, string(data), SelectionTTL); err != nil {
		return fmt.Errorf("failed to store selection session: %w", err)
	}

	m.logger.Debug("Stored selection session")

	return nil
}

// UpdateSelectionSession rewrites a selection session that still exists,
// keeping its expiry. A session that was consumed or expired in the meantime
// is not resurrected (ErrSelectionSessionGone).
func (m *Manager) UpdateSelectionSession(ctx context.Context, sessionID string, params map[string]string) error {
	data, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("failed to marshal selection session: %w", err)
	}
	ok, err := m.redis.SetXXKeepTTL(ctx, SelectionPrefix+sessionID, string(data))
	if err != nil {
		return fmt.Errorf("failed to update selection session: %w", err)
	}
	if !ok {
		return ErrSelectionSessionGone
	}
	return nil
}

// ErrSelectionSessionGone is returned when a selection session expired or was consumed.
var ErrSelectionSessionGone = errors.New("selection session expired or already used")

// StoreOAuthMappings records the provider round trip of a transaction: the
// Firebase state that comes back on the callback maps to the server's
// transaction id and to the Firebase session id. Both writes are create-only
// (a Firebase state already in use fails the login instead of redirecting
// another login's callback), and neither involves anything the client supplied.
func (m *Manager) StoreOAuthMappings(ctx context.Context, firebaseState, txID, firebaseSessionID string) error {
	if firebaseState == "" || txID == "" {
		return fmt.Errorf("firebase state and transaction id are required")
	}
	stateKey := SelectionPrefix + "oauth:state:" + firebaseState
	sessionKey := SelectionPrefix + "oauth:fbsession:" + firebaseState

	stateData, err := json.Marshal(map[string]string{"oauth_state": txID})
	if err != nil {
		return err
	}
	sessionData, err := json.Marshal(map[string]string{"session_id": firebaseSessionID})
	if err != nil {
		return err
	}
	if err := m.createOnly(ctx, stateKey, string(stateData), SelectionTTL); err != nil {
		return fmt.Errorf("failed to store OAuth state mapping: %w", err)
	}
	if err := m.createOnly(ctx, sessionKey, string(sessionData), SelectionTTL); err != nil {
		// Only the key this call created is removed.
		_ = m.redis.Delete(ctx, stateKey)
		return fmt.Errorf("failed to store OAuth session mapping: %w", err)
	}
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

// ConsumeOAuthStateMappings atomically consumes the mappings of a provider
// round trip and returns the transaction id and the Firebase session id.
// SECURITY FIX: Prevents TOCTOU race conditions during OAuth callback processing
func (m *Manager) ConsumeOAuthStateMappings(ctx context.Context, firebaseState string) (txID string, sessionID string, err error) {
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
			txID = stateData["oauth_state"]
		}
	}

	// Parse session ID mapping
	if results[1] != "" {
		var sessionData map[string]string
		if err := json.Unmarshal([]byte(results[1]), &sessionData); err == nil {
			sessionID = sessionData["session_id"]
		}
	}

	if txID == "" || sessionID == "" {
		m.logger.Warn("OAuth state mappings incomplete",
			"tx_id", txID,
			"session_id", sessionID,
			"firebase_state", firebaseState)
		return "", "", fmt.Errorf("invalid or incomplete OAuth state mappings")
	}

	m.logger.Debug("Atomically consumed OAuth state mappings",
		"firebase_state", firebaseState)

	return txID, sessionID, nil
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

	// Create-only: the id is server-generated and a session is never replaced.
	if err := m.createOnly(ctx, key, encryptedData, MFATTL); err != nil {
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

// ErrMFASessionNotFound means the MFA session expired or was already consumed
var ErrMFASessionNotFound = errors.New("MFA session not found")

// IncrementMFAAttempts atomically increments the MFA attempt counter
// SECURITY: Uses Redis INCR for atomic increment to prevent race conditions
func (m *Manager) IncrementMFAAttempts(ctx context.Context, sessionID string) (int, error) {
	// Verify session exists first
	session, err := m.GetMFASession(ctx, sessionID)
	if err != nil {
		return 0, err
	}
	if session == nil {
		return 0, ErrMFASessionNotFound
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
