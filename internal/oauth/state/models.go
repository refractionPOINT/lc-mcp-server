package state

import "time"

// OAuthState represents OAuth authorization request state (CSRF protection)
type OAuthState struct {
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	RedirectURI         string `json:"redirect_uri"`
	ClientID            string `json:"client_id"`
	Scope               string `json:"scope"`
	Resource            string `json:"resource"`
	Provider            string `json:"provider"` // e.g., "google.com", "microsoft.com"
	CreatedAt           int64  `json:"created_at"`
}

// AuthorizationCode represents an authorization code with associated data
// SECURITY: Stores OAuth security parameters for validation during token exchange
type AuthorizationCode struct {
	Code                 string `json:"code"`
	State                string `json:"state"`
	UID                  string `json:"uid"`
	FirebaseIDToken      string `json:"firebase_id_token"`      // Encrypted in Redis
	FirebaseRefreshToken string `json:"firebase_refresh_token"` // Encrypted in Redis
	FirebaseExpiresAt    int64  `json:"firebase_expires_at"`
	CreatedAt            int64  `json:"created_at"`
	// OAuth security parameters for token exchange validation
	RedirectURI         string  `json:"redirect_uri"`
	ClientID            string  `json:"client_id"`
	Scope               string  `json:"scope"`
	CodeChallenge       *string `json:"code_challenge,omitempty"`
	CodeChallengeMethod *string `json:"code_challenge_method,omitempty"`
}

// AccessTokenData represents an access token with Firebase token mapping
type AccessTokenData struct {
	AccessToken          string `json:"access_token"`
	UID                  string `json:"uid"`
	FirebaseIDToken      string `json:"firebase_id_token"`      // Encrypted in Redis
	FirebaseRefreshToken string `json:"firebase_refresh_token"` // Encrypted in Redis
	FirebaseExpiresAt    int64  `json:"firebase_expires_at"`
	Scope                string `json:"scope"`
	CreatedAt            int64  `json:"created_at"`
	ExpiresAt            int64  `json:"expires_at"`
	// Extension tracking for security auditing and limits
	ExtensionCount int   `json:"extension_count"`  // Number of times token has been auto-extended
	LastExtendedAt int64 `json:"last_extended_at"` // Timestamp of last extension (0 if never extended)
}

// RefreshTokenData represents a refresh token mapping
type RefreshTokenData struct {
	RefreshToken         string `json:"refresh_token"`
	AccessToken          string `json:"access_token"`
	UID                  string `json:"uid"`
	FirebaseRefreshToken string `json:"firebase_refresh_token"` // Encrypted in Redis
	Scope                string `json:"scope"`
	CreatedAt            int64  `json:"created_at"`
}

// ClientRegistration represents a dynamically registered OAuth client
type ClientRegistration struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	CreatedAt    int64    `json:"created_at"`
}

// MFASession represents an MFA challenge session
type MFASession struct {
	MFAPendingCredential string  `json:"mfa_pending_credential"`
	MFAEnrollmentID      string  `json:"mfa_enrollment_id"`
	OAuthState           string  `json:"oauth_state"`
	DisplayName          string  `json:"display_name"`
	LocalID              string  `json:"local_id"`
	Email                string  `json:"email"`
	AttemptCount         int     `json:"attempt_count"`
	PendingToken         *string `json:"pending_token,omitempty"` // Optional - not needed for OAuth TOTP
}

// TTL constants (in seconds)
const (
	StateTTL       = 600     // 10 minutes
	CodeTTL        = 300     // 5 minutes
	TokenTTL       = 86400   // 1 day (access token) - extends on each use
	RefreshTTL     = 2592000 // 30 days (refresh token)
	SelectionTTL   = 300     // 5 minutes (provider selection)
	MFATTL         = 300     // 5 minutes (MFA challenge)
	MaxMFAAttempts = 3       // Maximum failed MFA attempts

	// TokenRefreshBuffer is the time before expiration when we should refresh the MCP token
	// This ensures the token is refreshed before it expires (1 hour before)
	TokenRefreshBuffer = 3600 // 1 hour before expiration

	// TokenGracePeriod is extra time to keep token data in Redis after logical expiration
	// This allows the server to auto-refresh expired tokens transparently
	// Supports up to 1 week of inactivity before requiring re-authentication
	TokenGracePeriod = 604800 // 7 days grace period

	// MaxTokenExtensions limits how many times a token can be auto-extended
	// This prevents indefinite token lifetime and ensures periodic re-authentication
	// With 1-day TTL, this allows up to 30 days total lifetime (matches refresh token)
	MaxTokenExtensions = 30
)

// Key prefixes for Redis
const (
	StatePrefix     = "oauth:state:"
	CodePrefix      = "oauth:code:"
	TokenPrefix     = "oauth:token:"
	RefreshPrefix   = "oauth:refresh:"
	ClientPrefix    = "oauth:client:"
	SelectionPrefix = "oauth:selection:"
	MFAPrefix       = "oauth:mfa:"
	SessionPrefix   = "oauth:session:"   // OAuth state -> Firebase state mapping
	FBSessionPrefix = "oauth:fbsession:" // Firebase state -> session ID mapping
)

// Token validation result
type TokenValidationResult struct {
	Valid                bool
	UID                  string
	FirebaseIDToken      string
	FirebaseRefreshToken string
	Scope                string
	Error                string
	Refreshed            bool
}

// NewOAuthState creates a new OAuth state
func NewOAuthState(state, codeChallenge, codeChallengeMethod, redirectURI, clientID, scope, resource, provider string) *OAuthState {
	return &OAuthState{
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		RedirectURI:         redirectURI,
		ClientID:            clientID,
		Scope:               scope,
		Resource:            resource,
		Provider:            provider,
		CreatedAt:           time.Now().Unix(),
	}
}

// NewAuthorizationCode creates a new authorization code
func NewAuthorizationCode(code, state, uid, fbIDToken, fbRefreshToken string, fbExpiresAt int64, redirectURI, clientID, scope string, codeChallenge, codeChallengeMethod *string) *AuthorizationCode {
	return &AuthorizationCode{
		Code:                 code,
		State:                state,
		UID:                  uid,
		FirebaseIDToken:      fbIDToken,
		FirebaseRefreshToken: fbRefreshToken,
		FirebaseExpiresAt:    fbExpiresAt,
		CreatedAt:            time.Now().Unix(),
		RedirectURI:          redirectURI,
		ClientID:             clientID,
		Scope:                scope,
		CodeChallenge:        codeChallenge,
		CodeChallengeMethod:  codeChallengeMethod,
	}
}

// NewAccessTokenData creates a new access token data
func NewAccessTokenData(accessToken, uid, fbIDToken, fbRefreshToken string, fbExpiresAt int64, scope string, ttl int) *AccessTokenData {
	now := time.Now().Unix()
	return &AccessTokenData{
		AccessToken:          accessToken,
		UID:                  uid,
		FirebaseIDToken:      fbIDToken,
		FirebaseRefreshToken: fbRefreshToken,
		FirebaseExpiresAt:    fbExpiresAt,
		Scope:                scope,
		CreatedAt:            now,
		ExpiresAt:            now + int64(ttl),
	}
}

// NewRefreshTokenData creates a new refresh token data
func NewRefreshTokenData(refreshToken, accessToken, uid, fbRefreshToken, scope string) *RefreshTokenData {
	return &RefreshTokenData{
		RefreshToken:         refreshToken,
		AccessToken:          accessToken,
		UID:                  uid,
		FirebaseRefreshToken: fbRefreshToken,
		Scope:                scope,
		CreatedAt:            time.Now().Unix(),
	}
}

// NewClientRegistration creates a new client registration
func NewClientRegistration(clientID, clientName string, redirectURIs []string) *ClientRegistration {
	return &ClientRegistration{
		ClientID:     clientID,
		ClientName:   clientName,
		RedirectURIs: redirectURIs,
		CreatedAt:    time.Now().Unix(),
	}
}

// NewMFASession creates a new MFA session
func NewMFASession(mfaPendingCredential, mfaEnrollmentID, oauthState, displayName, localID, email string, pendingToken *string) *MFASession {
	return &MFASession{
		MFAPendingCredential: mfaPendingCredential,
		MFAEnrollmentID:      mfaEnrollmentID,
		OAuthState:           oauthState,
		DisplayName:          displayName,
		LocalID:              localID,
		Email:                email,
		AttemptCount:         0,
		PendingToken:         pendingToken,
	}
}
