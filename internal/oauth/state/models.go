package state

import "time"

// OAuthState is one OAuth authorization transaction.
//
// It is stored under TxID, which the server generates. State is the client's
// own "state" parameter: opaque data that is only echoed back to the client's
// redirect URI, never used to find or key anything.
type OAuthState struct {
	// TxID is the server-generated transaction id (the Redis key suffix). It is
	// empty on transactions written before transaction ids existed, which were
	// keyed by the client's state; callers always look transactions up by the
	// id they were handed (a provider-callback mapping or an MFA session), so
	// those finish normally.
	TxID                string `json:"tx_id,omitempty"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	RedirectURI         string `json:"redirect_uri"`
	ClientID            string `json:"client_id"`
	Scope               string `json:"scope"`
	Resource            string `json:"resource"`
	Provider            string `json:"provider"` // e.g., "google.com", "microsoft.com"
	CreatedAt           int64  `json:"created_at"`
	// BrowserBinding is the SHA-256 (hex) of the secret in the browser-binding
	// cookie of the browser that went through the selection page and
	// /authorize. The provider callback and the MFA steps only proceed from a
	// browser presenting that secret, so an authorization URL sent to someone
	// else cannot complete this transaction. Empty on transactions written
	// before the binding existed; those are never completed (fail closed).
	BrowserBinding string `json:"browser_binding,omitempty"`
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
	// Resource is the canonical RFC 8707 resource the code was authorized for.
	// Empty on codes written before resource binding existed (legacy).
	Resource string `json:"resource,omitempty"`
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
	// Resource is the canonical RFC 8707 resource (token audience) this token
	// was issued for. Empty on tokens issued before resource binding existed
	// (legacy): they are accepted for every endpoint of this server.
	Resource string `json:"resource,omitempty"`
	// ClientID is the OAuth client the token was issued to. Empty on tokens
	// issued before client binding existed (legacy).
	ClientID string `json:"client_id,omitempty"`
	// FamilyID identifies the grant (one sign-in) the token belongs to. Every
	// rotation of the refresh token carries it, so revoking the family revokes
	// every token of the grant, including ones a revoker has no name for.
	// Empty on tokens issued before families existed (legacy): the first
	// refresh gives the grant one.
	FamilyID string `json:"family_id,omitempty"`
}

// RefreshTokenData represents a refresh token mapping
type RefreshTokenData struct {
	RefreshToken         string `json:"refresh_token"`
	AccessToken          string `json:"access_token"`
	UID                  string `json:"uid"`
	FirebaseRefreshToken string `json:"firebase_refresh_token"` // Encrypted in Redis
	Scope                string `json:"scope"`
	CreatedAt            int64  `json:"created_at"`
	// Resource is the canonical RFC 8707 resource the token family is bound to;
	// it is carried over, or narrowed, on every rotation. Empty means legacy.
	Resource string `json:"resource,omitempty"`
	// ClientID is the OAuth client this token family is bound to; it is carried
	// through every rotation and must be presented on refresh. Empty means a
	// token issued before client binding existed (legacy): the first refresh
	// that names a client binds it.
	ClientID string `json:"client_id,omitempty"`
	// FamilyID is the grant this token belongs to; see AccessTokenData.FamilyID.
	FamilyID string `json:"family_id,omitempty"`
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
	OAuthState           string  `json:"oauth_state"` // transaction id of the OAuthState this challenge belongs to
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
	// Supports up to 23 hours of inactivity before requiring re-authentication
	TokenGracePeriod = 82800 // 23 hours grace period

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

	// RevokedTokenPrefix + sha256(token) is a tombstone left when a token is
	// revoked. It stops an operation in flight on that token from publishing
	// successors.
	RevokedTokenPrefix = "oauth:revoked:tok:"
	// RevokedFamilyPrefix + family id marks a revoked grant: none of its tokens
	// may be written, refreshed, extended or accepted.
	RevokedFamilyPrefix = "oauth:revoked:fam:"
	// RefreshClaimPrefix + sha256(refresh token) holds the claim of the refresh
	// in flight on that token: the value is the random id of the attempt that
	// owns it, and the key expires on its own (RefreshClaimTTL).
	RefreshClaimPrefix = "oauth:refresh_claim:"
	// FamilyPrefix + family id is the record of a grant, a Redis hash with the
	// grant's current refresh token ("rt"), that token's sha256 ("rth", which
	// names its claim) and its current access token ("at"). Revocation uses it
	// to delete the current tokens without help from whichever refresh may be
	// running.
	FamilyPrefix = "oauth:family:"
	// TokenFamilyPrefix + sha256(token) maps a refresh or access token to the
	// grant it belongs to. It outlives the token's own record (it lasts as long
	// as the token could have), so a token that was already rotated away still
	// leads revocation to the grant, and with it to the tokens that replaced it.
	TokenFamilyPrefix = "oauth:tokfam:"
	// AttemptOverPrefix + attempt id is left when a refresh attempt gives its claim
	// up. A copy of that attempt's claim command that arrives late (a command the
	// network delayed past the client's retry) must not take the claim back, or
	// it would block the token, or let a late copy of the attempt's publish
	// through.
	AttemptOverPrefix = "oauth:attempt_over:"
	// RotationPrefix + sha256(refresh token) records the outcome of that token's
	// rotation: the owner of the claim and the successors it published. A
	// publish that runs twice (a lost reply, retried by the client library)
	// finds it and answers like the first run.
	RotationPrefix = "oauth:rotation:"
)

// Lifetimes of the revocation records and the in-flight claim.
const (
	// RefreshClaimTTL bounds how long a refresh may hold a claim; a crashed
	// pod's claim expires on its own. A refresh that is still running when its
	// claim expires can no longer publish (the publish checks the claim is its
	// own).
	RefreshClaimTTL = 120 * time.Second
	// RevokedTokenTTL covers any refresh that can be in flight when its token is
	// revoked (RefreshClaimTTL plus slack).
	RevokedTokenTTL = time.Hour
	// RevokedFamilyTTL outlives every token a family can hold when it is
	// revoked: a refresh token (RefreshTTL) or an access token with its grace
	// period.
	RevokedFamilyTTL = (RefreshTTL + TokenTTL + TokenGracePeriod) * time.Second
	// AttemptOverTTL is how long a finished attempt is remembered: longer than a
	// packet can be delayed and retransmitted by TCP.
	AttemptOverTTL = 15 * time.Minute
	// RotationRecordTTL is how long a rotation's outcome is kept for a retried
	// publish to find; it only has to outlast the client library's retries.
	RotationRecordTTL = 5 * time.Minute
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
