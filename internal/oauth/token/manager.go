package token

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/firebase"
	"github.com/refractionpoint/lc-mcp-go/internal/oauth/state"
	"log/slog"
)

// JWTExchangeFunc is the function signature for exchanging Firebase tokens for LimaCharlie JWTs
type JWTExchangeFunc func(firebaseIDToken, oid string, logger *slog.Logger) (string, error)

// Manager manages OAuth token validation and lifecycle
type Manager struct {
	stateManager   *state.Manager
	firebaseClient firebase.ClientInterface
	logger         *slog.Logger
	jwtExchange    JWTExchangeFunc
}

// ValidationResult represents the result of token validation
type ValidationResult struct {
	Valid                bool
	UID                  string
	FirebaseIDToken      string
	FirebaseRefreshToken string
	LimaCharlieJWT       string // JWT exchanged from Firebase token for LimaCharlie API
	Scope                string
	// Resource is the canonical resource (audience) the token is bound to;
	// empty for a legacy token issued before resource binding existed.
	Resource  string
	Error     string
	Refreshed bool
	// AudienceMismatch is set when Valid is false only because the token is
	// bound to a resource that does not cover the request.
	AudienceMismatch bool
	// Transient is set when Valid is false because a backend (Firebase, the
	// JWT service, Redis) failed, not because the token is dead. Callers must
	// not send the client back through sign-in for it: a retry may succeed,
	// and a token that really is dead is rejected as expired once its TTL
	// runs out.
	Transient bool
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
	Aud       string `json:"aud,omitempty"` // Resource (audience) the token is bound to, when known
}

// NewManager creates a new OAuth token manager
func NewManager(stateManager *state.Manager, firebaseClient firebase.ClientInterface, logger *slog.Logger) *Manager {
	return &Manager{
		stateManager:   stateManager,
		firebaseClient: firebaseClient,
		logger:         logger,
		jwtExchange:    auth.ExchangeFirebaseTokenForJWT, // Default to real implementation
	}
}

// WithJWTExchange sets a custom JWT exchange function (useful for testing)
func (m *Manager) WithJWTExchange(fn JWTExchangeFunc) *Manager {
	m.jwtExchange = fn
	return m
}

// ErrInvalidTarget marks a resource (RFC 8707) that the token being issued or
// refreshed may not have. The token endpoint answers it with "invalid_target".
var ErrInvalidTarget = errors.New("invalid_target")

// ErrClientMismatch marks a refresh presented by a client other than the one
// the refresh token was issued to (or by none, when the token is bound). The
// token endpoint answers it with "invalid_grant".
var ErrClientMismatch = errors.New("refresh token was issued to a different client")

// ErrRefreshInFlight marks a refresh token that is being refreshed by another
// request right now, or that is held by a revocation that could not be confirmed
// (until its claim runs out). That request either consumes the token or gives it
// up, so a retry a moment later gets a definite answer. The token endpoint
// answers it like any refused refresh token.
var ErrRefreshInFlight = errors.New("refresh token is being refreshed by another request")

// ErrRefreshRevoked marks a refresh whose token (or grant) was revoked, before
// or while it ran. Nothing was issued.
var ErrRefreshRevoked = errors.New("refresh token was revoked")

// ErrRefreshSuperseded marks a refresh that lost the race to another refresh of
// the same token, which rotated it, when the successors cannot be handed to this
// request either: the client already used them, or the grant was revoked.
// Nothing was issued to this request. It is only reported when the rotation is
// proven; a claim that merely ran out is ErrRefreshClaimLost.
var ErrRefreshSuperseded = errors.New("refresh was superseded by another request")

// ErrRefreshClaimLost marks a refresh that outlived its claim on the token
// (it took longer than the claim lasts, or another refresh took the claim over
// and has not rotated the token, or a revocation that may not complete fenced the
// token). Nobody rotated or revoked the token, so nothing is wrong with it: the
// same refresh token can be tried again (and, while a fence holds it, is told it
// is in flight until the fence ends). It is a retryable failure, not a dead grant.
var ErrRefreshClaimLost = errors.New("refresh took longer than its claim on the refresh token lasts; retry")

// ErrRefreshTokenUnknown means the refresh token doesn't exist (never issued,
// expired, or already rotated).
var ErrRefreshTokenUnknown = errors.New("invalid or expired refresh token")

// ErrRefreshTokenDead means the upstream identity provider refused the
// grant behind the refresh token, so the user must sign in again.
var ErrRefreshTokenDead = errors.New("the identity provider refused the refresh")

// IsDeadRefresh reports whether a RefreshAccessToken error means the refresh
// token can never succeed (the client must sign in again), as opposed to a
// transient backend failure after which the same refresh token may be retried.
// Losing a race to a concurrent refresh of the same token (ErrRefreshInFlight)
// is transient: if the other refresh fails, the token is still valid, and if
// it succeeded a retry is handed its successors while the refresh grace window
// lasts and reports the token as unknown after it.
func IsDeadRefresh(err error) bool {
	for _, dead := range []error{ErrRefreshTokenUnknown, ErrRefreshTokenDead, ErrRefreshRevoked, ErrRefreshSuperseded, ErrClientMismatch, ErrInvalidTarget} {
		if errors.Is(err, dead) {
			return true
		}
	}
	return false
}

// MaxClientIDLen bounds a client_id we are willing to bind a token to.
const MaxClientIDLen = 2048

// AudienceCheck decides whether a token bound to tokenResource ("" for a
// legacy token) may be used for the request at hand. A non-nil error rejects
// the token with that message.
type AudienceCheck func(tokenResource string) error

// ResourceResolver chooses the resource of the tokens issued by a refresh,
// given the resource the refresh token is bound to ("" for a legacy one). It
// returns an error wrapping ErrInvalidTarget to refuse the refresh.
type ResourceResolver func(authorized string) (string, error)

// ValidateAccessToken validates an MCP access token and optionally refreshes Firebase tokens
// IMPORTANT: This method now also handles automatic MCP token lifetime extension
// to ensure tokens remain valid transparently for the client (e.g., Claude Code)
//
// It does not check which resource the token is bound to; request handlers
// use ValidateAccessTokenForAudience.
func (m *Manager) ValidateAccessToken(ctx context.Context, accessToken string, autoRefresh bool) (*ValidationResult, error) {
	return m.ValidateAccessTokenForAudience(ctx, accessToken, autoRefresh, nil)
}

// ValidateAccessTokenForAudience is ValidateAccessToken for a request that
// must also be covered by the token's audience. The check runs before any
// refresh or lifetime extension, so a token presented at the wrong endpoint
// has no side effects. A nil check accepts any audience.
func (m *Manager) ValidateAccessTokenForAudience(ctx context.Context, accessToken string, autoRefresh bool, audience AudienceCheck) (*ValidationResult, error) {
	// Look up token in Redis
	tokenData, err := m.stateManager.GetAccessTokenData(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get token data: %w", err)
	}

	if tokenData == nil {
		m.logger.Debug("Access token not found")
		return &ValidationResult{
			Valid: false,
			Error: "invalid or expired access token",
		}, nil
	}

	// A revoked grant's tokens are dead even if a record outlived the
	// revocation (for instance one nobody could name when it ran).
	revoked, err := m.stateManager.IsFamilyRevoked(ctx, tokenData.FamilyID)
	if err != nil {
		return nil, fmt.Errorf("failed to check token revocation: %w", err)
	}
	if revoked {
		m.logger.Warn("Access token rejected: its grant was revoked", "uid", tokenData.UID)
		return &ValidationResult{
			Valid: false,
			Error: "invalid or expired access token",
		}, nil
	}

	if tokenData.Resource == "" {
		m.logger.Debug("Access token has no resource binding (legacy), accepting for every endpoint", "uid", tokenData.UID)
	}
	if audience != nil {
		if err := audience(tokenData.Resource); err != nil {
			m.logger.Warn("Access token rejected: audience mismatch", "uid", tokenData.UID, "resource", tokenData.Resource, "reason", err.Error())
			return &ValidationResult{
				Valid:            false,
				Error:            err.Error(),
				Resource:         tokenData.Resource,
				AudienceMismatch: true,
			}, nil
		}
	}

	now := time.Now().Unix()
	mcpTokenExpiresIn := tokenData.ExpiresAt - now

	// Check if MCP token is expired (within grace period, since we still have the data)
	if mcpTokenExpiresIn <= 0 {
		// Token is expired but still in grace period (we have the data)
		// Check if we're within the grace period for auto-refresh
		if mcpTokenExpiresIn > -state.TokenGracePeriod && autoRefresh && tokenData.FirebaseRefreshToken != "" {
			// SECURITY: Check extension limits before allowing recovery
			if tokenData.ExtensionCount >= state.MaxTokenExtensions {
				m.logger.Warn("Token extension limit reached, forcing re-authentication",
					"uid", tokenData.UID,
					"extension_count", tokenData.ExtensionCount,
					"max_extensions", state.MaxTokenExtensions)
				return &ValidationResult{
					Valid: false,
					Error: "token extension limit reached, please re-authenticate",
				}, nil
			}

			m.logger.Info("MCP access token expired but within grace period, auto-extending...",
				"expired_ago_seconds", -mcpTokenExpiresIn,
				"uid", tokenData.UID,
				"extension_count", tokenData.ExtensionCount)

			// Extend MCP token lifetime by another TokenTTL
			newExpiresAt := now + int64(state.TokenTTL)

			// First refresh Firebase token since it's likely expired too
			newIDToken, newFBExpiresAt, err := m.firebaseClient.RefreshIDToken(ctx, tokenData.FirebaseRefreshToken)
			if err != nil {
				m.logger.Error("Failed to refresh Firebase ID token during MCP token extension", "error", err, "uid", tokenData.UID)
				return &ValidationResult{
					Valid:     false,
					Error:     fmt.Sprintf("token expired and refresh failed: %v", err),
					Transient: true,
				}, nil
			}

			// Update both Firebase tokens AND MCP token expiration
			tokenData.FirebaseIDToken = newIDToken
			tokenData.FirebaseExpiresAt = newFBExpiresAt
			tokenData.ExpiresAt = newExpiresAt
			tokenData.ExtensionCount++
			tokenData.LastExtendedAt = now

			updated, err := m.stateManager.UpdateAccessToken(ctx, tokenData)
			if err != nil {
				m.logger.Error("Failed to extend MCP token lifetime", "error", err, "uid", tokenData.UID)
				return &ValidationResult{
					Valid:     false,
					Error:     "failed to extend token lifetime",
					Transient: true,
				}, nil
			}
			if !updated {
				// Revoked (or expired) while we were refreshing: the update is
				// conditional, so nothing was written and the token stays dead.
				m.logger.Warn("MCP token was revoked during lifetime extension; not extended", "uid", tokenData.UID)
				return &ValidationResult{
					Valid: false,
					Error: "invalid or expired access token",
				}, nil
			}

			m.logger.Info("Successfully extended MCP token lifetime (grace period recovery)",
				"uid", tokenData.UID,
				"new_expires_at", newExpiresAt,
				"new_fb_expires_at", newFBExpiresAt,
				"extension_count", tokenData.ExtensionCount,
				"max_extensions", state.MaxTokenExtensions)

			// Exchange refreshed Firebase token for LimaCharlie JWT
			limaCharlieJWT, err := m.jwtExchange(newIDToken, "-", m.logger)
			if err != nil {
				m.logger.Error("Failed to exchange Firebase token for LimaCharlie JWT", "error", err, "uid", tokenData.UID)
				return &ValidationResult{
					Valid:     false,
					Error:     fmt.Sprintf("JWT exchange failed: %v", err),
					Transient: true,
				}, nil
			}

			return &ValidationResult{
				Valid:                true,
				UID:                  tokenData.UID,
				FirebaseIDToken:      newIDToken,
				FirebaseRefreshToken: tokenData.FirebaseRefreshToken,
				LimaCharlieJWT:       limaCharlieJWT,
				Scope:                tokenData.Scope,
				Resource:             tokenData.Resource,
				Refreshed:            true,
			}, nil
		}

		// Token expired and either outside grace period or refresh not available
		m.logger.Debug("Access token expired beyond grace period",
			"expired_ago_seconds", -mcpTokenExpiresIn)
		return &ValidationResult{
			Valid: false,
			Error: "access token expired",
		}, nil
	}

	// Check if MCP token needs proactive refresh (before expiration)
	mcpNeedsRefresh := mcpTokenExpiresIn < int64(state.TokenRefreshBuffer)

	// Check if Firebase token needs refresh
	firebaseExpiresIn := tokenData.FirebaseExpiresAt - now
	firebaseNeedsRefresh := firebaseExpiresIn < 300 // 5 minutes

	// Proactively refresh if either token needs it
	needsRefresh := (mcpNeedsRefresh || firebaseNeedsRefresh) && autoRefresh && tokenData.FirebaseRefreshToken != ""

	// SECURITY: Check extension limits before proactive MCP token extension
	if mcpNeedsRefresh && tokenData.ExtensionCount >= state.MaxTokenExtensions {
		m.logger.Warn("Token extension limit reached, not extending further",
			"uid", tokenData.UID,
			"extension_count", tokenData.ExtensionCount,
			"max_extensions", state.MaxTokenExtensions,
			"expires_in", mcpTokenExpiresIn)
		// Don't extend MCP token, but still allow Firebase refresh for the remaining lifetime
		mcpNeedsRefresh = false
		needsRefresh = firebaseNeedsRefresh && autoRefresh && tokenData.FirebaseRefreshToken != ""
	}

	if needsRefresh {
		if mcpNeedsRefresh {
			m.logger.Info("MCP access token expiring soon, proactively refreshing...",
				"mcp_expires_in", mcpTokenExpiresIn,
				"firebase_expires_in", firebaseExpiresIn,
				"uid", tokenData.UID,
				"extension_count", tokenData.ExtensionCount)
		} else {
			m.logger.Info("Firebase token expiring soon, refreshing...",
				"firebase_expires_in", firebaseExpiresIn,
				"uid", tokenData.UID)
		}

		// Refresh Firebase token
		newIDToken, newFBExpiresAt, err := m.firebaseClient.RefreshIDToken(ctx, tokenData.FirebaseRefreshToken)
		if err != nil {
			m.logger.Error("Failed to refresh Firebase ID token", "error", err, "uid", tokenData.UID)
			// Continue with existing token if refresh fails (might still be valid for a short time)
		} else {
			// Update Firebase tokens
			tokenData.FirebaseIDToken = newIDToken
			tokenData.FirebaseExpiresAt = newFBExpiresAt

			// Also extend MCP token lifetime if it's expiring soon
			if mcpNeedsRefresh {
				tokenData.ExpiresAt = now + int64(state.TokenTTL)
				tokenData.ExtensionCount++
				tokenData.LastExtendedAt = now
				m.logger.Info("Extending MCP token lifetime proactively",
					"uid", tokenData.UID,
					"new_expires_at", tokenData.ExpiresAt,
					"extension_count", tokenData.ExtensionCount,
					"max_extensions", state.MaxTokenExtensions)
			}

			// Store updated token data. The write is conditional: a token that
			// was revoked meanwhile is not brought back, and is refused here.
			updated, err := m.stateManager.UpdateAccessToken(ctx, tokenData)
			if err == nil && !updated {
				m.logger.Warn("Access token was revoked during refresh; not updated", "uid", tokenData.UID)
				return &ValidationResult{
					Valid: false,
					Error: "invalid or expired access token",
				}, nil
			}
			if err != nil {
				m.logger.Error("Failed to update access token", "error", err, "uid", tokenData.UID)
			} else {
				m.logger.Info("Successfully refreshed tokens",
					"uid", tokenData.UID,
					"fb_expires_at", newFBExpiresAt,
					"mcp_expires_at", tokenData.ExpiresAt,
					"extension_count", tokenData.ExtensionCount)

				// Exchange Firebase token for LimaCharlie JWT
				limaCharlieJWT, err := m.jwtExchange(newIDToken, "-", m.logger)
				if err != nil {
					m.logger.Error("Failed to exchange Firebase token for LimaCharlie JWT", "error", err, "uid", tokenData.UID)
					return &ValidationResult{
						Valid:     false,
						Error:     fmt.Sprintf("JWT exchange failed: %v", err),
						Transient: true,
					}, nil
				}

				return &ValidationResult{
					Valid:                true,
					UID:                  tokenData.UID,
					FirebaseIDToken:      newIDToken,
					FirebaseRefreshToken: tokenData.FirebaseRefreshToken,
					LimaCharlieJWT:       limaCharlieJWT,
					Scope:                tokenData.Scope,
					Resource:             tokenData.Resource,
					Refreshed:            true,
				}, nil
			}
		}
	}

	// Exchange Firebase token for LimaCharlie JWT
	// This matches Python SDK behavior in Manager.py _refreshJWT (lines 200-212)
	limaCharlieJWT, err := m.jwtExchange(tokenData.FirebaseIDToken, "-", m.logger)
	if err != nil {
		m.logger.Error("Failed to exchange Firebase token for LimaCharlie JWT", "error", err, "uid", tokenData.UID)
		return &ValidationResult{
			Valid:     false,
			Error:     fmt.Sprintf("JWT exchange failed: %v", err),
			Transient: true,
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
		Resource:             tokenData.Resource,
		Refreshed:            false,
	}, nil
}

// RefreshAccessToken issues a new access token using a refresh token
// SECURITY: Implements refresh token rotation to detect token theft
//
// The new tokens are bound to the resource chosen by resolve from the one the
// refresh token is bound to; a nil resolve keeps it unchanged. The resolver
// runs before anything is refreshed or rotated, so a refused request leaves
// the refresh token usable.
//
// The refresh token is bound to the client it was issued to, and clientID must
// be that client. The check runs before anything is refreshed or rotated.
//   - A different, non-empty client_id means someone holds the token and is not
//     the client it was issued to (a stolen token tried with guessed client
//     ids, or a client mixing up credentials). The token family is revoked (the
//     refresh token and its access token) and ErrClientMismatch is returned: a
//     secret that has shown up in the wrong hands is not left usable, and the
//     holder gets no further guesses. Only a presenter that already holds the
//     token can trigger this, so it hands nobody a new lever; the legitimate
//     user is asked to sign in again.
//   - A missing client_id on a bound token is accepted and the binding is kept:
//     refusing it would sign out every client that omits client_id on refresh.
//     It is logged so such clients can be identified.
//   - A legacy refresh token (issued before client binding) is accepted
//     whatever client_id is presented, and the rotated tokens are bound to the
//     one presented, so signed-in clients keep working and become bound on
//     their next refresh.
//
// Concurrency: a refresh first claims the token (see state.ClaimRefreshToken).
// The refresh record stays where it is for the whole refresh, so a revocation
// that arrives meanwhile always finds the token, its grant and its access
// token, and deletes them along with the claim. Exactly one refresh of a token
// proceeds; the others get ErrRefreshInFlight (or, once it has rotated, the
// successors through the grace window described below, and an unknown token
// after it). The successors are published in one atomic step that needs
// the claim to still be this refresh's own and nothing to have been revoked, so
// a refresh whose claim expired or was cleared issues nothing. That is only
// ErrRefreshClaimLost (retryable) unless the token is proven rotated or
// revoked: the dead-grant errors are reserved for those, and a token proven
// rotated is dead only if the successors cannot be handed to the request. A
// refresh that fails for any other reason just gives its claim up: the token was
// never removed, so the client can retry and stays signed in.
//
// A rotation whose reply never reached the client is not lost: for
// state.RotationRecordTTL the same client presenting the same refresh token is
// handed the successors that rotation issued (see recoverRotation for the
// security trade-off). That includes a refresh whose own claim ran out and was
// taken over by a retry that rotated the token: the slower request is not told
// the grant is dead, it goes through the same checked recovery and is handed what
// the retry issued.
func (m *Manager) RefreshAccessToken(ctx context.Context, refreshToken, clientID string, resolve ResourceResolver) (*TokenResponse, error) {
	claim, err := m.stateManager.ClaimRefreshToken(ctx, refreshToken)
	switch {
	case errors.Is(err, state.ErrRefreshInFlight):
		m.logger.Warn("Refresh token is being refreshed by another request")
		return nil, ErrRefreshInFlight
	case errors.Is(err, state.ErrTokenRevoked):
		m.logger.Warn("Refresh token was revoked")
		return nil, ErrRefreshRevoked
	case errors.Is(err, state.ErrRefreshTokenNotFound):
		// Rotated a moment ago, perhaps, with the reply lost on the way back.
		return m.recoverRotation(ctx, refreshToken, clientID, resolve)
	case err != nil:
		return nil, fmt.Errorf("failed to get refresh token data: %w", err)
	}
	refreshData := claim.Data

	// Unless the successors are published, the claim is given up on the way out
	// (only if it is still ours to give up). The cleanup outlives a cancelled
	// request.
	published := false
	keepClaim := false
	defer func() {
		if published || keepClaim {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		m.stateManager.ReleaseRefreshClaim(cleanup, claim)
	}()

	uid := refreshData.UID
	firebaseRefreshToken := refreshData.FirebaseRefreshToken
	scope := refreshData.Scope

	boundClientID := refreshData.ClientID
	switch {
	case boundClientID == "":
		m.logger.Debug("Refresh token has no client binding (legacy), binding it to the presenting client",
			"uid", uid, "client_bound", clientID != "")
		boundClientID = clientID
	case subtle.ConstantTimeCompare([]byte(boundClientID), []byte(clientID)) != 1:
		if clientID == "" {
			// Accepted, and the token stays bound: refusing would sign out any
			// client that omits client_id on refresh (OAuth 2.1 asks public
			// clients to send it, but not every client does). A thief gains
			// nothing over today by omitting it, while a wrong client_id is
			// still refused and revokes the token below.
			m.logger.Info("Refresh token presented without a client_id; accepting, binding kept", "uid", uid, "client_id", boundClientID)
			break
		}
		m.logger.Warn("Refresh refused: refresh token presented by a different client; revoking it",
			"uid", uid, "expected_client_id", boundClientID, "presented_client_id", clientID)
		if err := m.revokeAfterMismatch(ctx, claim.Token, claim.FamilyID); err != nil {
			// The grant may still be usable: the request gets no tokens, and a
			// backend error instead of invalid_grant so the situation is not
			// reported as settled. The claim stays in place (see
			// revokeAfterMismatch), so nobody else can refresh meanwhile.
			keepClaim = true
			return nil, err
		}
		return nil, ErrClientMismatch
	}

	resource := refreshData.Resource
	if resource == "" {
		m.logger.Debug("Refresh token has no resource binding (legacy)", "uid", uid)
	}
	if resolve != nil {
		var err error
		if resource, err = resolve(refreshData.Resource); err != nil {
			return nil, err
		}
	}

	// The family of the grant: the token's own, or the one the claim gave a
	// token from before families existed.
	familyID := claim.FamilyID

	// Refresh Firebase token first
	newFirebaseIDToken, newFirebaseExpiresAt, err := m.firebaseClient.RefreshIDToken(ctx, firebaseRefreshToken)
	if err != nil {
		if errors.Is(err, firebase.ErrRefreshTokenRejected) {
			return nil, fmt.Errorf("%w: %w", ErrRefreshTokenDead, err)
		}
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

	accessTokenData := state.NewAccessTokenData(
		newAccessToken,
		uid,
		newFirebaseIDToken,
		firebaseRefreshToken,
		newFirebaseExpiresAt,
		scope,
		state.TokenTTL,
	)
	accessTokenData.Resource = resource
	accessTokenData.ClientID = boundClientID
	accessTokenData.FamilyID = familyID

	refreshTokenData := state.NewRefreshTokenData(
		newRefreshToken,
		newAccessToken,
		uid,
		firebaseRefreshToken,
		scope,
	)
	refreshTokenData.Resource = resource
	refreshTokenData.ClientID = boundClientID
	refreshTokenData.FamilyID = familyID

	// Publish both successors and retire the old tokens in one atomic step,
	// refused if the claim is no longer ours or anything was revoked since.
	if err := m.stateManager.PublishRotation(ctx, claim, accessTokenData, refreshTokenData); err != nil {
		switch {
		case errors.Is(err, state.ErrTokenRevoked):
			m.logger.Warn("Refresh abandoned: the refresh token was revoked while it ran", "uid", uid)
			return nil, ErrRefreshRevoked
		case errors.Is(err, state.ErrAlreadyRotated):
			// Another request took the claim over and rotated the token while this
			// one ran. That is no reason to sign the client out: an immediate retry
			// of this very token would be handed the successors through the grace
			// window, so this request is handed them now, after the same checks
			// (client binding and revocation of the grant, resource). Only if that
			// is not possible, because the client already moved on to the successors
			// or the grant was revoked, is the token dead.
			m.logger.Warn("Refresh abandoned: another request rotated the refresh token while it ran; recovering its successors", "uid", uid)
			resp, recoverErr := m.recoverRotation(ctx, claim.Token, clientID, resolve)
			if errors.Is(recoverErr, ErrRefreshTokenUnknown) {
				return nil, ErrRefreshSuperseded
			}
			return resp, recoverErr
		case errors.Is(err, state.ErrClaimLost):
			// Not proven dead: the claim ran out (or was taken over) but the
			// token is still there, unrevoked and unrotated. The client retries.
			m.logger.Warn("Refresh abandoned: its claim on the refresh token was lost while it ran; the token is intact", "uid", uid)
			return nil, ErrRefreshClaimLost
		}
		return nil, fmt.Errorf("failed to store refreshed tokens: %w", err)
	}
	published = true

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

// maxMismatchRevokeAttempts bounds the in-request retries of the revocation a
// client mismatch triggers.
const maxMismatchRevokeAttempts = 3

var mismatchRevokeBackoff = 50 * time.Millisecond

// revokeAfterMismatch revokes the grant of a token that a wrong client presented,
// and only returns nil once the revocation is confirmed. familyID is the grant of
// the token, which the caller knows from the claim it holds or from the rotation
// record it read.
//
// A revocation that fails must not leave the token usable, or a thief gets
// another go and the owner's next refresh succeeds as if nothing happened. So:
//  1. The full revocation (one Lua script: tombstone, family marker, deletion of
//     the current tokens) is tried a few times in the request, since most Redis
//     failures are momentary. It revokes the grant by its id, so it never comes
//     back empty-handed because the token's own records or index are gone: a
//     revocation that found nothing is not a confirmation.
//  2. If it keeps failing, the family marker alone is written with a single
//     command (MarkFamilyRevoked). The marker is what every path checks (claims,
//     publishes, token validation and extension), so the grant is dead as soon as
//     it lands; the token records left over are inert and expire on their own.
//  3. If even that fails, the error is returned (a retryable backend error for
//     the wrong client's request) and the caller keeps the refresh claim it holds,
//     which blocks every refresh of the token until it expires on its own
//     (RefreshClaimTTL); the next presentation by anyone repeats this. On the
//     live path the claim is the token's own; for a rotated token presented
//     during the grace window it is the fence on the current successor (see
//     revokeAfterReplayMismatch).
//
// Why not a background retry or a separate pending marker: another pod could not
// see an in-process retry, and a marker written with a command that fails the
// same way as the revocation protects nothing the family marker does not. The
// claim (or the fence), by contrast, is taken before anything fails. This design
// adds no state: the confirmation is the family marker itself.
func (m *Manager) revokeAfterMismatch(ctx context.Context, token, familyID string) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	var err error
	for attempt := 0; attempt < maxMismatchRevokeAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt) * mismatchRevokeBackoff):
			case <-cleanup.Done():
			}
		}
		var outcome state.RevokeOutcome
		outcome, err = m.stateManager.RevokeTokenInFamily(cleanup, token, familyID)
		if err == nil && outcome != state.RevokedNothing {
			return nil
		}
		if err == nil {
			err = errors.New("the revocation found no grant to revoke")
		}
		m.logger.Warn("Failed to revoke the token family after client mismatch; retrying", "error", err, "attempt", attempt+1)
	}
	if markErr := m.stateManager.MarkFamilyRevoked(cleanup, familyID); markErr == nil {
		m.logger.Error("Revocation after client mismatch failed; the grant is marked revoked instead", "error", err)
		return nil
	} else {
		m.logger.Error("Could not revoke the token family after client mismatch", "error", err, "mark_error", markErr)
	}
	return fmt.Errorf("failed to revoke the grant after a client mismatch: %w", err)
}

// revokeAfterReplayMismatch is revokeAfterMismatch for a rotated refresh token
// that a wrong client presented during the grace window. The token itself is gone;
// what is worth protecting is the grant's current refresh token, its successor.
//
// On the live path the refresh claim on the presented token is held before the
// client is compared, and kept when the revocation cannot be confirmed, so that
// nobody refreshes meanwhile. Nothing is held here, so the same protection is
// built before the revocation is attempted: the successor is fenced
// (state.FenceFamily), which sets its claim to a revocation fence whoever owns it.
// The fence is kept when the revocation cannot be confirmed. For its lifetime:
//   - a refresh of the successor gets ErrRefreshInFlight, and so does anybody
//     presenting the rotated token with the right client id (recoverRotation), who
//     might be a thief trying client ids;
//   - a refresh already running on the successor cannot publish, because its claim
//     was replaced. It gets ErrRefreshClaimLost, which is retryable like any
//     refresh whose claim ran out: the token is intact, so the legitimate user is
//     not signed out by a revocation that did not happen, and the retry meets the
//     fence until it ends. If the revocation does land, that refresh is
//     ErrRefreshRevoked, like any refresh of a revoked grant.
//
// A confirmed revocation deletes the fence along with the successor; a grant that
// was only marked revoked leaves it to end on its own (every path refuses a revoked
// grant before looking at a claim).
//
// A claim would not do here. It is only granted to a token nobody holds, so it
// cannot hold a token whose refresh is in flight, and the helper that takes it
// gives it up when its reply is lost, although it may be in place. The fence has
// neither flaw: it replaces the claim whoever owns it, and it is never released
// here, only repeated, which is harmless. If the fence cannot be placed (Redis
// fails) the revocation is attempted anyway: it is still what the mismatch calls
// for, and the fence is only the fallback for when it fails.
//
// Residual: if the fence, every revocation attempt and the family marker all fail,
// nothing holds the grant and a refresh already running on it can publish. Nothing
// can be guaranteed when no protective write lands. The fence goes first because
// that is when Redis is the most likely to still be answering, and the next
// presentation by the wrong client repeats all of it.
func (m *Manager) revokeAfterReplayMismatch(ctx context.Context, rotatedToken string, rot *state.RotatedSuccessors) error {
	familyID := rot.Refresh.FamilyID

	// The fence outlives a cancelled request, like the revocation that follows.
	fenceCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	switch fenced, err := m.stateManager.FenceFamily(fenceCtx, familyID); {
	case err != nil:
		m.logger.Warn("Could not confirm the fence on the successor refresh token before revoking after a client mismatch; revoking anyway", "error", err)
	case !fenced:
		m.logger.Debug("Nothing to fence before revoking after a client mismatch: the grant has no current refresh token or is revoked already")
	}

	// If the revocation cannot be confirmed, its error comes back and the fence
	// stays: nobody refreshes the successor meanwhile.
	return m.revokeAfterMismatch(ctx, rotatedToken, familyID)
}

// recoverRotation answers a presentation of a refresh token that no longer
// exists. If it was rotated a moment ago, the committed rotation is handed back
// rather than lost: the Redis client retries a lost reply, but if every reply to
// a committed publish is lost the endpoint can only answer 503, and the client's
// retry with the token it still holds must not be told the token is dead. The
// same goes for a refresh that lost its claim to a retry which rotated the token.
//
// Within state.RotationRecordTTL of the rotation, the same client presenting the
// same refresh token gets the same successors (never a second family, nothing is
// minted). The usual conditions apply: the grant must not be revoked, the
// successors must still exist (a client that already refreshed with them has
// moved on and gets nothing), the client binding is enforced like on a live
// token (a different client_id revokes the grant, with the same protection when
// the revocation cannot be confirmed), and the resource requested must be the one
// the successors were issued for. While a refresh of the successors is in flight,
// or a revocation that could not be confirmed holds them (its fence), nothing is
// handed out (ErrRefreshInFlight).
//
// SECURITY (refresh grace): the rotated token is not restored, but for this
// short window a replay of it by a presenter that satisfies the client binding
// returns the pair the legitimate client was already issued. That weakens strict
// one-time use against a thief who captured the token and replays it within the
// window with the right client_id (or none); it is the standard trade-off of a
// refresh grace period, accepted so that a lost reply does not sign the user out.
func (m *Manager) recoverRotation(ctx context.Context, refreshToken, clientID string, resolve ResourceResolver) (*TokenResponse, error) {
	rot, err := m.stateManager.RotationSuccessors(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to look up the rotation of the refresh token: %w", err)
	}
	if rot == nil {
		m.logger.Warn("Refresh token not found or already used")
		return nil, ErrRefreshTokenUnknown
	}
	uid := rot.Refresh.UID

	if bound := rot.Refresh.ClientID; bound != "" && clientID != "" && subtle.ConstantTimeCompare([]byte(bound), []byte(clientID)) != 1 {
		m.logger.Warn("Replay of a rotated refresh token refused: presented by a different client; revoking the grant",
			"uid", uid, "expected_client_id", bound, "presented_client_id", clientID)
		if err := m.revokeAfterReplayMismatch(ctx, refreshToken, rot); err != nil {
			return nil, err
		}
		return nil, ErrClientMismatch
	}

	if resolve != nil {
		resource, err := resolve(rot.AuthorizedResource)
		if err != nil {
			return nil, err
		}
		if resource != rot.Refresh.Resource {
			return nil, fmt.Errorf("%w: the refresh was already completed for another resource", ErrInvalidTarget)
		}
	}

	if rot.SuccessorClaimed {
		m.logger.Warn("Refresh token was rotated moments ago, but its successor is being refreshed or held by a pending revocation; not handing out the successors", "uid", uid)
		return nil, ErrRefreshInFlight
	}

	expiresIn := int(rot.Access.ExpiresAt - time.Now().Unix())
	if expiresIn > state.TokenTTL {
		expiresIn = state.TokenTTL
	}
	if expiresIn < 1 {
		expiresIn = 1
	}
	m.logger.Warn("Refresh token was rotated moments ago; handing back the same successors (refresh grace)", "uid", uid)
	return &TokenResponse{
		AccessToken:  rot.Access.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: rot.Refresh.RefreshToken,
		Scope:        rot.Refresh.Scope,
	}, nil
}

// RevokeToken revokes a token and the grant it belongs to (RFC 7009).
//
// The token may be a refresh or an access token whatever the hint says (RFC
// 7009 asks the search to extend to every type); the hint is only logged. The
// grant is revoked in one atomic step: its refresh token, its access token and
// any refresh in flight on it are all gone, even when the token presented is one
// that was already rotated away. An unknown token is not an error (RFC 7009:
// the client is told success whether or not the token existed). An error means
// the backend failed, nothing is half done, and the caller must report the
// failure so the client retries.
//
// It never logs any part of the token: a prefix of a bearer token is part of
// a credential.
func (m *Manager) RevokeToken(ctx context.Context, token string, tokenTypeHint string) error {
	// The hint comes from an unauthenticated request and is only logged: log it
	// only when it is one of the two defined values.
	if tokenTypeHint != "access_token" && tokenTypeHint != "refresh_token" && tokenTypeHint != "" {
		tokenTypeHint = "other"
	}

	outcome, err := m.stateManager.RevokeToken(ctx, token)
	if err != nil {
		m.logger.Error("Failed to revoke token", "error", err, "token_type_hint", tokenTypeHint)
		return err
	}

	switch outcome {
	case state.RevokedRefreshToken:
		m.logger.Info("Revoked refresh token")
	case state.RevokedAccessToken:
		m.logger.Info("Revoked access token")
	case state.RevokedGrantByToken:
		m.logger.Info("Revoked the grant of a token that was already rotated away")
	case state.RevokedAlready:
		m.logger.Debug("Token was already revoked", "token_type_hint", tokenTypeHint)
	default:
		m.logger.Warn("Token not found for revocation (may already be revoked)", "token_type_hint", tokenTypeHint)
	}

	return nil
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

	// Check expiration, and that the grant has not been revoked
	isActive := tokenData.ExpiresAt > time.Now().Unix()
	if isActive {
		revoked, err := m.stateManager.IsFamilyRevoked(ctx, tokenData.FamilyID)
		if err != nil {
			return nil, fmt.Errorf("failed to check token revocation: %w", err)
		}
		isActive = !revoked
	}

	clientID := tokenData.ClientID
	if clientID == "" {
		clientID = "mcp" // token issued before client binding: client unknown
	}

	return &IntrospectionResponse{
		Active:    isActive,
		Scope:     tokenData.Scope,
		ClientID:  clientID,
		TokenType: "Bearer",
		Exp:       tokenData.ExpiresAt,
		Iat:       tokenData.CreatedAt,
		Sub:       tokenData.UID, // Firebase UID as subject
		Aud:       tokenData.Resource,
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
// Called after successful authorization to issue tokens. resource is the
// canonical resource the tokens are bound to; "" issues unbound (legacy) tokens.
// clientID is the client the authorization code was issued to; the tokens (and
// every rotation of the refresh token) are bound to it.
func (m *Manager) CreateTokenResponse(ctx context.Context, uid, firebaseIDToken, firebaseRefreshToken string, firebaseExpiresAt int64, scope, resource, clientID string) (*TokenResponse, error) {
	// Generate MCP tokens
	accessToken, err := m.stateManager.GenerateAccessToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := m.stateManager.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Every sign-in starts a new family; rotations carry it.
	familyID, err := m.stateManager.GenerateFamilyID()
	if err != nil {
		return nil, err
	}

	accessTokenData := state.NewAccessTokenData(
		accessToken,
		uid,
		firebaseIDToken,
		firebaseRefreshToken,
		firebaseExpiresAt,
		scope,
		state.TokenTTL,
	)
	accessTokenData.Resource = resource
	accessTokenData.ClientID = clientID
	accessTokenData.FamilyID = familyID

	refreshTokenData := state.NewRefreshTokenData(
		refreshToken,
		accessToken,
		uid,
		firebaseRefreshToken,
		scope,
	)
	refreshTokenData.Resource = resource
	refreshTokenData.ClientID = clientID
	refreshTokenData.FamilyID = familyID

	// Both tokens, the family record and the indices that let revocation find
	// them are stored in one atomic step.
	if err := m.stateManager.IssueTokens(ctx, accessTokenData, refreshTokenData); err != nil {
		return nil, fmt.Errorf("failed to store tokens: %w", err)
	}

	m.logger.Info("Successfully created new token pair", "uid", uid, "scope", scope, "resource", resource)

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    state.TokenTTL,
		RefreshToken: refreshToken,
		Scope:        scope,
	}, nil
}
