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
// request right now. That request either consumes the token or gives it up, so
// a retry a moment later gets a definite answer. The token endpoint answers it
// like any refused refresh token.
var ErrRefreshInFlight = errors.New("refresh token is being refreshed by another request")

// ErrRefreshRevoked marks a refresh whose token (or grant) was revoked, before
// or while it ran. Nothing was issued.
var ErrRefreshRevoked = errors.New("refresh token was revoked")

// ErrRefreshSuperseded marks a refresh that lost its claim on the token while
// it ran (it took longer than the claim lasts, or another refresh took over).
// Nothing was issued.
var ErrRefreshSuperseded = errors.New("refresh was superseded by another request")

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
// proceeds; the others get ErrRefreshInFlight (or, once it has rotated, an
// unknown token). The successors are published in one atomic step that needs
// the claim to still be this refresh's own and nothing to have been revoked, so
// a refresh whose claim expired or was cleared issues nothing. A refresh that
// fails for any other reason just gives its claim up: the token was never
// removed, so the client can retry and stays signed in.
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
		m.logger.Warn("Refresh token not found or already used")
		return nil, fmt.Errorf("invalid or expired refresh token")
	case err != nil:
		return nil, fmt.Errorf("failed to get refresh token data: %w", err)
	}
	refreshData := claim.Data

	// Unless the successors are published, the claim is given up on the way out
	// (only if it is still ours to give up). The cleanup outlives a cancelled
	// request.
	published := false
	defer func() {
		if published {
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
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if _, err := m.stateManager.RevokeToken(cleanup, claim.Token); err != nil {
			m.logger.Error("Failed to revoke the token family after client mismatch", "error", err, "uid", uid)
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
		case errors.Is(err, state.ErrClaimLost):
			m.logger.Warn("Refresh abandoned: its claim on the refresh token was lost while it ran", "uid", uid)
			return nil, ErrRefreshSuperseded
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
