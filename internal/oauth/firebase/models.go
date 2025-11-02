package firebase

import "fmt"

// CreateAuthURIRequest represents the Firebase createAuthUri request
type CreateAuthURIRequest struct {
	ProviderID   string `json:"providerId"`
	ContinueURI  string `json:"continueUri"`
	AuthFlowType string `json:"authFlowType"`
	OAuthScope   string `json:"oauthScope"`
}

// CreateAuthURIResponse represents the Firebase createAuthUri response
type CreateAuthURIResponse struct {
	SessionID string `json:"sessionId"`
	AuthURI   string `json:"authUri"`
}

// SignInWithIdpRequest represents the Firebase signInWithIdp request
type SignInWithIdpRequest struct {
	RequestURI         string `json:"requestUri"`
	PostBody           string `json:"postBody"`
	SessionID          string `json:"sessionId"`
	ReturnSecureToken  bool   `json:"returnSecureToken"`
	ReturnIdpCredential bool   `json:"returnIdpCredential"`
}

// SignInWithIdpResponse represents the Firebase signInWithIdp response
type SignInWithIdpResponse struct {
	IDToken      string `json:"idToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    string `json:"expiresIn"`
	LocalID      string `json:"localId"`
	Email        string `json:"email"`
	DisplayName  string `json:"displayName"`
	// MFA fields
	MFAPendingCredential string      `json:"mfaPendingCredential,omitempty"`
	MFAInfo              []MFAMethod `json:"mfaInfo,omitempty"`
	PendingToken         string      `json:"pendingToken,omitempty"`
	NeedConfirmation     bool        `json:"needConfirmation,omitempty"`
}

// MFAMethod represents an MFA enrollment method
type MFAMethod struct {
	MFAEnrollmentID string `json:"mfaEnrollmentId"`
	DisplayName     string `json:"displayName"`
	EnrolledAt      string `json:"enrolledAt"`
}

// RefreshTokenRequest represents the Firebase token refresh request
type RefreshTokenRequest struct {
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshTokenResponse represents the Firebase token refresh response
type RefreshTokenResponse struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    string `json:"expires_in"`
	TokenType    string `json:"token_type"`
	UserID       string `json:"user_id"`
}

// FinalizeMFARequest represents the Firebase MFA finalization request
type FinalizeMFARequest struct {
	MFAPendingCredential string                   `json:"mfaPendingCredential"`
	MFAEnrollmentID      string                   `json:"mfaEnrollmentId"`
	TOTPVerificationInfo *TOTPVerificationInfo    `json:"totpVerificationInfo,omitempty"`
}

// TOTPVerificationInfo represents TOTP verification data
type TOTPVerificationInfo struct {
	VerificationCode string `json:"verificationCode"`
}

// FinalizeMFAResponse represents the Firebase MFA finalization response
type FinalizeMFAResponse struct {
	IDToken      string `json:"idToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    string `json:"expiresIn"`
	LocalID      string `json:"localId"`
}

// FirebaseError represents a Firebase API error
type FirebaseError struct {
	ErrorDetails struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Errors  []struct {
			Message string `json:"message"`
			Domain  string `json:"domain"`
			Reason  string `json:"reason"`
		} `json:"errors"`
	} `json:"error"`
}

// Error implements the error interface
func (e *FirebaseError) Error() string {
	return fmt.Sprintf("Firebase error %d: %s", e.ErrorDetails.Code, e.ErrorDetails.Message)
}

// MFARequiredError indicates that MFA verification is required
type MFARequiredError struct {
	MFAPendingCredential string
	MFAEnrollmentID      string
	DisplayName          string
	LocalID              string
	Email                string
	PendingToken         string
}

func (e *MFARequiredError) Error() string {
	return "MFA verification required"
}
