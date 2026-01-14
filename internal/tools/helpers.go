package tools

import (
	"context"
	"fmt"
	"log/slog"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

// LCQLValidator defines the interface for LCQL query validation.
// This interface enables mocking for testing.
type LCQLValidator interface {
	ValidateLCQLQuery(query string) (*lc.ValidationResponse, error)
}

// ExtractAndValidateSID extracts and validates a sensor ID from tool arguments.
//
// Parameters:
//   - args: Tool arguments map containing the sensor ID
//
// Returns:
//   - string: The validated sensor ID
//   - error: Error if validation fails
func ExtractAndValidateSID(args map[string]interface{}) (string, error) {
	sid, ok := args["sid"].(string)
	if !ok || sid == "" {
		return "", fmt.Errorf("sid parameter is required")
	}

	// Validate SID format (must be UUID)
	if err := auth.ValidateSID(sid); err != nil {
		return "", fmt.Errorf("invalid SID: %w", err)
	}

	return sid, nil
}

// HandleOIDSwitch handles the optional OID parameter for UID mode
// Returns the updated context and any error
func HandleOIDSwitch(ctx context.Context, args map[string]interface{}, logger *slog.Logger) (context.Context, error) {
	if oidParam, ok := args["oid"].(string); ok && oidParam != "" {
		return auth.WithOID(ctx, oidParam, logger)
	}
	return ctx, nil
}

// LCQLValidationResult contains the full result of an LCQL query validation.
type LCQLValidationResult struct {
	// Valid indicates if the query syntax is valid
	Valid bool
	// Error contains the validation error message if validation failed
	Error string
	// NumEvals contains the estimated number of evaluation operations
	NumEvals int
	// NumEvents contains the estimated number of events to process
	NumEvents int
	// EvalTime contains the estimated evaluation time in seconds
	EvalTime float64
}

// ValidateLCQLQuery validates an LCQL query using the LimaCharlie API.
// Returns a simple bool/string for quick validation checks.
//
// Parameters:
//   - validator: Any type implementing LCQLValidator (e.g., *lc.Organization)
//   - query: The LCQL query string to validate
//
// Returns:
//   - bool: true if the query is valid, false otherwise
//   - string: error message if validation failed, empty string if valid
func ValidateLCQLQuery(validator LCQLValidator, query string) (bool, string) {
	result := ValidateLCQLQueryFull(validator, query)
	return result.Valid, result.Error
}

// ValidateLCQLQueryFull validates an LCQL query and returns full validation details.
// Use this when you need estimate information in addition to validation status.
//
// Parameters:
//   - validator: Any type implementing LCQLValidator (e.g., *lc.Organization)
//   - query: The LCQL query string to validate
//
// Returns:
//   - *LCQLValidationResult: Full validation result including estimates
func ValidateLCQLQueryFull(validator LCQLValidator, query string) *LCQLValidationResult {
	if query == "" {
		return &LCQLValidationResult{
			Valid: false,
			Error: "query is empty",
		}
	}

	// Use SDK's LCQL validation via replay service
	resp, err := validator.ValidateLCQLQuery(query)
	if err != nil {
		return &LCQLValidationResult{
			Valid: false,
			Error: fmt.Sprintf("validation error: %v", err),
		}
	}

	// Check if validation found an error
	if resp.Error != "" {
		return &LCQLValidationResult{
			Valid:     false,
			Error:     resp.Error,
			NumEvals:  resp.NumEvals,
			NumEvents: resp.NumEvents,
			EvalTime:  resp.EvalTime,
		}
	}

	return &LCQLValidationResult{
		Valid:     true,
		NumEvals:  resp.NumEvals,
		NumEvents: resp.NumEvents,
		EvalTime:  resp.EvalTime,
	}
}
