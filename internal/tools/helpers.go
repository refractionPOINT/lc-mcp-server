package tools

import (
	"context"
	"fmt"
	"log/slog"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

// LCQLValidator defines the interface for LCQL query validation and billing estimation.
// This interface enables mocking for testing.
type LCQLValidator interface {
	// ValidateLCQLQuery validates LCQL query syntax without executing it.
	ValidateLCQLQuery(query string) (*lc.ValidationResponse, error)
	// EstimateLCQLQueryBilling returns billing estimates for an LCQL query.
	EstimateLCQLQueryBilling(query string) (*lc.BillingEstimate, error)
	// ValidateAndEstimateLCQLQuery validates and estimates billing concurrently.
	ValidateAndEstimateLCQLQuery(query string) (*lc.QueryValidationResult, error)
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

// LCQLValidationResult contains the full result of an LCQL query validation and billing estimate.
type LCQLValidationResult struct {
	// Valid indicates if the query syntax is valid
	Valid bool
	// Error contains the validation error message if validation failed
	Error string

	// D&R validation fields (from ValidationResponse)
	// NumEvals contains the estimated number of evaluation operations
	NumEvals int
	// NumEvents contains the estimated number of events to process
	NumEvents int
	// EvalTime contains the estimated evaluation time in seconds
	EvalTime float64

	// Billing estimate fields (from BillingEstimate)
	// BilledEvents is the estimated number of events that would be billed
	BilledEvents uint64
	// FreeEvents is the estimated number of events that would be free (not billed)
	FreeEvents uint64
	// EstimatedPriceUSD is the estimated cost in USD (converted from cents)
	EstimatedPriceUSD float64
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

// ValidateLCQLQueryFull validates an LCQL query and returns full validation details including billing estimates.
// This uses the concurrent ValidateAndEstimateLCQLQuery API for better performance.
//
// Parameters:
//   - validator: Any type implementing LCQLValidator (e.g., *lc.Organization)
//   - query: The LCQL query string to validate
//
// Returns:
//   - *LCQLValidationResult: Full validation result including billing estimates
func ValidateLCQLQueryFull(validator LCQLValidator, query string) *LCQLValidationResult {
	if query == "" {
		return &LCQLValidationResult{
			Valid: false,
			Error: "query is empty",
		}
	}

	// Use SDK's concurrent validation + billing estimation
	resp, err := validator.ValidateAndEstimateLCQLQuery(query)
	if err != nil {
		return &LCQLValidationResult{
			Valid: false,
			Error: fmt.Sprintf("validation error: %v", err),
		}
	}

	// Check if validation found an error
	if resp.Validation.Error != "" {
		return &LCQLValidationResult{
			Valid: false,
			Error: resp.Validation.Error,
		}
	}

	result := &LCQLValidationResult{
		Valid: true,
	}

	// Include D&R validation fields if available (from ValidationResponse)
	if resp.Validation != nil {
		result.NumEvals = resp.Validation.NumEvals
		result.NumEvents = resp.Validation.NumEvents
		result.EvalTime = resp.Validation.EvalTime
	}

	// Include billing estimate if available
	if resp.BillingEstimate != nil {
		result.BilledEvents = resp.BillingEstimate.BilledEvents
		result.FreeEvents = resp.BillingEstimate.FreeEvents
		// Convert cents to USD if currency is "USD cents"
		if resp.BillingEstimate.EstimatedPrice.Currency == "USD cents" {
			result.EstimatedPriceUSD = resp.BillingEstimate.EstimatedPrice.Price / 100.0
		} else {
			result.EstimatedPriceUSD = resp.BillingEstimate.EstimatedPrice.Price
		}
	}

	return result
}

// EstimateLCQLQueryBilling returns only the billing estimate for an LCQL query.
// Use this when you only need billing information and the query has already been validated.
//
// Parameters:
//   - validator: Any type implementing LCQLValidator (e.g., *lc.Organization)
//   - query: The LCQL query string to estimate
//
// Returns:
//   - *lc.BillingEstimate: Billing estimate with BilledEvents, FreeEvents, and EstimatedPrice
//   - error: Error if estimation fails
func EstimateLCQLQueryBilling(validator LCQLValidator, query string) (*lc.BillingEstimate, error) {
	if query == "" {
		return nil, fmt.Errorf("query is empty")
	}

	return validator.EstimateLCQLQueryBilling(query)
}
