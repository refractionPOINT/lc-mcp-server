package tools

import (
	"context"
	"fmt"
	"log/slog"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

// ExtractAndValidateSID extracts and validates a sensor ID from tool arguments
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

// ValidateLCQLQuery validates an LCQL query using the LimaCharlie API.
//
// Parameters:
//   - org: The LimaCharlie organization to validate against
//   - query: The LCQL query string to validate
//
// Returns:
//   - bool: true if the query is valid, false otherwise
//   - string: error message if validation failed, empty string if valid
func ValidateLCQLQuery(org *lc.Organization, query string) (bool, string) {
	if query == "" {
		return false, "query is empty"
	}

	// Use SDK's LCQL validation via replay service
	resp, err := org.ValidateLCQLQuery(query)
	if err != nil {
		return false, fmt.Sprintf("validation error: %v", err)
	}

	// Check if validation found an error
	if resp.Error != "" {
		return false, resp.Error
	}

	return true, ""
}
