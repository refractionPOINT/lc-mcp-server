package tools

import (
	"context"
	"fmt"
	"log/slog"

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
