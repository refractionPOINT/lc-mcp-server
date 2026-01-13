package forensics

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// getSensor retrieves a sensor by ID from the organization and returns a cleanup function.
//
// IMPORTANT: The caller MUST call the cleanup function when done to shut down any
// Spout connections. Use: defer cleanup()
//
// This function generates a unique investigation ID for each request.
// The SDK cache returns a fresh Organization object (without a Spout attached)
// to prevent Spout reuse issues. If Spouts were shared across requests with
// different investigation IDs, responses would be filtered incorrectly at the
// WebSocket level and never arrive, causing 10-minute timeouts.
//
// See sdk_cache.go for details on the caching strategy.
func getSensor(ctx context.Context, sensorID string) (*lc.Sensor, func(), error) {
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return nil, nil, err
	}

	// Set investigation ID for interactive mode
	// Each request gets a unique ID to track responses through the WebSocket Spout
	org = org.WithInvestigationID(uuid.New().String())

	sensor := org.GetSensor(sensorID)
	if sensor == nil {
		org.Close() // Clean up since we won't return a cleanup function
		return nil, nil, fmt.Errorf("sensor not found: %s", sensorID)
	}

	// Return cleanup function that closes the org (and its Spout if created)
	return sensor, func() { org.Close() }, nil
}
