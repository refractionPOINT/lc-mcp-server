package forensics

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

// getOrganization retrieves the organization from the context
func getOrganization(ctx context.Context) (*lc.Organization, error) {
	cache, err := auth.GetSDKCache(ctx)
	if err != nil {
		return nil, err
	}
	return cache.GetFromContext(ctx)
}

// getSensor retrieves a sensor by ID from the organization
//
// IMPORTANT: This function generates a unique investigation ID for each request.
// The SDK cache returns a fresh Organization object (without a Spout attached)
// to prevent Spout reuse issues. If Spouts were shared across requests with
// different investigation IDs, responses would be filtered incorrectly at the
// WebSocket level and never arrive, causing 10-minute timeouts.
//
// See sdk_cache.go for details on the caching strategy.
func getSensor(ctx context.Context, sensorID string) (*lc.Sensor, error) {
	org, err := getOrganization(ctx)
	if err != nil {
		return nil, err
	}

	// Set investigation ID for interactive mode
	// Each request gets a unique ID to track responses through the WebSocket Spout
	org = org.WithInvestigationID(uuid.New().String())

	sensor := org.GetSensor(sensorID)
	if sensor == nil {
		return nil, fmt.Errorf("sensor not found: %s", sensorID)
	}

	return sensor, nil
}
