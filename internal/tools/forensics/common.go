package forensics

import (
	"context"
	"fmt"

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
// Note: SDK doesn't have Sensor() method yet - needs to be added
func getSensor(ctx context.Context, sensorID string) (interface{}, error) {
	_, err := getOrganization(ctx)
	if err != nil {
		return nil, err
	}

	// TODO: SDK needs org.Sensor(sid) method
	// For now, return a placeholder
	return nil, fmt.Errorf("SDK does not yet have org.Sensor() method - needs to be added to go-limacharlie")
}
