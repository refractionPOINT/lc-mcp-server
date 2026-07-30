package tools

import (
	"fmt"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// SensorIsolation is the response of GET /{sid}/isolation.
type SensorIsolation struct {
	// IsIsolated is the isolation the sensor has actually applied.
	IsIsolated bool `json:"is_isolated"`
	// ShouldIsolate is the isolation requested for the sensor. It leads
	// IsIsolated while an isolate/rejoin request is still in flight.
	ShouldIsolate bool `json:"should_isolate"`
}

// GetSensorIsolation reads a sensor's isolation status.
//
// The sensor record cannot be used for this: the platform renames the record's
// isolation field to is_isolated on the way out, while the SDK's
// Sensor.IsIsolated is tagged json:"isolated", so it never unmarshals and
// always reads false. The dedicated isolation endpoint returns both flags.
func GetSensorIsolation(org *lc.Organization, sid string) (SensorIsolation, error) {
	isolation := SensorIsolation{}
	// The route is /{sid}/isolation, with no path prefix.
	if err := org.GenericGETRequest(fmt.Sprintf("%s/isolation", sid), nil, &isolation); err != nil {
		return isolation, err
	}
	return isolation, nil
}
