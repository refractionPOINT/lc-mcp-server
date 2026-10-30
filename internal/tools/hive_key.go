package tools

import (
	"errors"
	"fmt"
)

// ValidateHiveRecordKey refuses a hive record key that cannot safely be one
// segment of a request path.
//
// Keys are put into paths like hive/<hive>/<partition>/<key>/data, escaped with
// url.PathEscape, which leaves "." and ".." unchanged. A key of ".." would make
// the request hive/<hive>/<partition>/../data, which anything that resolves dot
// segments between this server and the API (a proxy, a gateway) turns into a
// different route. Empty is refused too: the SDK refuses it, and a hand-built
// path would otherwise lose a segment.
//
// Every place that puts a record key into a path goes through this check, either
// directly or through the hive package's Client.
func ValidateHiveRecordKey(key string) error {
	switch key {
	case "":
		return errors.New("record key is required")
	case ".", "..":
		return fmt.Errorf("record key %q is not allowed: it is a path segment, not a name", key)
	}
	return nil
}
