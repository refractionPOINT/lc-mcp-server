package investigation

import "fmt"

// The engine owns inferred value validation; reject unknown keys and malformed
// arrays here before making a remote request.
func validateRunTrust(v map[string]any) error {
	for k, value := range v {
		max := 100
		if k == "lookups" {
			max = 64
		} else if k != "values" {
			return fmt.Errorf("unknown trust key %q", k)
		}
		list, ok := value.([]any)
		if !ok {
			return fmt.Errorf("trust.%s must be an array of strings", k)
		}
		if len(list) > max {
			return fmt.Errorf("trust.%s exceeds %d entries", k, max)
		}
		for _, x := range list {
			s, ok := x.(string)
			if !ok || s == "" {
				return fmt.Errorf("trust.%s entries must be nonempty strings", k)
			}
		}
	}
	return nil
}
