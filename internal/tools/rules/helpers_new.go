package rules

import "fmt"

// toStringSlice converts an interface{} (typically decoded JSON) into a []string.
// It accepts nil (returns an empty slice), []string, and []interface{} of strings.
func toStringSlice(v interface{}) ([]string, error) {
	if v == nil {
		return []string{}, nil
	}
	switch t := v.(type) {
	case []string:
		return t, nil
	case []interface{}:
		out := make([]string, 0, len(t))
		for i, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("element %d is not a string", i)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected an array of strings")
	}
}
