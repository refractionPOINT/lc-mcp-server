package investigation

import (
	"fmt"
	"math"
	"strings"
)

// The argument readers refuse a value of the wrong type instead of dropping it: a silently ignored
// constraint (a sample list, a wait) would make the call do something other than what was asked.

func optString(args map[string]interface{}, name string) (string, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", name)
	}
	return s, nil
}

func optBool(args map[string]interface{}, name string) (bool, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be a boolean", name)
	}
	return b, nil
}

// optInt reads a whole number. The second result says whether the argument was given.
func optInt(args map[string]interface{}, name string) (int, bool, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return 0, false, nil
	}
	f, ok := v.(float64)
	if !ok || f != math.Trunc(f) || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false, fmt.Errorf("%s must be a whole number", name)
	}
	if f > math.MaxInt32 || f < math.MinInt32 {
		return 0, false, fmt.Errorf("%s is out of range", name)
	}
	return int(f), true, nil
}

func optObject(args map[string]interface{}, name string) (map[string]interface{}, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return nil, nil
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an object", name)
	}
	return m, nil
}

func optObjects(args map[string]interface{}, name string) ([]interface{}, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return nil, nil
	}
	list, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an array of objects", name)
	}
	for i, item := range list {
		if _, ok := item.(map[string]interface{}); !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", name, i)
		}
	}
	return list, nil
}

// stringList reads an array of strings or one comma separated string.
func stringList(args map[string]interface{}, name string) ([]string, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return nil, nil
	}
	var out []string
	switch t := v.(type) {
	case string:
		for _, p := range strings.Split(t, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	case []interface{}:
		for i, item := range t {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%s[%d] must be a string", name, i)
			}
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	default:
		return nil, fmt.Errorf("%s must be an array of strings or a comma separated string", name)
	}
	return out, nil
}

// pathID refuses an id that cannot be one path segment of the gateway route.
func pathID(name, v string) error {
	if v == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len(v) > 128 {
		return fmt.Errorf("%s is too long", name)
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == ':') {
			return fmt.Errorf("%s may only contain letters, digits and - _ . :", name)
		}
	}
	if v == "." || v == ".." {
		return fmt.Errorf("%s is not a valid id", name)
	}
	return nil
}
