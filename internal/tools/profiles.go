package tools

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadProfiles loads profile definitions from a YAML file
func LoadProfiles(path string) (map[string][]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read profiles file: %w", err)
	}

	profiles := make(map[string][]string)
	if err := yaml.Unmarshal(data, &profiles); err != nil {
		return nil, fmt.Errorf("failed to parse profiles YAML: %w", err)
	}

	return profiles, nil
}

// builtinProfileDefinitions is the hardcoded set of profiles as compiled, kept so the definitions can be
// rebuilt after the gates in featuregate.go are re-read.
var builtinProfileDefinitions map[string][]string

// init loads profiles from YAML and populates ProfileDefinitions
func init() {
	builtinProfileDefinitions = make(map[string][]string, len(ProfileDefinitions))
	for name, toolNames := range ProfileDefinitions {
		builtinProfileDefinitions[name] = toolNames
	}
	loadProfileDefinitions()
}

// loadProfileDefinitions sets ProfileDefinitions from the profiles file, or from the hardcoded definitions
// when there is none, then removes the profiles of every feature whose gate is off.
func loadProfileDefinitions() {
	profiles := make(map[string][]string, len(builtinProfileDefinitions))
	for name, toolNames := range builtinProfileDefinitions {
		profiles[name] = toolNames
	}

	// Try to load profiles from YAML file
	// Look for the file relative to the project root
	// If it is not found, or does not load, the hardcoded definitions stand.
	// This ensures backward compatibility and testing scenarios
	if profilePath := findProfilesFile(); profilePath != "" {
		loaded, err := LoadProfiles(profilePath)
		if err != nil {
			// Log warning but don't fail - fall back to hardcoded definitions
			fmt.Fprintf(os.Stderr, "Warning: failed to load profiles from %s: %v\n", profilePath, err)
			fmt.Fprintf(os.Stderr, "Using default profile definitions\n")
		} else {
			// Replace ProfileDefinitions with loaded profiles
			profiles = loaded
		}
	}

	applyFeatureGates(profiles)
	ProfileDefinitions = profiles
}

// findProfilesFile searches for the profiles.yaml file in common locations
func findProfilesFile() string {
	// Try multiple possible locations
	locations := []string{
		// 1. Relative to current working directory
		"configs/profiles.yaml",
		// 2. Relative to executable location
		filepath.Join(getExecutableDir(), "configs", "profiles.yaml"),
		// 3. From PROFILES_CONFIG_PATH environment variable
		os.Getenv("PROFILES_CONFIG_PATH"),
	}

	for _, path := range locations {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// getExecutableDir returns the directory containing the executable
func getExecutableDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exe)
}
