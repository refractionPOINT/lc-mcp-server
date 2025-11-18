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

// init loads profiles from YAML and populates ProfileDefinitions
func init() {
	// Try to load profiles from YAML file
	// Look for the file relative to the project root
	profilePath := findProfilesFile()

	if profilePath == "" {
		// Fall back to hardcoded definitions if file not found
		// This ensures backward compatibility and testing scenarios
		return
	}

	profiles, err := LoadProfiles(profilePath)
	if err != nil {
		// Log warning but don't fail - fall back to hardcoded definitions
		fmt.Fprintf(os.Stderr, "Warning: failed to load profiles from %s: %v\n", profilePath, err)
		fmt.Fprintf(os.Stderr, "Using default profile definitions\n")
		return
	}

	// Replace ProfileDefinitions with loaded profiles
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
