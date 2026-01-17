package tools_test

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"

	// Import all tool packages to trigger init() registration.
	// This ensures all tools are registered before tests run.
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/admin"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/ai"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/api"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/artifacts"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/config"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/core"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/forensics"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/historical"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/hive"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/investigation"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/payloads"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/replay"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/response"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/rules"
	_ "github.com/refractionpoint/lc-mcp-go/internal/tools/schemas"
)

// skipPackages contains packages under internal/tools/ that should NOT be imported
// in the test file because they don't register tools via init().
//
// Add a package here if:
//   - It's a utility/helper package (e.g., testutil, mocks)
//   - It doesn't have an init() function that calls RegisterTool()
//   - It's not a real tool package
var skipPackages = map[string]bool{
	"testutil": true, // Test utilities and mocks, no tool registration
}

// TestAllToolPackagesImported verifies that all tool subdirectories under internal/tools/
// are imported in this test file. This ensures that when a new tool package is added,
// it gets imported here to trigger its init() registration.
//
// If a new package is added that is NOT a tool package (e.g., utilities, mocks),
// add it to the skipPackages map above to exclude it from this check.
func TestAllToolPackagesImported(t *testing.T) {
	// Get the directory containing this test file
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get current file path")
	}
	toolsDir := filepath.Dir(thisFile)

	// Read this test file to check for imports
	testFileContent, err := os.ReadFile(thisFile)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}
	testFileStr := string(testFileContent)

	// Find all subdirectories in internal/tools/
	entries, err := os.ReadDir(toolsDir)
	if err != nil {
		t.Fatalf("failed to read tools directory: %v", err)
	}

	var missingImports []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pkgName := entry.Name()

		// Skip packages that are not tool packages (utilities, mocks, etc.)
		if skipPackages[pkgName] {
			continue
		}

		// Check if directory contains Go files (is a package)
		pkgPath := filepath.Join(toolsDir, pkgName)
		goFiles, err := filepath.Glob(filepath.Join(pkgPath, "*.go"))
		if err != nil || len(goFiles) == 0 {
			continue // Not a Go package, skip
		}

		// Check if any go file is not a test file (has actual code)
		hasNonTestFile := false
		for _, f := range goFiles {
			if !strings.HasSuffix(f, "_test.go") {
				hasNonTestFile = true
				break
			}
		}
		if !hasNonTestFile {
			continue // Only test files, skip
		}

		// Check if this package is imported in the test file
		expectedImport := `"github.com/refractionpoint/lc-mcp-go/internal/tools/` + pkgName + `"`
		if !strings.Contains(testFileStr, expectedImport) {
			missingImports = append(missingImports, pkgName)
		}
	}

	if len(missingImports) > 0 {
		sort.Strings(missingImports)
		t.Errorf("tool packages not imported in registry_test.go (add blank import to trigger init() registration): %v", missingImports)
		t.Log("Add the following imports to registry_test.go:")
		for _, pkg := range missingImports {
			t.Logf(`  _ "github.com/refractionpoint/lc-mcp-go/internal/tools/%s"`, pkg)
		}
		t.Log("If this is NOT a tool package, add it to skipPackages map in registry_test.go")
	}
}

// TestAllProfileToolsAreRegistered verifies that all tools listed in ProfileDefinitions
// are actually registered in the global registry. This catches cases where a tool name
// is added to a profile but the corresponding RegisterTool() call is missing.
func TestAllProfileToolsAreRegistered(t *testing.T) {
	// Collect all unique tool names from ProfileDefinitions
	profileTools := make(map[string][]string)
	for profile, toolList := range tools.ProfileDefinitions {
		for _, toolName := range toolList {
			profileTools[toolName] = append(profileTools[toolName], profile)
		}
	}

	// Check each tool in ProfileDefinitions is registered
	var missingTools []string
	for toolName, profiles := range profileTools {
		if _, exists := tools.GetTool(toolName); !exists {
			missingTools = append(missingTools, toolName)
			t.Errorf("tool %q is listed in profile(s) %v but is not registered", toolName, profiles)
		}
	}

	if len(missingTools) > 0 {
		sort.Strings(missingTools)
		t.Logf("Missing tools count: %d", len(missingTools))
		t.Logf("Missing tools: %v", missingTools)
	}
}

// TestAllRegisteredToolsAreInProfile verifies that all registered tools appear in at
// least one profile. This catches cases where a tool is registered via RegisterTool()
// but not added to any profile in ProfileDefinitions.
//
// NOTE: This test currently warns but does not fail for orphan tools. This allows
// gradual migration of tools to profiles without breaking the build.
func TestAllRegisteredToolsAreInProfile(t *testing.T) {
	// Build a set of all tools that appear in any profile
	toolsInProfiles := make(map[string]bool)
	for _, toolList := range tools.ProfileDefinitions {
		for _, toolName := range toolList {
			toolsInProfiles[toolName] = true
		}
	}

	// Check each registered tool is in at least one profile
	var orphanTools []string
	for _, toolName := range tools.GetAllRegisteredToolNames() {
		if !toolsInProfiles[toolName] {
			orphanTools = append(orphanTools, toolName)
			// Warn but don't fail - allows gradual migration
			t.Logf("WARNING: tool %q is registered but not listed in any profile", toolName)
		}
	}

	if len(orphanTools) > 0 {
		sort.Strings(orphanTools)
		t.Logf("Orphan tools count: %d", len(orphanTools))
		t.Logf("Orphan tools: %v", orphanTools)
		t.Logf("Consider adding these tools to appropriate profiles in ProfileDefinitions")
	}
}

// TestProfileDefinitionsConsistency performs additional consistency checks on profiles.
func TestProfileDefinitionsConsistency(t *testing.T) {
	t.Run("no duplicate tools within single profile", func(t *testing.T) {
		for profile, toolList := range tools.ProfileDefinitions {
			seen := make(map[string]bool)
			for _, toolName := range toolList {
				if seen[toolName] {
					t.Errorf("profile %q contains duplicate tool %q", profile, toolName)
				}
				seen[toolName] = true
			}
		}
	})

	t.Run("profile names are non-empty", func(t *testing.T) {
		for profile := range tools.ProfileDefinitions {
			if profile == "" {
				t.Error("found profile with empty name")
			}
		}
	})

	t.Run("profiles are non-empty", func(t *testing.T) {
		for profile, toolList := range tools.ProfileDefinitions {
			if len(toolList) == 0 {
				t.Errorf("profile %q has no tools defined", profile)
			}
		}
	})
}

// TestRegisteredToolsHaveValidMetadata verifies that all registered tools have
// the required metadata fields populated.
func TestRegisteredToolsHaveValidMetadata(t *testing.T) {
	for _, toolName := range tools.GetAllRegisteredToolNames() {
		t.Run(toolName, func(t *testing.T) {
			reg, exists := tools.GetTool(toolName)
			if !exists {
				t.Fatalf("tool %q not found in registry", toolName)
			}

			// Check the tool has either interface-based or legacy registration
			if reg.Tool != nil {
				// Interface-based tool
				if reg.Tool.Name() == "" {
					t.Error("interface tool has empty name")
				}
				if reg.Tool.Description() == "" {
					t.Error("interface tool has empty description")
				}
			} else {
				// Legacy registration
				if reg.Name == "" {
					t.Error("legacy tool has empty name")
				}
				if reg.Description == "" {
					t.Error("legacy tool has empty description")
				}
				if reg.Handler == nil {
					t.Error("legacy tool has nil handler")
				}
			}
		})
	}
}

// getProjectRoot returns the project root directory by traversing up from the test file.
//
// Returns:
//   - string: absolute path to the project root directory
func getProjectRoot() string {
	_, filename, _, _ := runtime.Caller(0)
	// registry_test.go is in internal/tools/, so go up 3 levels to reach project root
	return filepath.Join(filepath.Dir(filename), "..", "..")
}

// TestProfileDefinitionsMatchYAML verifies that the hardcoded ProfileDefinitions
// in registry.go matches the contents of configs/profiles.yaml. This ensures
// the fallback definitions stay in sync with the YAML configuration file.
func TestProfileDefinitionsMatchYAML(t *testing.T) {
	projectRoot := getProjectRoot()
	yamlPath := filepath.Join(projectRoot, "configs", "profiles.yaml")

	yamlProfiles, err := tools.LoadProfiles(yamlPath)
	if err != nil {
		t.Fatalf("failed to load profiles.yaml: %v", err)
	}

	// Get the hardcoded definitions (before init() potentially overwrites them)
	// Since init() may have already loaded from YAML, we need to compare what's
	// currently in ProfileDefinitions with what's in the YAML file
	codeProfiles := tools.ProfileDefinitions

	t.Run("same profile names", func(t *testing.T) {
		// Check for profiles in YAML but not in code
		for profile := range yamlProfiles {
			if _, exists := codeProfiles[profile]; !exists {
				t.Errorf("profile %q exists in profiles.yaml but not in hardcoded ProfileDefinitions", profile)
			}
		}

		// Check for profiles in code but not in YAML
		for profile := range codeProfiles {
			if _, exists := yamlProfiles[profile]; !exists {
				t.Errorf("profile %q exists in hardcoded ProfileDefinitions but not in profiles.yaml", profile)
			}
		}
	})

	t.Run("same tools in each profile", func(t *testing.T) {
		for profile, yamlTools := range yamlProfiles {
			codeTools, exists := codeProfiles[profile]
			if !exists {
				continue // Already reported in previous subtest
			}

			// Build sets for comparison
			yamlSet := make(map[string]bool)
			for _, tool := range yamlTools {
				yamlSet[tool] = true
			}

			codeSet := make(map[string]bool)
			for _, tool := range codeTools {
				codeSet[tool] = true
			}

			// Check for tools in YAML but not in code
			var missingInCode []string
			for tool := range yamlSet {
				if !codeSet[tool] {
					missingInCode = append(missingInCode, tool)
				}
			}
			if len(missingInCode) > 0 {
				sort.Strings(missingInCode)
				t.Errorf("profile %q: tools in profiles.yaml but not in hardcoded ProfileDefinitions: %v", profile, missingInCode)
			}

			// Check for tools in code but not in YAML
			var missingInYAML []string
			for tool := range codeSet {
				if !yamlSet[tool] {
					missingInYAML = append(missingInYAML, tool)
				}
			}
			if len(missingInYAML) > 0 {
				sort.Strings(missingInYAML)
				t.Errorf("profile %q: tools in hardcoded ProfileDefinitions but not in profiles.yaml: %v", profile, missingInYAML)
			}
		}
	})
}
