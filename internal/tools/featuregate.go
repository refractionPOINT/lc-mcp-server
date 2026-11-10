package tools

import (
	"os"
	"strings"
)

// EnvInvestigationEngine turns the Investigation Engine tools and profiles on. It is read once, when the
// process starts (tools register in package init): unset, or anything but "true" or "1", leaves the
// investigate_* tools unregistered and the investigation_engine profiles undefined, so no profile, endpoint,
// X-MCP-Tools header or lc_call_tool can reach them.
const EnvInvestigationEngine = "INVESTIGATION_ENGINE_ENABLED"

// investigationEngineProfiles are the profiles that only exist while the Investigation Engine gate is on.
var investigationEngineProfiles = []string{"investigation_engine", "investigation_engine_readonly"}

// InvestigationEngineEnabled reports whether the Investigation Engine gate is on.
func InvestigationEngineEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvInvestigationEngine))) {
	case "true", "1":
		return true
	}
	return false
}

// applyFeatureGates removes the profiles of every feature whose gate is off. It runs on whatever the
// profile definitions were loaded from (profiles.yaml, a PROFILES_CONFIG_PATH file or the built-in
// fallback), so the gate cannot be bypassed by the way the profiles were defined. Because "all" is the union
// of the defined profiles, it loses the gated tools with them.
func applyFeatureGates(profiles map[string][]string) {
	if InvestigationEngineEnabled() {
		return
	}
	for _, name := range investigationEngineProfiles {
		delete(profiles, name)
	}
}

// heldTools are the Investigation Engine tools declared while the gate is off. They are not in the registry,
// so nothing that resolves a tool by name (tools/list, tools/call, X-MCP-Tools, lc_call_tool) can reach them.
var heldTools []*ToolRegistration

// RegisterInvestigationEngineTool registers an Investigation Engine tool when INVESTIGATION_ENGINE_ENABLED is
// on, and otherwise only remembers it.
func RegisterInvestigationEngineTool(reg *ToolRegistration) {
	if !InvestigationEngineEnabled() {
		heldTools = append(heldTools, reg)
		return
	}
	RegisterTool(reg)
}

// HeldToolNames returns the tools declared but kept out of the registry by a gate that is off.
func HeldToolNames() []string {
	names := make([]string, 0, len(heldTools))
	for _, reg := range heldTools {
		names = append(names, reg.Name)
	}
	return names
}

// EnableInvestigationEngineForTest turns the Investigation Engine gate on after init has run: it sets the
// environment variable, registers the held tools and restores the gated profiles. For tests that need the
// full tool catalog; the gate is otherwise fixed at process start.
func EnableInvestigationEngineForTest() {
	os.Setenv(EnvInvestigationEngine, "true")
	for _, reg := range heldTools {
		RegisterTool(reg)
	}
	heldTools = nil
	loadProfileDefinitions()
}
