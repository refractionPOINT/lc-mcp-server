package tools_test

import (
	"os"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// The tests of this package check the whole tool catalog (every tool classified, the hardcoded profiles equal to
// profiles.yaml), so they run with the Investigation Engine gate on. The gate being off is covered by
// internal/http/investigation_gate_test.go, which runs without it.
func TestMain(m *testing.M) {
	tools.EnableInvestigationEngineForTest()
	os.Exit(m.Run())
}
