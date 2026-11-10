//go:build !windows

package http

import (
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// The tools and profiles register when the process starts, according to INVESTIGATION_ENGINE_ENABLED, and cannot
// be undone afterwards. The gate-off tests of this package (investigation_gate_test.go) need a process that
// started without the variable, so a test run with it exported starts over without it instead of failing.
func TestMain(m *testing.M) {
	if _, set := os.LookupEnv(tools.EnvInvestigationEngine); set {
		os.Unsetenv(tools.EnvInvestigationEngine)
		exe, err := os.Executable()
		if err == nil {
			err = syscall.Exec(exe, os.Args, os.Environ())
		}
		fmt.Fprintf(os.Stderr, "cannot restart the test binary without %s: %v\n", tools.EnvInvestigationEngine, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
