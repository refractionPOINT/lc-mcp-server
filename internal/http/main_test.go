//go:build !windows

package http

import (
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/testutil"
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
	// Every LimaCharlie REST call this package's tests make goes to a local stand-in,
	// never to the production API. auth.APIRoot reads it once, so it is set first.
	api, stop := testutil.InstallFakeAPI()
	fakeAPI = api
	code := m.Run()
	stop()
	os.Exit(code)
}

// fakeAPI is the local LimaCharlie gateway the tests drive real SDK calls against.
var fakeAPI *testutil.FakeAPI
