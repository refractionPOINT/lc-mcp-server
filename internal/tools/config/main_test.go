package config

import (
	"os"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools/testutil"
)

// fakeAPI is the local stand-in for the LimaCharlie gateway that the tool
// handlers are driven against. It must be installed before any test touches the SDK.
var fakeAPI *testutil.FakeAPI

func TestMain(m *testing.M) {
	api, stop := testutil.InstallFakeAPI()
	fakeAPI = api
	code := m.Run()
	stop()
	os.Exit(code)
}
