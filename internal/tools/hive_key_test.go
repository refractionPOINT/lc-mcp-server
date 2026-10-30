package tools_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateHiveRecordKey(t *testing.T) {
	for _, ok := range []string{"playbook-1", "a b", "a/b", "..a", "a..", "...", ".hidden", "é", "%2e%2e", `..\x`, " .. "} {
		assert.NoError(t, tools.ValidateHiveRecordKey(ok), "%q", ok)
	}
	for _, bad := range []string{"", ".", ".."} {
		assert.Error(t, tools.ValidateHiveRecordKey(bad), "%q", bad)
	}
}

// Tools reach hive request paths in two ways: the SDK's hive client, which the hive
// package wraps in a Client that checks the key, and the few paths built by hand.
// This keeps it that way: a tool that builds its own client or path would put a
// record key into a request unchecked. (The per-tool tests in the hive and config
// packages show the tools that use the checked ones refuse "." and "..".)
func TestHiveKeyPathsAreOnlyBuiltByCheckedCode(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	internalDir := filepath.Join(filepath.Dir(thisFile), "..")

	// The files that may name the SDK constructor or format a hive path, and so
	// must validate the key themselves.
	const checkedClient = "tools/hive/client.go"
	handBuilt := map[string]bool{"tools/hive/record_write.go": true, "tools/hive/hive_schema.go": true}

	err := filepath.WalkDir(internalDir, func(path string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(internalDir, path)
		require.NoError(t, err)
		rel = filepath.ToSlash(rel)
		src, err := os.ReadFile(path)
		require.NoError(t, err)
		code := string(src)

		if rel != checkedClient {
			assert.False(t, strings.Contains(code, "NewHiveClient("), "%s builds an unchecked SDK hive client: use hive.NewClient", rel)
		}
		if strings.Contains(code, `"hive/%s/`) {
			assert.True(t, handBuilt[rel], "%s builds a hive request path: it must validate the key (tools.ValidateHiveRecordKey) and be listed here", rel)
			assert.True(t, strings.Contains(code, "ValidateHiveRecordKey("), "%s builds a hive request path without validating the key", rel)
		}
		return nil
	})
	require.NoError(t, err)
}
