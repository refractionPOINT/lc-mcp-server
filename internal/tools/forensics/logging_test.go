package forensics

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The "Sending sensor command" INFO line names the command and its flags but
// never their values: mem_find_string's value is what the user searches
// memory for.
func TestSensorCommandLogOmitsValues(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// No SDK cache in the context: the sensor lookup fails after the command
	// is logged, so nothing reaches LimaCharlie.
	ctx := auth.WithRequestID(context.Background(), "req-123")
	_, err := sendSensorCommandWithPositional(ctx, "sid-1", "mem_find_string", []string{"secret-positional"}, map[string]interface{}{
		"pid":    4242,
		"string": []string{"secret-search-string"},
	})
	require.Error(t, err)

	out := buf.String()
	assert.NotContains(t, out, "secret-", "sensor command values must not be logged")
	assert.NotContains(t, out, "4242", "sensor command values must not be logged")

	var entry map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var e map[string]interface{}
		if json.Unmarshal([]byte(line), &e) == nil && e["msg"] == "Sending sensor command" {
			entry = e
			break
		}
	}
	require.NotNil(t, entry, "expected a 'Sending sensor command' line in:\n%s", out)
	assert.Equal(t, "req-123", entry["request_id"])
	assert.Equal(t, "sid-1", entry["sensor_id"])
	assert.Equal(t, "mem_find_string", entry["command"])
	assert.EqualValues(t, 1, entry["positional_args"])
	assert.Equal(t, "pid,string", entry["flags"])
}
