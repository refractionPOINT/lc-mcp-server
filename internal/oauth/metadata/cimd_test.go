package metadata

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthorizationServerMetadataAdvertisesCIMD(t *testing.T) {
	t.Setenv("MCP_SERVER_URL", "https://test.example.com")
	meta := NewProvider(slog.New(slog.NewTextHandler(io.Discard, nil))).GetAuthorizationServerMetadata()

	assert.Equal(t, true, meta["client_id_metadata_document_supported"])
	// Dynamic registration stays available for existing clients.
	assert.Equal(t, "https://test.example.com/register", meta["registration_endpoint"])
	assert.Equal(t, []string{"none"}, meta["token_endpoint_auth_methods_supported"])
}
