package metadata

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthorizationServerMetadata_AdvertisesIssParameter(t *testing.T) {
	t.Setenv("MCP_SERVER_URL", "https://mcp.example.com/")
	p := NewProvider(slog.New(slog.NewTextHandler(io.Discard, nil)))

	md := p.GetAuthorizationServerMetadata()

	// RFC 9207: the flag must be a real boolean true, and the issuer clients
	// compare iss against must be the trailing-slash-trimmed server URL.
	assert.Equal(t, true, md["authorization_response_iss_parameter_supported"])
	assert.Equal(t, "https://mcp.example.com", md["issuer"])
	assert.Equal(t, p.GetServerURL(), md["issuer"])
}
