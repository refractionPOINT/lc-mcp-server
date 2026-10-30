package server

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/config"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSTDIOServerServesBothProtocolEras drives the stdio server through a real
// MCP client over pipes, once negotiating 2026-07-28 (server/discover, no
// handshake) and once per legacy revision (initialize handshake).
func TestSTDIOServerServesBothProtocolEras(t *testing.T) {
	cases := []struct {
		pinned      string
		wantVersion string
	}{
		{"", "2026-07-28"},
		{"2025-11-25", "2025-11-25"},
		{"2025-06-18", "2025-06-18"},
		{"2024-11-05", "2024-11-05"},
	}
	for _, tc := range cases {
		name := tc.pinned
		if name == "" {
			name = "default"
		}
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{
				Server:   config.ServerConfig{Mode: "stdio", Profile: "core", LogLevel: "error"},
				Features: config.FeatureConfig{SDKCacheTTL: 5 * time.Minute},
				Auth:     &auth.AuthContext{Mode: auth.AuthModeNormal, OID: "test-org", APIKey: "test-key-1234567890"},
			}
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			stdioSrv, err := NewSTDIOServer(cfg, logger)
			require.NoError(t, err)
			t.Cleanup(func() { _ = stdioSrv.Close() })

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			clientToServerR, clientToServerW := io.Pipe()
			serverToClientR, serverToClientW := io.Pipe()
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = mcpserver.NewStdioServer(stdioSrv.mcpServer).Listen(ctx, clientToServerR, serverToClientW)
			}()
			t.Cleanup(func() {
				cancel()
				_ = clientToServerW.Close()
				_ = serverToClientW.Close()
				<-done
			})

			var opts []mcpclient.ClientOption
			if tc.pinned != "" {
				opts = append(opts, mcpclient.WithProtocolVersion(tc.pinned))
			}
			c := mcpclient.NewClient(transport.NewIO(serverToClientR, clientToServerW, io.NopCloser(&emptyReader{})), opts...)
			require.NoError(t, c.Start(ctx))

			res, err := c.Initialize(ctx, mcp.InitializeRequest{Params: mcp.InitializeParams{
				ProtocolVersion: tc.pinned,
				ClientInfo:      mcp.Implementation{Name: "stdio-test", Version: "1"},
			}})
			require.NoError(t, err)
			assert.Equal(t, tc.wantVersion, c.ProtocolVersion())
			assert.Equal(t, "LimaCharlie MCP Server", res.ServerInfo.Name)

			listed, err := c.ListTools(ctx, mcp.ListToolsRequest{})
			require.NoError(t, err)
			var names []string
			for _, tool := range listed.Tools {
				names = append(names, tool.Name)
			}
			for _, want := range tools.GetToolsForProfile("core") {
				if _, ok := tools.GetTool(want); ok {
					assert.Contains(t, names, want)
				}
			}
		})
	}
}

type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, io.EOF }
