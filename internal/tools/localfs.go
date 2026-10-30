package tools

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

// RefuseServerFilesystem returns a tool error when the request may not use the
// filesystem of the machine hosting this server, and nil when it may.
//
// Over HTTP one server process is shared by many organizations. A tool that opens,
// writes or scans a path the caller chose would let one tenant read another tenant's
// files (temp results, credentials) or overwrite the server's own. Only the
// single-user stdio server grants access (auth.HasLocalFilesystemAccess); everything
// else, including a context that was never marked, is refused.
//
// arg names the offending argument and alternative says what to send instead, so the
// model can retry in-band rather than give up.
func RefuseServerFilesystem(ctx context.Context, toolName, arg, alternative string) *mcp.CallToolResult {
	if auth.HasLocalFilesystemAccess(ctx) {
		return nil
	}
	return ErrorResultf(
		"%s: argument '%s' refers to the filesystem of the machine hosting this MCP server, which is not available "+
			"on a shared (HTTP) server because it is used by many organizations. %s",
		toolName, arg, alternative)
}
