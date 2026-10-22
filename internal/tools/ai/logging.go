package ai

import (
	"context"
	"log/slog"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

// toolCallAttrs returns the slog attributes every AI tool call line carries:
// the request ID (to join with the HTTP handler's lines) and the org ID, then
// the caller's extra attributes.
//
// These lines are kept at INFO in prod, so they must never carry what the
// caller typed (a natural-language request, a memory key or name) or what was
// generated from it. Log a length instead.
func toolCallAttrs(ctx context.Context, extra ...any) []any {
	oid := ""
	if a, err := auth.FromContext(ctx); err == nil {
		oid = a.OID
	}
	return append([]any{"request_id", auth.GetRequestID(ctx), "oid", oid}, extra...)
}

// logGeneratorCall logs that an AI generator tool was called, with the
// length of the user's request but not its text.
func logGeneratorCall(ctx context.Context, tool string, query string) {
	slog.Info("Tool called: "+tool, toolCallAttrs(ctx, "query_len", len(query))...)
}
