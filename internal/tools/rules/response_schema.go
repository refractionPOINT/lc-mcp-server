package rules

import "github.com/mark3labs/mcp-go/mcp"

// WithResponseComponent describes both forms accepted by BuildRuleFromComponents.
// The array is the canonical D&R form; a single action remains compatible with
// callers that used the original object-only schema.
func WithResponseComponent(description string) mcp.ToolOption {
	return mcp.WithAny("respond", mcp.Description(description), func(schema map[string]any) {
		schema["oneOf"] = []any{
			map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
			map[string]any{"type": "object"},
		}
	})
}
