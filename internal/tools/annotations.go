package tools

import (
	"github.com/mark3labs/mcp-go/mcp"
)

// Tool annotation classification.
//
// Every tool the server ships has exactly one entry in toolAnnotations
// (annotations_table.go). The entry is the single source of truth for the four
// MCP behaviour hints and is applied to the schema returned by
// ToolRegistration.ToolSchema, so tools/list, the stdio server, the OAuth scope
// policy and lc_call_tool all see the same values.
//
// Why a table instead of per-tool literals: mcp-go's NewTool pre-fills every
// hint (readOnly=false, destructive=true, idempotent=false, openWorld=true), so
// a tool that simply forgets a hint is indistinguishable from one that chose it,
// and openWorld=true silently advertised every LimaCharlie tool as reaching
// outside the user's organization. Requiring a table entry makes the choice
// explicit and reviewable in one place, and a test fails when a tool lacks one.
//
// The hints follow the OpenAI plugin guidelines and map onto the Meta Muse
// connector classes (see MuseClass):
//
//   - ReadOnly: the tool never modifies anything in LimaCharlie, on endpoints
//     or in third-party systems. A read-only OAuth token (limacharlie:read) can
//     call ONLY tools with ReadOnly=true, so this is a security boundary.
//   - Destructive: only meaningful for non-read-only tools. True when the tool
//     can delete, overwrite, revoke, isolate, kill or otherwise cause loss or
//     disruption; false for purely additive writes. Read-only tools are always
//     false.
//   - Idempotent: only meaningful for non-read-only tools. True when repeating
//     the call with the same arguments has no additional effect. Read-only
//     tools are always false.
//   - OpenWorld: true when the call itself reaches beyond the user's own
//     LimaCharlie organization: it tasks a sensor / acts on a real endpoint,
//     creates or changes an output (data sent to third-party destinations),
//     or actively calls an external system. False when it only reads or writes
//     the organization's own data and configuration, including configuration
//     that later makes LimaCharlie contact a third party.
type Annotation struct {
	ReadOnly    bool
	Destructive bool
	Idempotent  bool
	OpenWorld   bool
}

// Constructors used by the table. They keep the invariants (read-only tools are
// neither destructive nor idempotent) out of the 400-odd entries.

// read is a read-only tool confined to the organization's own data.
func read() Annotation { return Annotation{ReadOnly: true} }

// write is an additive, non-idempotent write (creates, appends, queued work).
func write() Annotation { return Annotation{} }

// destroy is a write that can delete, overwrite, revoke or disrupt.
func destroy() Annotation { return Annotation{Destructive: true} }

// Idem marks a write as idempotent.
func (a Annotation) Idem() Annotation { a.Idempotent = !a.ReadOnly; return a }

// Open marks the tool as reaching beyond the user's own organization.
func (a Annotation) Open() Annotation { a.OpenWorld = true; return a }

// MuseClass is the Meta Muse connector classification derived from the hints:
// read-only tools are "Read", destructive tools are "Sensitive write" and every
// other write is "Write". A tool that mixes reads and writes counts as a write.
func (a Annotation) MuseClass() string {
	switch {
	case a.ReadOnly:
		return "Read"
	case a.Destructive:
		return "Sensitive write"
	default:
		return "Write"
	}
}

// AnnotationFor returns the classification of a registered tool by name.
func AnnotationFor(toolName string) (Annotation, bool) {
	a, ok := toolAnnotations[toolName]
	return a, ok
}

// withAnnotations returns tool with the hints from its table entry applied.
// Tools without an entry (test doubles) are returned unchanged. The pointers
// are freshly allocated so the tool's own annotation values are never mutated.
func withAnnotations(tool mcp.Tool, name string) mcp.Tool {
	a, ok := toolAnnotations[name]
	if !ok {
		return tool
	}
	ro, des, idem, open := a.ReadOnly, a.Destructive, a.Idempotent, a.OpenWorld
	tool.Annotations.ReadOnlyHint = &ro
	tool.Annotations.DestructiveHint = &des
	tool.Annotations.IdempotentHint = &idem
	tool.Annotations.OpenWorldHint = &open
	return tool
}

// ClassifiedToolNames returns the names that have a classification entry.
func ClassifiedToolNames() []string {
	names := make([]string, 0, len(toolAnnotations))
	for name := range toolAnnotations {
		names = append(names, name)
	}
	return names
}
