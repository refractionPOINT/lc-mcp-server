// Package tools provides interfaces and utilities for MCP tool development.
//
// This package includes two main interface abstractions:
//
// 1. Tool Interface: Defines the contract for MCP tools, enabling better testability
// and cleaner architecture. Tools can implement this interface directly or embed
// BaseTool for default implementations.
//
// 2. OrganizationClient Interface: Provides a mockable interface for LimaCharlie
// organization operations, making it easier to write unit tests without requiring
// actual API credentials.
//
// These interfaces are designed to support both new interface-based implementations
// and legacy struct-based tools through backward-compatible registration patterns.
// See interface_example_test.go for usage examples.
package tools

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
)

// Tool defines the interface that all MCP tools must implement.
// This interface provides a cleaner, more testable architecture for tool development.
//
// Tools can implement this interface directly or embed BaseTool for a default implementation.
// The interface-based design enables:
//   - Easier mocking and unit testing
//   - Better separation of concerns
//   - Simplified tool composition and decoration
//   - More flexible tool registration patterns
//
// Example implementation:
//
//	type MyTool struct {
//	    *BaseTool
//	}
//
//	func NewMyTool() *MyTool {
//	    base := NewBaseTool(
//	        "my_tool",
//	        "Description of my tool",
//	        "core",
//	        true,  // requires OID
//	        mySchema,
//	    )
//	    return &MyTool{BaseTool: base}
//	}
//
//	func (t *MyTool) Handle(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
//	    // Tool implementation
//	    return SuccessResult(data), nil
//	}
type Tool interface {
	// Name returns the tool's unique identifier used for registration and invocation
	Name() string

	// Description returns a human-readable description of what the tool does
	Description() string

	// Profile returns the profile this tool belongs to (e.g., "core", "historical_data")
	Profile() string

	// RequiresOID returns whether this tool requires organization context (OID parameter)
	// in UID mode. Tools that operate on organization-specific data should return true.
	RequiresOID() bool

	// Schema returns the MCP tool schema defining the tool's input parameters
	Schema() mcp.Tool

	// Handle executes the tool with the given context and arguments.
	// The context may contain authentication and organization information.
	// Returns the tool result or an error if execution fails.
	Handle(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error)
}

// BaseTool provides a default implementation of the Tool interface that tools can embed.
// It handles all the metadata methods, requiring only Handle() to be implemented.
//
// BaseTool is designed to reduce boilerplate when creating new tools. Simply embed it
// and implement the Handle method:
//
//	type MyTool struct {
//	    *BaseTool
//	}
//
//	func (t *MyTool) Handle(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
//	    // Your implementation here
//	}
type BaseTool struct {
	name        string
	description string
	profile     string
	requiresOID bool
	schema      mcp.Tool
}

// Name returns the tool's unique identifier
func (t *BaseTool) Name() string {
	return t.name
}

// Description returns a human-readable description
func (t *BaseTool) Description() string {
	return t.description
}

// Profile returns the profile this tool belongs to
func (t *BaseTool) Profile() string {
	return t.profile
}

// RequiresOID returns whether this tool requires organization context
func (t *BaseTool) RequiresOID() bool {
	return t.requiresOID
}

// Schema returns the MCP tool schema
func (t *BaseTool) Schema() mcp.Tool {
	return t.schema
}

// NewBaseTool creates a new base tool with the given metadata.
//
// Parameters:
//   - name: Unique identifier for the tool
//   - description: Human-readable description
//   - profile: Profile the tool belongs to (e.g., "core", "historical_data")
//   - requiresOID: Whether tool requires OID parameter in UID mode
//   - schema: MCP tool schema defining input parameters
//
// Returns a BaseTool that can be embedded in custom tool implementations.
func NewBaseTool(name, description, profile string, requiresOID bool, schema mcp.Tool) *BaseTool {
	return &BaseTool{
		name:        name,
		description: description,
		profile:     profile,
		requiresOID: requiresOID,
		schema:      schema,
	}
}
