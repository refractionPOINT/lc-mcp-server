package tools

import "github.com/mark3labs/mcp-go/mcp"

// DeclaredSchemaForTest exposes the schema exactly as the tool declares it,
// before the central annotation table is applied.
func (reg *ToolRegistration) DeclaredSchemaForTest() mcp.Tool { return reg.declaredSchema() }
