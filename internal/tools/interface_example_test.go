package tools_test

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// exampleTool demonstrates how to implement a custom tool using the Tool interface
type exampleTool struct {
	*tools.BaseTool
}

// Handle implements the Tool interface
func (t *exampleTool) Handle(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	message := args["message"].(string)
	result := map[string]string{
		"processed": message,
	}
	return tools.SuccessResult(result), nil
}

// Example_toolInterface demonstrates how to implement a custom tool using the Tool interface
func Example_toolInterface() {
	// Define the schema for the tool
	schema := mcp.Tool{
		Name:        "example_tool",
		Description: "An example tool",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"message": map[string]interface{}{
					"type":        "string",
					"description": "A message to process",
				},
			},
			Required: []string{"message"},
		},
	}

	// Create the base tool with metadata
	base := tools.NewBaseTool(
		"example_tool",
		"An example tool",
		"core",
		false, // doesn't require OID
		schema,
	)

	// Create the tool instance
	tool := &exampleTool{BaseTool: base}

	// Register the tool
	reg := &tools.ToolRegistration{
		Tool: tool,
	}

	tools.RegisterTool(reg)

	// The tool is now registered and can be used by the MCP server
}

// Example_organizationClientMock demonstrates the pattern for mocking OrganizationClient
// This example is for documentation purposes and shows how to structure mock implementations
func Example_organizationClientMock() {
	// In your test files, you would create a mock like this:
	//
	// type mockOrganization struct {
	//     getOIDFunc     func() string
	//     getSensorFunc  func(sid string) *lc.Sensor
	//     listSensorsFunc func(opts ...lc.ListSensorsOptions) (map[string]*lc.Sensor, error)
	// }
	//
	// func (m *mockOrganization) GetOID() string {
	//     if m.getOIDFunc != nil {
	//         return m.getOIDFunc()
	//     }
	//     return "default-oid"
	// }
	//
	// func (m *mockOrganization) GetSensor(sid string) *lc.Sensor {
	//     if m.getSensorFunc != nil {
	//         return m.getSensorFunc(sid)
	//     }
	//     return nil
	// }
	//
	// func (m *mockOrganization) ListSensors(opts ...lc.ListSensorsOptions) (map[string]*lc.Sensor, error) {
	//     if m.listSensorsFunc != nil {
	//         return m.listSensorsFunc(opts...)
	//     }
	//     return nil, nil
	// }
	//
	// // ... implement other required methods from OrganizationClient interface
	//
	// Usage in tests:
	// mock := &mockOrganization{
	//     getOIDFunc: func() string {
	//         return "test-org-123"
	//     },
	//     getSensorFunc: func(sid string) *lc.Sensor {
	//         return &lc.Sensor{
	//             SID: sid,
	//             // ... other test data
	//         }
	//     },
	// }
	//
	// // Use the mock in place of a real organization client
	// var client tools.OrganizationClient = mock
	// oid := client.GetOID() // Returns "test-org-123"
	// sensor := client.GetSensor("test-sid") // Returns mock sensor
}
