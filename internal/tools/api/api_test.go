package api

import (
	"context"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func TestToolRegistration(t *testing.T) {
	// Test that the tool is registered
	tool, ok := tools.GetTool("lc_call_tool")
	if !ok {
		t.Fatal("lc_call_tool tool not registered")
	}

	if tool.Name != "lc_call_tool" {
		t.Errorf("Expected tool name 'lc_call_tool', got '%s'", tool.Name)
	}

	if tool.Profile != "api_access" {
		t.Errorf("Expected profile 'api_access', got '%s'", tool.Profile)
	}

	// lc_call_tool does not require OID itself (it passes through to target tool)
	if tool.RequiresOID {
		t.Error("Expected RequiresOID to be false")
	}
}

func TestProfileDefinition(t *testing.T) {
	// Test that the api_access profile exists and contains lc_call_tool
	profile := tools.GetToolsForProfile("api_access")
	if len(profile) == 0 {
		t.Fatal("api_access profile not found or empty")
	}

	found := false
	for _, toolName := range profile {
		if toolName == "lc_call_tool" {
			found = true
			break
		}
	}

	if !found {
		t.Error("lc_call_tool not found in api_access profile")
	}
}

func TestToolNameValidation(t *testing.T) {
	tests := []struct {
		name        string
		toolName    interface{}
		expectError string
	}{
		{"missing tool_name", nil, "tool_name parameter is required"},
		{"empty tool_name", "", "tool_name parameter is required"},
		{"non-string tool_name", 123, "tool_name parameter is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := map[string]interface{}{
				"parameters": map[string]interface{}{},
			}
			if tt.toolName != nil {
				args["tool_name"] = tt.toolName
			}

			result, err := handleLCCallTool(context.Background(), args)
			if err != nil {
				t.Fatalf("handler returned unexpected error: %v", err)
			}

			if !result.IsError {
				t.Errorf("Expected error for tool_name %v, but got success", tt.toolName)
				return
			}

			errorText := ""
			if len(result.Content) > 0 {
				if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
					errorText = textContent.Text
				}
			}
			if !strings.Contains(errorText, tt.expectError) {
				t.Errorf("Expected error containing %q, got %q", tt.expectError, errorText)
			}
		})
	}
}

func TestParametersValidation(t *testing.T) {
	tests := []struct {
		name        string
		parameters  interface{}
		expectError string
	}{
		{"missing parameters", nil, "parameters must be an object"},
		{"non-object parameters", "not an object", "parameters must be an object"},
		{"array parameters", []interface{}{}, "parameters must be an object"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := map[string]interface{}{
				"tool_name": "test_tool",
			}
			if tt.parameters != nil {
				args["parameters"] = tt.parameters
			}

			result, err := handleLCCallTool(context.Background(), args)
			if err != nil {
				t.Fatalf("handler returned unexpected error: %v", err)
			}

			if !result.IsError {
				t.Errorf("Expected error for parameters %v, but got success", tt.parameters)
				return
			}

			errorText := ""
			if len(result.Content) > 0 {
				if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
					errorText = textContent.Text
				}
			}
			if !strings.Contains(errorText, tt.expectError) {
				t.Errorf("Expected error containing %q, got %q", tt.expectError, errorText)
			}
		})
	}
}

func TestRecursiveCallPrevention(t *testing.T) {
	args := map[string]interface{}{
		"tool_name": "lc_call_tool",
		"parameters": map[string]interface{}{
			"tool_name":  "some_tool",
			"parameters": map[string]interface{}{},
		},
	}

	result, err := handleLCCallTool(context.Background(), args)
	if err != nil {
		t.Fatalf("handler returned unexpected error: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error for recursive call, but got success")
		return
	}

	errorText := ""
	if len(result.Content) > 0 {
		if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
			errorText = textContent.Text
		}
	}
	if !strings.Contains(errorText, "cannot call lc_call_tool recursively") {
		t.Errorf("Expected recursive call error, got %q", errorText)
	}
}

func TestNonExistentTool(t *testing.T) {
	args := map[string]interface{}{
		"tool_name":  "nonexistent_tool",
		"parameters": map[string]interface{}{},
	}

	result, err := handleLCCallTool(context.Background(), args)
	if err != nil {
		t.Fatalf("handler returned unexpected error: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error for non-existent tool, but got success")
		return
	}

	errorText := ""
	if len(result.Content) > 0 {
		if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
			errorText = textContent.Text
		}
	}
	if !strings.Contains(errorText, "not found") {
		t.Errorf("Expected 'not found' error, got %q", errorText)
	}
}

func TestValidToolCallWithValidParameters(t *testing.T) {
	// Register a simple test tool for testing
	testToolCalled := false
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "test_call_tool_target",
		Description: "Test target tool for lc_call_tool tests",
		Profile:     "core",
		RequiresOID: false,
		Schema: mcp.NewTool("test_call_tool_target",
			mcp.WithDescription("Test target tool"),
			mcp.WithString("message",
				mcp.Required(),
				mcp.Description("Test message")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			testToolCalled = true
			msg, _ := args["message"].(string)
			return tools.SuccessResult(map[string]interface{}{
				"echo": msg,
			}), nil
		},
	})

	args := map[string]interface{}{
		"tool_name": "test_call_tool_target",
		"parameters": map[string]interface{}{
			"message": "hello world",
		},
	}

	result, err := handleLCCallTool(context.Background(), args)
	if err != nil {
		t.Fatalf("handler returned unexpected error: %v", err)
	}

	if result.IsError {
		errorText := ""
		if len(result.Content) > 0 {
			if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
				errorText = textContent.Text
			}
		}
		t.Fatalf("Expected success, got error: %s", errorText)
	}

	if !testToolCalled {
		t.Error("Target tool was not called")
	}
}

func TestParameterValidationAgainstSchema(t *testing.T) {
	// Register a test tool with required parameters
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "test_validation_target",
		Description: "Test target for validation",
		Profile:     "core",
		RequiresOID: false,
		Schema: mcp.NewTool("test_validation_target",
			mcp.WithDescription("Test target tool"),
			mcp.WithString("required_param",
				mcp.Required(),
				mcp.Description("Required parameter")),
			mcp.WithString("optional_param",
				mcp.Description("Optional parameter")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return tools.SuccessResult(map[string]interface{}{"ok": true}), nil
		},
	})

	// Test missing required parameter
	t.Run("missing required parameter", func(t *testing.T) {
		args := map[string]interface{}{
			"tool_name": "test_validation_target",
			"parameters": map[string]interface{}{
				"optional_param": "value",
			},
		}

		result, err := handleLCCallTool(context.Background(), args)
		if err != nil {
			t.Fatalf("handler returned unexpected error: %v", err)
		}

		if !result.IsError {
			t.Error("Expected validation error, but got success")
			return
		}

		errorText := ""
		if len(result.Content) > 0 {
			if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
				errorText = textContent.Text
			}
		}
		if !strings.Contains(errorText, "required_param") {
			t.Errorf("Expected error about required_param, got %q", errorText)
		}
	})

	// Test with all required parameters
	t.Run("with required parameter", func(t *testing.T) {
		args := map[string]interface{}{
			"tool_name": "test_validation_target",
			"parameters": map[string]interface{}{
				"required_param": "value",
			},
		}

		result, err := handleLCCallTool(context.Background(), args)
		if err != nil {
			t.Fatalf("handler returned unexpected error: %v", err)
		}

		if result.IsError {
			errorText := ""
			if len(result.Content) > 0 {
				if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
					errorText = textContent.Text
				}
			}
			t.Errorf("Expected success, got error: %s", errorText)
		}
	})
}

func TestTypeValidation(t *testing.T) {
	// Register a test tool with typed parameters
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "test_type_validation",
		Description: "Test target for type validation",
		Profile:     "core",
		RequiresOID: false,
		Schema: mcp.NewTool("test_type_validation",
			mcp.WithDescription("Test target tool"),
			mcp.WithString("string_param",
				mcp.Required(),
				mcp.Description("String parameter")),
			mcp.WithNumber("number_param",
				mcp.Description("Number parameter")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return tools.SuccessResult(map[string]interface{}{"ok": true}), nil
		},
	})

	// Test wrong type for string parameter
	t.Run("wrong type for string", func(t *testing.T) {
		args := map[string]interface{}{
			"tool_name": "test_type_validation",
			"parameters": map[string]interface{}{
				"string_param": 123, // Should be string
			},
		}

		result, err := handleLCCallTool(context.Background(), args)
		if err != nil {
			t.Fatalf("handler returned unexpected error: %v", err)
		}

		if !result.IsError {
			t.Error("Expected type validation error, but got success")
			return
		}

		errorText := ""
		if len(result.Content) > 0 {
			if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
				errorText = textContent.Text
			}
		}
		if !strings.Contains(errorText, "string_param") || !strings.Contains(errorText, "string") {
			t.Errorf("Expected error about string_param type, got %q", errorText)
		}
	})

	// Test wrong type for number parameter
	t.Run("wrong type for number", func(t *testing.T) {
		args := map[string]interface{}{
			"tool_name": "test_type_validation",
			"parameters": map[string]interface{}{
				"string_param": "valid",
				"number_param": "not a number", // Should be number
			},
		}

		result, err := handleLCCallTool(context.Background(), args)
		if err != nil {
			t.Fatalf("handler returned unexpected error: %v", err)
		}

		if !result.IsError {
			t.Error("Expected type validation error, but got success")
			return
		}

		errorText := ""
		if len(result.Content) > 0 {
			if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
				errorText = textContent.Text
			}
		}
		if !strings.Contains(errorText, "number_param") || !strings.Contains(errorText, "number") {
			t.Errorf("Expected error about number_param type, got %q", errorText)
		}
	})
}

func TestUnknownParameterValidation(t *testing.T) {
	// Register a test tool with specific parameters
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "test_unknown_params",
		Description: "Test for unknown params",
		Profile:     "core",
		RequiresOID: false,
		Schema: mcp.NewTool("test_unknown_params",
			mcp.WithDescription("Test tool"),
			mcp.WithString("valid_param",
				mcp.Required(),
				mcp.Description("Valid parameter")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return tools.SuccessResult(map[string]interface{}{"ok": true}), nil
		},
	})

	t.Run("unknown parameter rejected", func(t *testing.T) {
		args := map[string]interface{}{
			"tool_name": "test_unknown_params",
			"parameters": map[string]interface{}{
				"valid_param":   "value",
				"invalid_param": "should fail",
			},
		}

		result, err := handleLCCallTool(context.Background(), args)
		if err != nil {
			t.Fatalf("handler returned unexpected error: %v", err)
		}

		if !result.IsError {
			t.Error("Expected error for unknown parameter, but got success")
			return
		}

		errorText := ""
		if len(result.Content) > 0 {
			if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
				errorText = textContent.Text
			}
		}
		if !strings.Contains(errorText, "unknown parameter") {
			t.Errorf("Expected 'unknown parameter' error, got %q", errorText)
		}
		if !strings.Contains(errorText, "invalid_param") {
			t.Errorf("Expected error to contain 'invalid_param', got %q", errorText)
		}
	})

	t.Run("valid parameters accepted", func(t *testing.T) {
		args := map[string]interface{}{
			"tool_name": "test_unknown_params",
			"parameters": map[string]interface{}{
				"valid_param": "value",
			},
		}

		result, err := handleLCCallTool(context.Background(), args)
		if err != nil {
			t.Fatalf("handler returned unexpected error: %v", err)
		}

		if result.IsError {
			errorText := ""
			if len(result.Content) > 0 {
				if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
					errorText = textContent.Text
				}
			}
			t.Errorf("Expected success, got error: %s", errorText)
		}
	})

	t.Run("multiple unknown parameters listed", func(t *testing.T) {
		args := map[string]interface{}{
			"tool_name": "test_unknown_params",
			"parameters": map[string]interface{}{
				"valid_param": "value",
				"bad_param1":  "should fail",
				"bad_param2":  "also should fail",
			},
		}

		result, err := handleLCCallTool(context.Background(), args)
		if err != nil {
			t.Fatalf("handler returned unexpected error: %v", err)
		}

		if !result.IsError {
			t.Error("Expected error for unknown parameters, but got success")
			return
		}

		errorText := ""
		if len(result.Content) > 0 {
			if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
				errorText = textContent.Text
			}
		}
		// Both unknown parameters should be mentioned
		if !strings.Contains(errorText, "bad_param1") || !strings.Contains(errorText, "bad_param2") {
			t.Errorf("Expected error to contain both 'bad_param1' and 'bad_param2', got %q", errorText)
		}
	})

	t.Run("oid parameter accepted for tools requiring OID", func(t *testing.T) {
		// Register a test tool that requires OID
		tools.RegisterTool(&tools.ToolRegistration{
			Name:        "test_oid_tool",
			Description: "Test tool requiring OID",
			Profile:     "core",
			RequiresOID: true,
			Schema: mcp.NewTool("test_oid_tool",
				mcp.WithDescription("Test tool"),
				mcp.WithString("some_param",
					mcp.Required(),
					mcp.Description("Some parameter")),
			),
			Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
				return tools.SuccessResult(map[string]interface{}{"ok": true}), nil
			},
		})

		args := map[string]interface{}{
			"tool_name": "test_oid_tool",
			"parameters": map[string]interface{}{
				"some_param": "value",
				"oid":        "test-org-id",
			},
		}

		result, err := handleLCCallTool(context.Background(), args)
		if err != nil {
			t.Fatalf("handler returned unexpected error: %v", err)
		}

		// The call may fail due to missing auth context for OID switching,
		// but the important thing is that 'oid' is NOT flagged as unknown parameter
		if result.IsError {
			errorText := ""
			if len(result.Content) > 0 {
				if textContent, ok := mcp.AsTextContent(result.Content[0]); ok {
					errorText = textContent.Text
				}
			}
			// Should NOT be an unknown parameter error
			if strings.Contains(errorText, "unknown parameter") {
				t.Errorf("oid should be accepted as valid parameter, got: %s", errorText)
			}
		}
	})
}
