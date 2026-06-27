package ai

import (
	"context"
	"log/slog"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register AI memory management tools.
	RegisterSetAIMemory()
	RegisterDeleteAIMemory()
}

// RegisterSetAIMemory registers the set_ai_memory tool.
func RegisterSetAIMemory() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_ai_memory",
		Description: "Set or merge an AI memory entry for an agent",
		Profile:     "ai_powered",
		RequiresOID: true,
		Schema: mcp.NewTool("set_ai_memory",
			mcp.WithDescription("Create or replace a single AI memory entry on an agent record (partial merge; other memories are preserved)"),
			mcp.WithString("key",
				mcp.Required(),
				mcp.Description("Agent identifier (the ai_memory hive record key)")),
			mcp.WithString("memory_name",
				mcp.Required(),
				mcp.Description("Name of the memory entry within the record (filesystem-style name)")),
			mcp.WithString("content",
				mcp.Required(),
				mcp.Description("Memory content to store")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			key, ok := optString(args, "key")
			if !ok {
				return tools.ErrorResult("key parameter is required"), nil
			}
			memoryName, ok := optString(args, "memory_name")
			if !ok {
				return tools.ErrorResult("memory_name parameter is required"), nil
			}
			content, ok := args["content"].(string)
			if !ok {
				return tools.ErrorResult("content parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			slog.Info("Tool called: set_ai_memory", "key", key, "memory_name", memoryName)

			if err := org.SetAIMemory(key, memoryName, content); err != nil {
				return tools.ErrorResultf("failed to set AI memory '%s' on '%s': %v", memoryName, key, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":     true,
				"key":         key,
				"memory_name": memoryName,
			}), nil
		},
	})
}

// RegisterDeleteAIMemory registers the delete_ai_memory tool.
func RegisterDeleteAIMemory() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_ai_memory",
		Description: "Delete a single AI memory entry from an agent record",
		Profile:     "ai_powered",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_ai_memory",
			mcp.WithDescription("Delete a single AI memory entry from an agent record (sends a null value so the merge hook drops just that entry; other memories are preserved)"),
			mcp.WithString("key",
				mcp.Required(),
				mcp.Description("Agent identifier (the ai_memory hive record key)")),
			mcp.WithString("memory_name",
				mcp.Required(),
				mcp.Description("Name of the memory entry to drop")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			key, ok := optString(args, "key")
			if !ok {
				return tools.ErrorResult("key parameter is required"), nil
			}
			memoryName, ok := optString(args, "memory_name")
			if !ok {
				return tools.ErrorResult("memory_name parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			slog.Info("Tool called: delete_ai_memory", "key", key, "memory_name", memoryName)

			if err := org.DeleteAIMemory(key, memoryName); err != nil {
				return tools.ErrorResultf("failed to delete AI memory '%s' on '%s': %v", memoryName, key, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":     true,
				"key":         key,
				"memory_name": memoryName,
			}), nil
		},
	})
}
