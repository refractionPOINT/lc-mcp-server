package ai

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// aiMemoryHiveName is the hive name backing AI agent memory entries. Mirrors
// HIVE_NAME in python-limacharlie's ai_memory.py.
const aiMemoryHiveName = "ai_memory"

// aiMemoriesField is the top-level record field holding the memories map.
// Mirrors MEMORIES_FIELD in ai_memory.py.
const aiMemoriesField = "memories"

func init() {
	// Register AI memory management tools.
	RegisterSetAIMemory()
	RegisterDeleteAIMemory()
}

// partialSetAIMemory POSTs a partial "memories" payload to the ai_memory hive
// data endpoint, relying on the server's PreIngest merge hook. A nil content
// value drops the named memory. Mirrors ai_memory.py's _partial_set: POST to
// hive/ai_memory/{partition}/{key}/data with form param data={"memories":{name:value}}.
// The partition key is the org OID.
func partialSetAIMemory(org *lc.Organization, key string, memories map[string]interface{}) (lc.Dict, error) {
	path := fmt.Sprintf("hive/%s/%s/%s/data",
		aiMemoryHiveName,
		org.GetOID(),
		url.PathEscape(key),
	)
	payload := lc.Dict{aiMemoriesField: memories}
	var resp lc.Dict
	// GenericPOSTRequest form-encodes the Dict; a nested map value (the payload)
	// is JSON-marshaled and shipped as the "data" form field, exactly matching
	// the Python SDK's params={"data": json.dumps(payload)}.
	if err := org.GenericPOSTRequest(path, lc.Dict{"data": payload}, &resp); err != nil {
		return nil, err
	}
	return resp, nil
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

			resp, err := partialSetAIMemory(org, key, map[string]interface{}{memoryName: content})
			if err != nil {
				return tools.ErrorResultf("failed to set AI memory '%s' on '%s': %v", memoryName, key, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":  true,
				"response": map[string]interface{}(resp),
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

			// A nil (JSON null) value tells the server-side merge hook to drop
			// just this one memory entry. Mirrors ai_memory.py's delete.
			resp, err := partialSetAIMemory(org, key, map[string]interface{}{memoryName: nil})
			if err != nil {
				return tools.ErrorResultf("failed to delete AI memory '%s' on '%s': %v", memoryName, key, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":  true,
				"response": map[string]interface{}(resp),
			}), nil
		},
	})
}
