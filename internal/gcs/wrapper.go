package gcs

import (
	"context"
	"encoding/json"
)

// WrapMCPResult attempts to wrap large MCP tool results with GCS
// If the result is too large, it uploads to GCS and returns a reference
// This function handles the MCP CallToolResult structure automatically
func WrapMCPResult(ctx context.Context, result interface{}, toolName string) interface{} {
	// Marshal the result to JSON to inspect its structure
	resultJSON, err := json.Marshal(result)
	if err != nil {
		// Can't marshal - return as-is
		return result
	}

	// Parse as map to extract text content
	var resultMap map[string]interface{}
	if err := json.Unmarshal(resultJSON, &resultMap); err != nil {
		return result
	}

	// Check if this is an error result
	if isError, ok := resultMap["isError"].(bool); ok && isError {
		return result
	}

	// Try to extract text from content
	if contentList, ok := resultMap["content"].([]interface{}); ok && len(contentList) > 0 {
		if contentItem, ok := contentList[0].(map[string]interface{}); ok {
			if text, ok := contentItem["text"].(string); ok {
				// Parse the JSON text
				var data interface{}
				if err := json.Unmarshal([]byte(text), &data); err != nil {
					// Not JSON or can't parse - return as-is
					return result
				}

				// Try to wrap with GCS
				wrappedData, err := MaybeWrapResult(ctx, data, toolName)
				if err != nil {
					// If wrapping fails, return original
					return result
				}

				// Re-encode and update the content with compact JSON
				wrappedJSON, _ := json.Marshal(wrappedData)
				contentItem["text"] = string(wrappedJSON)

				// Return the modified result
				return resultMap
			}
		}
	}

	// If we can't process it, return as-is
	return result
}
