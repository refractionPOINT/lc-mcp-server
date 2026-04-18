package ai

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertToAnthropicMessages_BasicUserMessage(t *testing.T) {
	messages := []map[string]interface{}{
		{
			"role": "user",
			"parts": []interface{}{
				map[string]interface{}{"text": "hello world"},
			},
		},
	}

	result := convertToAnthropicMessages(messages)
	require.Len(t, result, 1)
	assert.Equal(t, "user", string(result[0].Role))
	require.Len(t, result[0].Content, 1)
	assert.Equal(t, "hello world", result[0].Content[0].OfText.Text)
}

func TestConvertToAnthropicMessages_ModelRoleMapsToAssistant(t *testing.T) {
	messages := []map[string]interface{}{
		{
			"role": "user",
			"parts": []interface{}{
				map[string]interface{}{"text": "question"},
			},
		},
		{
			"role": "model",
			"parts": []interface{}{
				map[string]interface{}{"text": "answer"},
			},
		},
	}

	result := convertToAnthropicMessages(messages)
	require.Len(t, result, 2)
	assert.Equal(t, "user", string(result[0].Role))
	assert.Equal(t, "assistant", string(result[1].Role))
	assert.Equal(t, "answer", result[1].Content[0].OfText.Text)
}

func TestConvertToAnthropicMessages_AssistantRolePassthrough(t *testing.T) {
	messages := []map[string]interface{}{
		{
			"role": "user",
			"parts": []interface{}{
				map[string]interface{}{"text": "q"},
			},
		},
		{
			"role": "assistant",
			"parts": []interface{}{
				map[string]interface{}{"text": "a"},
			},
		},
	}

	result := convertToAnthropicMessages(messages)
	require.Len(t, result, 2)
	assert.Equal(t, "assistant", string(result[1].Role))
}

func TestConvertToAnthropicMessages_MultiTurnRetryPattern(t *testing.T) {
	// Simulates the actual retry loop pattern from ai.go
	messages := []map[string]interface{}{
		{
			"role": "user",
			"parts": []interface{}{
				map[string]interface{}{"text": "generate a query"},
			},
		},
		{
			"role": "model",
			"parts": []interface{}{
				map[string]interface{}{"text": "SELECT * FROM events"},
			},
		},
		{
			"role": "user",
			"parts": []interface{}{
				map[string]interface{}{"text": "that was invalid, try again"},
			},
		},
	}

	result := convertToAnthropicMessages(messages)
	require.Len(t, result, 3)
	assert.Equal(t, "user", string(result[0].Role))
	assert.Equal(t, "assistant", string(result[1].Role))
	assert.Equal(t, "user", string(result[2].Role))
}

func TestConvertToAnthropicMessages_EmptyInput(t *testing.T) {
	result := convertToAnthropicMessages(nil)
	assert.Empty(t, result)

	result = convertToAnthropicMessages([]map[string]interface{}{})
	assert.Empty(t, result)
}

func TestConvertToAnthropicMessages_SkipsMissingRole(t *testing.T) {
	messages := []map[string]interface{}{
		{
			"parts": []interface{}{
				map[string]interface{}{"text": "no role"},
			},
		},
	}

	result := convertToAnthropicMessages(messages)
	assert.Empty(t, result)
}

func TestConvertToAnthropicMessages_SkipsMissingParts(t *testing.T) {
	messages := []map[string]interface{}{
		{
			"role": "user",
		},
	}

	result := convertToAnthropicMessages(messages)
	assert.Empty(t, result)
}

func TestConvertToAnthropicMessages_SkipsEmptyTextParts(t *testing.T) {
	messages := []map[string]interface{}{
		{
			"role":  "user",
			"parts": []interface{}{},
		},
	}

	result := convertToAnthropicMessages(messages)
	assert.Empty(t, result)
}

func TestConvertToAnthropicMessages_SkipsNonTextParts(t *testing.T) {
	messages := []map[string]interface{}{
		{
			"role": "user",
			"parts": []interface{}{
				map[string]interface{}{"image": "base64data"},
			},
		},
	}

	result := convertToAnthropicMessages(messages)
	assert.Empty(t, result)
}

func TestConvertToAnthropicMessages_SkipsUnknownRole(t *testing.T) {
	messages := []map[string]interface{}{
		{
			"role": "system",
			"parts": []interface{}{
				map[string]interface{}{"text": "should be skipped"},
			},
		},
	}

	result := convertToAnthropicMessages(messages)
	assert.Empty(t, result)
}

func TestConvertToAnthropicMessages_MultipleTextParts(t *testing.T) {
	messages := []map[string]interface{}{
		{
			"role": "user",
			"parts": []interface{}{
				map[string]interface{}{"text": "part one"},
				map[string]interface{}{"text": "part two"},
			},
		},
	}

	result := convertToAnthropicMessages(messages)
	require.Len(t, result, 1)
	require.Len(t, result[0].Content, 2)
	assert.Equal(t, "part one", result[0].Content[0].OfText.Text)
	assert.Equal(t, "part two", result[0].Content[1].OfText.Text)
}
