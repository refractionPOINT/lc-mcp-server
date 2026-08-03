package ai

import (
	"strings"
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

func TestExtractGeneratedLCQL_StripsWrappingBackticks(t *testing.T) {
	// Shape of a real generated response: the model wraps the query in inline
	// backticks, and the leading backtick makes the LCQL grammar fail at
	// position 0 ("expected: [0-9a-z +-/:,]i") — an error that points nowhere
	// near the real (nonexistent) problem with the query itself.
	response := "`-24h | * | WEL | (event/EVENT/System/EventID == \"17\" or event/EVENT/System/EventID == \"18\") and event/EVENT/EventData/PipeName contains \"Example_Pipe_\" | event/EVENT/System/EventID as EventID`\n\n**Query for Sysmon Event IDs 17 and 18**\n* `-24h`: last 24 hours"

	query, explanation := extractGeneratedLCQL(response)

	assert.Equal(t, "-24h | * | WEL | (event/EVENT/System/EventID == \"17\" or event/EVENT/System/EventID == \"18\") and event/EVENT/EventData/PipeName contains \"Example_Pipe_\" | event/EVENT/System/EventID as EventID", query)
	assert.Contains(t, explanation, "**Query for Sysmon Event IDs 17 and 18**")
}

func TestExtractGeneratedLCQL_StripsCodeFence(t *testing.T) {
	response := "```lcql\n-1h | * | NEW_PROCESS | event/FILE_PATH contains 'evil'\n```\n\nExplanation here"

	query, explanation := extractGeneratedLCQL(response)

	assert.Equal(t, "-1h | * | NEW_PROCESS | event/FILE_PATH contains 'evil'", query)
	// The explanation sits AFTER the closing fence; unwrapping must not swallow
	// it, since it is returned to the caller as tool output.
	assert.Equal(t, "Explanation here", explanation)
}

func TestExtractGeneratedLCQL_FenceWithBulletExplanation(t *testing.T) {
	// Full-fidelity shape of a fenced response: fence, query, fence, then the
	// bulleted explanation the prompt asks for.
	response := "```\n-24h | * | WEL | / exists\n```\n\n**Query for all WEL events**\n* `-24h`: last 24 hours\n* `WEL`: Windows Event Log events"

	query, explanation := extractGeneratedLCQL(response)

	assert.Equal(t, "-24h | * | WEL | / exists", query)
	assert.Contains(t, explanation, "**Query for all WEL events**")
	assert.Contains(t, explanation, "* `WEL`: Windows Event Log events")
}

func TestDropFenceLines_KeepsTimeframeGluedToFence(t *testing.T) {
	// A query glued to its fence marker must keep its leading timeframe: "-24h"
	// is content, not a language hint.
	assert.Equal(t, "-24h | * | * | / exists", dropFenceLines("```-24h | * | * | / exists\n```"))
}

func TestDropFenceLines_DropsLoneLanguageHint(t *testing.T) {
	assert.Equal(t, "content", dropFenceLines("```yaml\ncontent\n```"))
}

func TestExtractGeneratedLCQL_SkipsPreamble(t *testing.T) {
	// The model was told not to emit a preamble, but does anyway; the query on a
	// later line must still be what gets validated.
	response := "Here is the query you requested:\n\n`-1h | * | DNS_REQUEST | event/DOMAIN_NAME contains 'evil'`\n\nIt matches evil domains."

	query, explanation := extractGeneratedLCQL(response)

	assert.Equal(t, "-1h | * | DNS_REQUEST | event/DOMAIN_NAME contains 'evil'", query)
	assert.Equal(t, "It matches evil domains.", explanation)
}

func TestExtractGeneratedLCQL_PreservesInnerBackticks(t *testing.T) {
	// A backtick-quoted regex in a `matches` clause must survive unwrapping.
	response := "`-1h | * | NEW_PROCESS | event/FILE_PATH matches `.*system32.*``"

	query, _ := extractGeneratedLCQL(response)

	assert.Equal(t, "-1h | * | NEW_PROCESS | event/FILE_PATH matches `.*system32.*`", query)
}

func TestExtractGeneratedLCQL_NoQueryFoundFallsBackToFirstLine(t *testing.T) {
	// A refusal/clarification response has nothing query-shaped; the first line is
	// surfaced so the validation error the user sees reflects the actual output.
	response := "I need to clarify an important limitation:\n\nNone of the available event types contain Sysmon data."

	query, _ := extractGeneratedLCQL(response)

	assert.Equal(t, "I need to clarify an important limitation:", query)
}

func TestExtractFirstLine_SelectorStartingAndEndingWithQuotedValue(t *testing.T) {
	// Regression: this selector both starts and ends with a backtick-quoted
	// value without being wrapped in anything. Removing a "wrapping" pair
	// corrupts it into "vip` in tags and plat == `windows", which is exactly
	// what a live generation returned before this was fixed.
	selector, _ := extractFirstLine("`vip` in tags and plat == `windows`\n\nTargets Windows VIP sensors.")

	assert.Equal(t, "`vip` in tags and plat == `windows`", selector)
}

func TestExtractFirstLine_SelectorWithQuotedValueAtOneEnd(t *testing.T) {
	// Only the trailing end is a quoted value here, so there is no wrapping
	// pair to be tempted by.
	selector, _ := extractFirstLine("plat == `linux` and isolated == true")

	assert.Equal(t, "plat == `linux` and isolated == true", selector)
}

// TestExtractFirstLine_SelectorCorpus covers the selector forms the generator
// actually emits: the three returned by live generations during the
// investigation of this regression, plus every example the sensor-selector
// prompt template teaches the model to produce.
func TestExtractFirstLine_SelectorCorpus(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		// Observed live. The first is the one that regressed.
		{"live: quoted value at both ends", "`vip` in tags and plat == `windows`", "`vip` in tags and plat == `windows`"},
		{"live: quoted value mid-expression", "plat == `linux` and isolated == true", "plat == `linux` and isolated == true"},
		{"live: quoted values, unquoted tail", "`production` in tags and `critical` in tags", "`production` in tags and `critical` in tags"},

		// Forms taught by prompts/gen_sensor_selector.txt.
		{"prompt example: plat and tag", "plat == `windows` and `vip` in tags", "plat == `windows` and `vip` in tags"},
		{"prompt example: no backticks at all", "isolated == true or should_isolate == true", "isolated == true or should_isolate == true"},
		{"prompt example: numeric-leading value", "plat == `1password`", "plat == `1password`"},

		// Markdown decoration the model adds despite instructions.
		{"unambiguous inline wrapper", "`isolated == true`", "isolated == true"},
		{"fenced, quoted values", "```\nplat == `windows` and `vip` in tags\n```", "plat == `windows` and `vip` in tags"},
		{"fenced, no backticks", "```\nisolated == true\n```", "isolated == true"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := extractFirstLine(tc.input)
			assert.Equal(t, tc.want, got)

			// Invariant that generically catches this class of corruption: a
			// selector's backticks always pair up, so an odd count means a
			// quote was eaten.
			assert.Equal(t, 0, strings.Count(got, "`")%2,
				"unbalanced backticks in %q — a quoted value was corrupted", got)
		})
	}
}

func TestExtractFirstLine_UnwrapsUnambiguousSelector(t *testing.T) {
	// No backticks inside, so the outer pair can only be a markdown wrapper.
	selector, explanation := extractFirstLine("`isolated == true`\n\nIsolated sensors.")

	assert.Equal(t, "isolated == true", selector)
	assert.Equal(t, "Isolated sensors.", explanation)
}

func TestExtractFirstLine_UnwrappedSelectorUnchanged(t *testing.T) {
	selector, _ := extractFirstLine("plat == `windows`\n\nWindows sensors.")

	assert.Equal(t, "plat == `windows`", selector)
}
