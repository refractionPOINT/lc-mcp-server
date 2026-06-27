package feedback

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register feedback request tools (mutate, not destructive).
	RegisterRequestFeedbackApproval()
	RegisterRequestFeedbackAck()
	RegisterRequestFeedbackQuestion()

	// Register feedback channel management tools.
	RegisterListFeedbackChannels()
	RegisterAddFeedbackChannel()
	RegisterRemoveFeedbackChannel()
}

// asDict converts an object argument into a lc.Dict, returning nil when absent.
func asDict(args map[string]interface{}, key string) lc.Dict {
	v, ok := args[key].(map[string]interface{})
	if !ok {
		return nil
	}
	return lc.Dict(v)
}

// asInt converts a numeric argument (typically a JSON float64) to an int.
func asInt(args map[string]interface{}, key string) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	}
	return 0
}

// RegisterRequestFeedbackApproval registers the request_feedback_approval tool.
func RegisterRequestFeedbackApproval() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "request_feedback_approval",
		Description: "Request a simple Approve/Deny approval via ext-feedback",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("request_feedback_approval",
			mcp.WithDescription("Send a simple Approve/Deny feedback request to a configured feedback channel. The recipient's choice is dispatched to the given feedback destination (case or playbook)."),
			mcp.WithString("channel",
				mcp.Required(),
				mcp.Description("Name of the configured feedback channel to deliver the request to")),
			mcp.WithString("question",
				mcp.Required(),
				mcp.Description("The question/prompt shown to the recipient")),
			mcp.WithString("feedback_destination",
				mcp.Required(),
				mcp.Description("Where the response is dispatched: 'case' or 'playbook'")),
			mcp.WithString("case_id",
				mcp.Description("Case number to attach the response to (required when destination is 'case')")),
			mcp.WithString("playbook_name",
				mcp.Description("Playbook to trigger with the response (required when destination is 'playbook')")),
			mcp.WithObject("approved_content",
				mcp.Description("JSON data included in the response payload when the recipient approves")),
			mcp.WithObject("denied_content",
				mcp.Description("JSON data included in the response payload when the recipient denies")),
			mcp.WithNumber("timeout_seconds",
				mcp.Description("Auto-respond after this many seconds with no human response (minimum 60). Requires timeout_choice.")),
			mcp.WithString("timeout_choice",
				mcp.Description("Choice to auto-select on timeout: 'approved' or 'denied' (required when timeout_seconds is set)")),
			mcp.WithObject("timeout_content",
				mcp.Description("JSON data for the timeout response payload")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			channel, ok := args["channel"].(string)
			if !ok || channel == "" {
				return tools.ErrorResult("channel parameter is required"), nil
			}
			question, ok := args["question"].(string)
			if !ok || question == "" {
				return tools.ErrorResult("question parameter is required"), nil
			}
			destination, ok := args["feedback_destination"].(string)
			if !ok || destination == "" {
				return tools.ErrorResult("feedback_destination parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			opts := lc.RequestApprovalOptions{
				CaseID:          asString(args, "case_id"),
				PlaybookName:    asString(args, "playbook_name"),
				ApprovedContent: asDict(args, "approved_content"),
				DeniedContent:   asDict(args, "denied_content"),
				TimeoutSeconds:  asInt(args, "timeout_seconds"),
				TimeoutChoice:   asString(args, "timeout_choice"),
				TimeoutContent:  asDict(args, "timeout_content"),
			}

			resp, err := org.Feedback().RequestApproval(channel, question, destination, opts)
			if err != nil {
				return tools.ErrorResultf("failed to request approval: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"response": resp,
			}), nil
		},
	})
}

// RegisterRequestFeedbackAck registers the request_feedback_ack tool.
func RegisterRequestFeedbackAck() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "request_feedback_ack",
		Description: "Request an acknowledgement via ext-feedback",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("request_feedback_ack",
			mcp.WithDescription("Send an acknowledgement request (single Acknowledge button) to a configured feedback channel. The acknowledgement is dispatched to the given feedback destination (case or playbook)."),
			mcp.WithString("channel",
				mcp.Required(),
				mcp.Description("Name of the configured feedback channel to deliver the request to")),
			mcp.WithString("question",
				mcp.Required(),
				mcp.Description("The message/prompt shown to the recipient")),
			mcp.WithString("feedback_destination",
				mcp.Required(),
				mcp.Description("Where the response is dispatched: 'case' or 'playbook'")),
			mcp.WithString("case_id",
				mcp.Description("Case number to attach the response to (required when destination is 'case')")),
			mcp.WithString("playbook_name",
				mcp.Description("Playbook to trigger with the response (required when destination is 'playbook')")),
			mcp.WithObject("acknowledged_content",
				mcp.Description("JSON data included in the response payload when the recipient acknowledges")),
			mcp.WithNumber("timeout_seconds",
				mcp.Description("Auto-acknowledge after this many seconds with no human response (minimum 60)")),
			mcp.WithObject("timeout_content",
				mcp.Description("JSON data for the timeout response payload")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			channel, ok := args["channel"].(string)
			if !ok || channel == "" {
				return tools.ErrorResult("channel parameter is required"), nil
			}
			question, ok := args["question"].(string)
			if !ok || question == "" {
				return tools.ErrorResult("question parameter is required"), nil
			}
			destination, ok := args["feedback_destination"].(string)
			if !ok || destination == "" {
				return tools.ErrorResult("feedback_destination parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			opts := lc.RequestAcknowledgementOptions{
				CaseID:              asString(args, "case_id"),
				PlaybookName:        asString(args, "playbook_name"),
				AcknowledgedContent: asDict(args, "acknowledged_content"),
				TimeoutSeconds:      asInt(args, "timeout_seconds"),
				TimeoutContent:      asDict(args, "timeout_content"),
			}

			resp, err := org.Feedback().RequestAcknowledgement(channel, question, destination, opts)
			if err != nil {
				return tools.ErrorResultf("failed to request acknowledgement: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"response": resp,
			}), nil
		},
	})
}

// RegisterRequestFeedbackQuestion registers the request_feedback_question tool.
func RegisterRequestFeedbackQuestion() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "request_feedback_question",
		Description: "Request a free-form question response via ext-feedback",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("request_feedback_question",
			mcp.WithDescription("Send a question with a free-form text input field to a configured feedback channel. The recipient's text answer is dispatched to the given feedback destination (case or playbook)."),
			mcp.WithString("channel",
				mcp.Required(),
				mcp.Description("Name of the configured feedback channel to deliver the request to")),
			mcp.WithString("question",
				mcp.Required(),
				mcp.Description("The question shown to the recipient")),
			mcp.WithString("feedback_destination",
				mcp.Required(),
				mcp.Description("Where the response is dispatched: 'case' or 'playbook'")),
			mcp.WithString("case_id",
				mcp.Description("Case number to attach the response to (required when destination is 'case')")),
			mcp.WithString("playbook_name",
				mcp.Description("Playbook to trigger with the response (required when destination is 'playbook')")),
			mcp.WithNumber("timeout_seconds",
				mcp.Description("Auto-answer after this many seconds with no human response (minimum 60). Requires timeout_content.")),
			mcp.WithObject("timeout_content",
				mcp.Description("JSON data used as the automatic answer on timeout (required when timeout_seconds is set)")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			channel, ok := args["channel"].(string)
			if !ok || channel == "" {
				return tools.ErrorResult("channel parameter is required"), nil
			}
			question, ok := args["question"].(string)
			if !ok || question == "" {
				return tools.ErrorResult("question parameter is required"), nil
			}
			destination, ok := args["feedback_destination"].(string)
			if !ok || destination == "" {
				return tools.ErrorResult("feedback_destination parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			opts := lc.RequestQuestionOptions{
				CaseID:         asString(args, "case_id"),
				PlaybookName:   asString(args, "playbook_name"),
				TimeoutSeconds: asInt(args, "timeout_seconds"),
				TimeoutContent: asDict(args, "timeout_content"),
			}

			resp, err := org.Feedback().RequestQuestion(channel, question, destination, opts)
			if err != nil {
				return tools.ErrorResultf("failed to request question: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"response": resp,
			}), nil
		},
	})
}

// RegisterListFeedbackChannels registers the list_feedback_channels tool.
func RegisterListFeedbackChannels() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_feedback_channels",
		Description: "List the feedback channels configured for the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_feedback_channels",
			mcp.WithDescription("List the feedback channels configured for the organization via ext-feedback"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			channels, err := org.Feedback().ListChannels()
			if err != nil {
				return tools.ErrorResultf("failed to list feedback channels: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"channels": channels,
				"count":    len(channels),
			}), nil
		},
	})
}

// RegisterAddFeedbackChannel registers the add_feedback_channel tool.
func RegisterAddFeedbackChannel() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "add_feedback_channel",
		Description: "Add a feedback channel to the organization's ext-feedback configuration",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("add_feedback_channel",
			mcp.WithDescription("Add a feedback channel to the organization's ext-feedback configuration"),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Unique channel name referenced when sending feedback requests")),
			mcp.WithString("channel_type",
				mcp.Required(),
				mcp.Description("Channel type: one of web, slack, email, telegram, ms_teams")),
			mcp.WithString("output_name",
				mcp.Description("Tailored Output holding the channel credentials. Required for all types except 'web'.")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("name parameter is required"), nil
			}
			channelType, ok := args["channel_type"].(string)
			if !ok || channelType == "" {
				return tools.ErrorResult("channel_type parameter is required"), nil
			}
			outputName := asString(args, "output_name")

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			_, err = org.Feedback().AddChannel(name, channelType, outputName)
			if err != nil {
				return tools.ErrorResultf("failed to add feedback channel '%s': %v", name, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"name":    name,
			}), nil
		},
	})
}

// RegisterRemoveFeedbackChannel registers the remove_feedback_channel tool.
func RegisterRemoveFeedbackChannel() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "remove_feedback_channel",
		Description: "Remove a feedback channel from the organization's ext-feedback configuration",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("remove_feedback_channel",
			mcp.WithDescription("Remove a feedback channel from the organization's ext-feedback configuration. Does not delete the associated Tailored Output."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name of the channel to remove")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			_, err = org.Feedback().RemoveChannel(name)
			if err != nil {
				return tools.ErrorResultf("failed to remove feedback channel '%s': %v", name, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"name":    name,
			}), nil
		},
	})
}

// asString returns a string argument or empty string when absent.
func asString(args map[string]interface{}, key string) string {
	v, _ := args[key].(string)
	return v
}
