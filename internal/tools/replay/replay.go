package replay

import (
	"context"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/rules"
)

func init() {
	// Register replay tools
	RegisterTestDRRuleEvents()
	RegisterReplayDRRule()
}

// RegisterTestDRRuleEvents registers the test_dr_rule_events tool
func RegisterTestDRRuleEvents() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "test_dr_rule_events",
		Description: "Test a D&R rule against inline events (unit testing style)",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("test_dr_rule_events",
			mcp.WithDescription("Test a D&R rule against inline events for unit testing. Provide either rule_name OR detect/respond components."),
			mcp.WithString("rule_name",
				mcp.Description("Name of an existing rule to test (optional if detect is provided)")),
			mcp.WithString("namespace",
				mcp.Description("Rule namespace: 'general', 'managed', or 'service' (default: 'general')")),
			mcp.WithObject("detect",
				mcp.Description("Detection component (YAML/JSON structure). Required if rule_name not provided")),
			mcp.WithObject("respond",
				mcp.Description("Response component (array of actions). Optional, defaults to a report action")),
			mcp.WithArray("events",
				mcp.Required(),
				mcp.Description("Array of event objects to test against. Each event should have 'routing' and 'event' keys")),
			mcp.WithBoolean("trace",
				mcp.Description("Enable trace output for debugging rule evaluation (default: false)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Get organization (supports mock injection for testing)
			org, err := tools.GetOrganizationClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Build replay request
			req, err := buildReplayRequest(args, true)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			// Execute replay
			resp, err := org.ReplayDRRule(req)
			if err != nil {
				return tools.ErrorResultf("failed to execute replay: %v", err), nil
			}

			// Check for error in response
			if resp.Error != "" {
				return tools.ErrorResult(resp.Error), nil
			}

			// Format result
			result := formatReplayResponse(resp)
			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterReplayDRRule registers the replay_dr_rule tool
func RegisterReplayDRRule() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "replay_dr_rule",
		Description: "Test a D&R rule against historical sensor data",
		Profile:     "detection_engineering",
		RequiresOID: true,
		Schema: mcp.NewTool("replay_dr_rule",
			mcp.WithDescription("Test a D&R rule against historical sensor data. Provide either rule_name OR detect/respond components. Specify time range with start_time/end_time OR last_seconds."),
			mcp.WithString("rule_name",
				mcp.Description("Name of an existing rule to test (optional if detect is provided)")),
			mcp.WithString("namespace",
				mcp.Description("Rule namespace: 'general', 'managed', or 'service' (default: 'general')")),
			mcp.WithObject("detect",
				mcp.Description("Detection component (YAML/JSON structure). Required if rule_name not provided")),
			mcp.WithObject("respond",
				mcp.Description("Response component (array of actions). Optional, defaults to a report action")),
			mcp.WithString("sid",
				mcp.Description("Specific sensor ID to replay from (optional)")),
			mcp.WithString("selector",
				mcp.Description("Sensor selector expression using bexpr syntax (e.g., 'plat == `windows`')")),
			mcp.WithNumber("start_time",
				mcp.Description("Start timestamp in epoch seconds (required if last_seconds not provided)")),
			mcp.WithNumber("end_time",
				mcp.Description("End timestamp in epoch seconds (required if last_seconds not provided)")),
			mcp.WithNumber("last_seconds",
				mcp.Description("Alternative: replay last N seconds (e.g., 3600 for last hour)")),
			mcp.WithNumber("limit_event",
				mcp.Description("Maximum number of events to process (default: 10000)")),
			mcp.WithNumber("limit_eval",
				mcp.Description("Maximum number of evaluations to perform")),
			mcp.WithBoolean("trace",
				mcp.Description("Enable trace output for debugging (default: false)")),
			mcp.WithBoolean("dry_run",
				mcp.Description("Estimate cost only without processing (default: false)")),
			mcp.WithString("stream",
				mcp.Description("Data stream: 'event', 'audit', or 'detect' (default: 'event')")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Get organization (supports mock injection for testing)
			org, err := tools.GetOrganizationClient(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Build replay request
			req, err := buildReplayRequest(args, false)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			// Execute replay
			resp, err := org.ReplayDRRule(req)
			if err != nil {
				return tools.ErrorResultf("failed to execute replay: %v", err), nil
			}

			// Check for error in response
			if resp.Error != "" {
				return tools.ErrorResult(resp.Error), nil
			}

			// Format result
			result := formatReplayResponse(resp)
			return tools.SuccessResult(result), nil
		},
	})
}

// buildReplayRequest constructs a ReplayDRRuleRequest from tool arguments
func buildReplayRequest(args map[string]interface{}, requireEvents bool) (lc.ReplayDRRuleRequest, error) {
	req := lc.ReplayDRRuleRequest{}

	// Extract rule source
	ruleName, _ := args["rule_name"].(string)
	detect, hasDetect := args["detect"]
	respond, _ := args["respond"]

	// Validate rule source - must have exactly one of rule_name or detect
	if ruleName == "" && !hasDetect {
		return req, fmt.Errorf("either 'rule_name' or 'detect' must be provided")
	}
	if ruleName != "" && hasDetect {
		return req, fmt.Errorf("cannot provide both 'rule_name' and 'detect' - use one or the other")
	}

	req.RuleName = ruleName
	req.Namespace = rules.GetNamespaceWithDefault(args)

	// Build inline rule if provided
	if hasDetect {
		rule, err := rules.BuildRuleFromComponents(detect, respond, "test-detection")
		if err != nil {
			return req, err
		}
		req.Rule = rule
	}

	// Handle events (for test_dr_rule_events)
	if requireEvents {
		events, ok := args["events"]
		if !ok {
			return req, fmt.Errorf("events parameter is required")
		}

		switch e := events.(type) {
		case []interface{}:
			if len(e) == 0 {
				return req, fmt.Errorf("events array cannot be empty")
			}
			eventsList := make([]lc.Dict, 0, len(e))
			for i, event := range e {
				eventMap, ok := event.(map[string]interface{})
				if !ok {
					return req, fmt.Errorf("event at index %d must be an object", i)
				}
				eventsList = append(eventsList, eventMap)
			}
			req.Events = eventsList
		default:
			return req, fmt.Errorf("events must be an array")
		}
	} else {
		// Handle historical replay parameters
		sid, _ := args["sid"].(string)
		selector, _ := args["selector"].(string)
		startTime, hasStartTime := args["start_time"].(float64)
		endTime, hasEndTime := args["end_time"].(float64)
		lastSeconds, hasLastSeconds := args["last_seconds"].(float64)

		req.SID = sid
		req.Selector = selector

		// Determine time range
		if hasLastSeconds && lastSeconds > 0 {
			now := time.Now().Unix()
			req.EndTime = now
			req.StartTime = now - int64(lastSeconds)
		} else if hasStartTime && hasEndTime {
			req.StartTime = int64(startTime)
			req.EndTime = int64(endTime)
		} else {
			return req, fmt.Errorf("either 'last_seconds' or both 'start_time' and 'end_time' must be provided")
		}

		// Handle limits
		if limitEvent, ok := args["limit_event"].(float64); ok {
			req.LimitEvent = uint64(limitEvent)
		} else {
			req.LimitEvent = 10000 // Default limit
		}

		if limitEval, ok := args["limit_eval"].(float64); ok {
			req.LimitEval = uint64(limitEval)
		}

		// Handle stream
		if stream, ok := args["stream"].(string); ok && stream != "" {
			req.Stream = stream
		}

		// Handle dry run
		if dryRun, ok := args["dry_run"].(bool); ok {
			req.DryRun = dryRun
		}
	}

	// Handle trace
	if trace, ok := args["trace"].(bool); ok {
		req.Trace = trace
	}

	return req, nil
}

// formatReplayResponse converts a ReplayDRRuleResponse to a tool result map
func formatReplayResponse(resp *lc.ReplayDRRuleResponse) map[string]interface{} {
	result := map[string]interface{}{
		"matched": resp.DidMatch,
		"stats": map[string]interface{}{
			"events_processed": resp.Stats.NumEventsProcessed,
			"events_matched":   resp.Stats.NumEventsMatched,
			"evaluations":      resp.Stats.NumEvals,
			"events_scanned":   resp.Stats.NumScanned,
			"bytes_scanned":    resp.Stats.NumBytesScanned,
			"shards":           resp.Stats.NumShards,
			"wall_time":        resp.Stats.WallTime,
			"billed_events":    resp.Stats.BilledFor,
			"free_events":      resp.Stats.NotBilledFor,
		},
		"is_dry_run": resp.IsDryRun,
	}

	// Add results (actions that would be taken)
	if len(resp.Results) > 0 {
		results := make([]map[string]interface{}, 0, len(resp.Results))
		for _, r := range resp.Results {
			results = append(results, map[string]interface{}{
				"action": r.Action,
				"data":   r.Data,
			})
		}
		result["results"] = results
	} else {
		result["results"] = []interface{}{}
	}

	// Add traces if present
	if len(resp.Traces) > 0 {
		result["traces"] = resp.Traces
	}

	return result
}
