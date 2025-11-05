package response

import (
	"context"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register threat response tools
	RegisterIsolateNetwork()
	RegisterRejoinNetwork()
	RegisterIsIsolated()
	RegisterAddTag()
	RegisterRemoveTag()
}

// getSDKCache retrieves the SDK cache from context
func getSDKCache(ctx context.Context) (*auth.SDKCache, error) {
	return auth.GetSDKCache(ctx)
}

// getOrganization retrieves or creates an Organization instance from context
func getOrganization(ctx context.Context) (*lc.Organization, error) {
	cache, err := getSDKCache(ctx)
	if err != nil {
		return nil, err
	}

	return cache.GetFromContext(ctx)
}

// RegisterIsolateNetwork registers the isolate_network tool
func RegisterIsolateNetwork() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "isolate_network",
		Description: "Isolate a sensor from the network",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("isolate_network",
			mcp.WithDescription("Isolate a sensor from the network (blocks all network access except LC comms)"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract and validate SID
			sid, err := tools.ExtractAndValidateSID(args)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			// Get organization
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get sensor (returns *Sensor)
			sensor := org.GetSensor(sid)
			if sensor == nil {
				return tools.ErrorResult("sensor not found"), nil
			}

			// Isolate sensor
			if err = sensor.IsolateFromNetwork(); err != nil {
				return tools.ErrorResultf("failed to isolate sensor: %v", err), nil
			}

			result := map[string]interface{}{
				"status":  "success",
				"message": fmt.Sprintf("Sensor %s isolated from network", sid),
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterRejoinNetwork registers the rejoin_network tool
func RegisterRejoinNetwork() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "rejoin_network",
		Description: "Remove network isolation from a sensor",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("rejoin_network",
			mcp.WithDescription("Remove network isolation from a sensor (restore normal network access)"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract and validate SID
			sid, err := tools.ExtractAndValidateSID(args)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			// Get organization
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get sensor (returns *Sensor)
			sensor := org.GetSensor(sid)
			if sensor == nil {
				return tools.ErrorResult("sensor not found"), nil
			}

			// Rejoin network
			if err = sensor.RejoinNetwork(); err != nil {
				return tools.ErrorResultf("failed to rejoin sensor: %v", err), nil
			}

			result := map[string]interface{}{
				"status":  "success",
				"message": fmt.Sprintf("Sensor %s rejoined network", sid),
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterIsIsolated registers the is_isolated tool
func RegisterIsIsolated() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "is_isolated",
		Description: "Check if a sensor is isolated from the network",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("is_isolated",
			mcp.WithDescription("Check if a sensor is isolated from the network"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract and validate SID
			sid, err := tools.ExtractAndValidateSID(args)
			if err != nil {
				return tools.ErrorResult(err.Error()), nil
			}

			// Get organization
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get sensor (returns *Sensor)
			sensor := org.GetSensor(sid)
			if sensor == nil {
				return tools.ErrorResult("sensor not found"), nil
			}

			// Update sensor to get latest status
			sensor = sensor.Update()
			if sensor.LastError != nil {
				return tools.ErrorResultf("failed to update sensor: %v", sensor.LastError), nil
			}

			// Check isolation status from sensor field
			result := map[string]interface{}{
				"sid":         sid,
				"is_isolated": sensor.IsIsolated,
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterAddTag registers the add_tag tool
func RegisterAddTag() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "add_tag",
		Description: "Add a tag to a sensor",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("add_tag",
			mcp.WithDescription("Add a tag to a sensor"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithString("tag",
				mcp.Required(),
				mcp.Description("Tag to add")),
			mcp.WithNumber("ttl",
				mcp.Required(),
				mcp.Description("Time to live in seconds (0 for permanent)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract SID
			sid, ok := args["sid"].(string)
			if !ok || sid == "" {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			// Extract tag
			tag, ok := args["tag"].(string)
			if !ok || tag == "" {
				return tools.ErrorResult("tag parameter is required"), nil
			}

			// Extract TTL
			ttlFloat, ok := args["ttl"].(float64)
			if !ok {
				return tools.ErrorResult("ttl parameter is required"), nil
			}
			ttl := int(ttlFloat)

			// Get organization
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get sensor (returns *Sensor)
			sensor := org.GetSensor(sid)
			if sensor == nil {
				return tools.ErrorResult("sensor not found"), nil
			}

			// Add tag (SDK expects time.Duration)
			ttlDuration := time.Duration(ttl) * time.Second
			if err = sensor.AddTag(tag, ttlDuration); err != nil {
				return tools.ErrorResultf("failed to add tag: %v", err), nil
			}

			result := map[string]interface{}{
				"status":  "success",
				"message": fmt.Sprintf("Tag '%s' added to sensor %s", tag, sid),
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterRemoveTag registers the remove_tag tool
func RegisterRemoveTag() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "remove_tag",
		Description: "Remove a tag from a sensor",
		Profile:     "threat_response",
		RequiresOID: true,
		Schema: mcp.NewTool("remove_tag",
			mcp.WithDescription("Remove a tag from a sensor"),
			mcp.WithString("sid",
				mcp.Required(),
				mcp.Description("Sensor ID (UUID)")),
			mcp.WithString("tag",
				mcp.Required(),
				mcp.Description("Tag to remove")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Extract SID
			sid, ok := args["sid"].(string)
			if !ok || sid == "" {
				return tools.ErrorResult("sid parameter is required"), nil
			}

			// Extract tag
			tag, ok := args["tag"].(string)
			if !ok || tag == "" {
				return tools.ErrorResult("tag parameter is required"), nil
			}

			// Get organization
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Get sensor (returns *Sensor)
			sensor := org.GetSensor(sid)
			if sensor == nil {
				return tools.ErrorResult("sensor not found"), nil
			}

			// Remove tag
			if err = sensor.RemoveTag(tag); err != nil {
				return tools.ErrorResultf("failed to remove tag: %v", err), nil
			}

			result := map[string]interface{}{
				"status":  "success",
				"message": fmt.Sprintf("Tag '%s' removed from sensor %s", tag, sid),
			}

			return tools.SuccessResult(result), nil
		},
	})
}
