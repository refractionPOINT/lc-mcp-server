package investigation

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register live investigation tools
	RegisterGetProcesses()
	RegisterGetNetworkConnections()
	RegisterGetOSVersion()
}

// RegisterGetProcesses registers the get_processes tool
func RegisterGetProcesses() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_processes",
		Description: "Get the process list for a given sensor",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("get_processes",
			mcp.WithDescription("Get the process list for a given sensor"),
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
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}
			defer org.Close() // Ensure Spout is shut down when request completes

			// Set investigation ID for interactive mode
			org = org.WithInvestigationID(uuid.New().String())

			// Get sensor (returns *Sensor)
			sensor := org.GetSensor(sid)
			if sensor == nil {
				return tools.ErrorResult("sensor not found"), nil
			}

			// Use SimpleRequest to get synchronous response
			result, err := sensor.SimpleRequest("os_processes", lc.SimpleRequestOptions{
				Timeout: 10 * time.Minute,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get processes: %v", err), nil
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterGetNetworkConnections registers the get_network_connections tool
func RegisterGetNetworkConnections() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_network_connections",
		Description: "Get network connections for a given sensor",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("get_network_connections",
			mcp.WithDescription("Get network connections for a given sensor"),
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
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}
			defer org.Close() // Ensure Spout is shut down when request completes

			// Set investigation ID for interactive mode
			org = org.WithInvestigationID(uuid.New().String())

			// Get sensor (returns *Sensor)
			sensor := org.GetSensor(sid)
			if sensor == nil {
				return tools.ErrorResult("sensor not found"), nil
			}

			// Use SimpleRequest to get synchronous response
			// Python uses "netstat" command instead of "os_network_connections"
			result, err := sensor.SimpleRequest("netstat", lc.SimpleRequestOptions{
				Timeout: 10 * time.Minute,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get network connections: %v", err), nil
			}

			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterGetOSVersion registers the get_os_version tool
func RegisterGetOSVersion() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_os_version",
		Description: "Get OS version information for a given sensor",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("get_os_version",
			mcp.WithDescription("Get OS version information for a given sensor"),
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
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}
			defer org.Close() // Ensure Spout is shut down when request completes

			// Set investigation ID for interactive mode
			org = org.WithInvestigationID(uuid.New().String())

			// Get sensor (returns *Sensor)
			sensor := org.GetSensor(sid)
			if sensor == nil {
				return tools.ErrorResult("sensor not found"), nil
			}

			// Use SimpleRequest to get synchronous response
			result, err := sensor.SimpleRequest("os_version", lc.SimpleRequestOptions{
				Timeout: 10 * time.Minute,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get OS version: %v", err), nil
			}

			return tools.SuccessResult(result), nil
		},
	})
}
