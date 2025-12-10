package response

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register Velociraptor DFIR tools
	RegisterListVelociraptorArtifacts()
	RegisterShowVelociraptorArtifact()
	RegisterCollectVelociraptorArtifact()
}

// RegisterListVelociraptorArtifacts registers the list_velociraptor_artifacts tool
// This tool lists all available Velociraptor artifacts via the ext-velociraptor extension
func RegisterListVelociraptorArtifacts() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_velociraptor_artifacts",
		Description: "List all available Velociraptor artifacts for DFIR collection (built-in and external from triage.velocidex.com)",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("list_velociraptor_artifacts",
			mcp.WithDescription("List available Velociraptor artifacts (built-in and external)"),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			resp := lc.Dict{}
			if err := org.ExtensionRequest(&resp, "ext-velociraptor", "list", lc.Dict{}, false); err != nil {
				return tools.ErrorResultf("failed to list velociraptor artifacts: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterShowVelociraptorArtifact registers the show_velociraptor_artifact tool
// This tool displays the YAML definition of a specific Velociraptor artifact
func RegisterShowVelociraptorArtifact() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "show_velociraptor_artifact",
		Description: "Display the YAML definition of a Velociraptor artifact to understand its parameters and behavior",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("show_velociraptor_artifact",
			mcp.WithDescription("Display YAML definition of a Velociraptor artifact"),
			mcp.WithString("artifact_name",
				mcp.Required(),
				mcp.Description("Name of the artifact (e.g., 'Windows.System.Drivers')")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			artifactName, ok := args["artifact_name"].(string)
			if !ok || artifactName == "" {
				return tools.ErrorResult("artifact_name parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			data := lc.Dict{
				"artifact_name": artifactName,
			}

			resp := lc.Dict{}
			if err := org.ExtensionRequest(&resp, "ext-velociraptor", "show", data, false); err != nil {
				return tools.ErrorResultf("failed to show velociraptor artifact: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterCollectVelociraptorArtifact registers the collect_velociraptor_artifact tool
// This tool initiates Velociraptor artifact collection from endpoints
func RegisterCollectVelociraptorArtifact() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "collect_velociraptor_artifact",
		Description: "Initiate Velociraptor artifact collection from endpoints for DFIR investigations",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("collect_velociraptor_artifact",
			mcp.WithDescription("Collect Velociraptor artifacts from sensors for forensic analysis"),
			mcp.WithArray("artifact_list",
				mcp.Description("List of artifact names to collect (e.g., ['Windows.System.Drivers', 'Windows.EventLogs.Security'])")),
			mcp.WithString("custom_artifact",
				mcp.Description("Custom artifact YAML definition (alternative to artifact_list)")),
			mcp.WithString("sid",
				mcp.Description("Single sensor ID to target")),
			mcp.WithString("sensor_selector",
				mcp.Description("Sensor selector expression (e.g., 'plat == windows')")),
			mcp.WithString("args",
				mcp.Description("Comma-separated arguments for artifact (e.g., 'DriverPathRegex=.*malware.*')")),
			mcp.WithNumber("collection_ttl",
				mcp.Description("Seconds to keep attempting collection (default: 604800 = 7 days)")),
			mcp.WithNumber("retention_ttl",
				mcp.Description("Days to retain collected artifacts (default: 7)")),
			mcp.WithBoolean("ignore_cert",
				mcp.Description("Ignore SSL certificate errors during collection")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			data := lc.Dict{}

			// Handle artifact_list (array of strings)
			if artifactList, ok := args["artifact_list"].([]interface{}); ok && len(artifactList) > 0 {
				artifacts := make([]string, 0, len(artifactList))
				for _, a := range artifactList {
					if s, ok := a.(string); ok {
						artifacts = append(artifacts, s)
					}
				}
				if len(artifacts) > 0 {
					data["artifact_list"] = artifacts
				}
			}

			// Handle custom_artifact
			if v, ok := args["custom_artifact"].(string); ok && v != "" {
				data["custom_artifact"] = v
			}

			// Handle sid
			if v, ok := args["sid"].(string); ok && v != "" {
				data["sid"] = v
			}

			// Handle sensor_selector
			if v, ok := args["sensor_selector"].(string); ok && v != "" {
				data["sensor_selector"] = v
			}

			// Handle args
			if v, ok := args["args"].(string); ok && v != "" {
				data["args"] = v
			}

			// Handle collection_ttl
			if v, ok := args["collection_ttl"].(float64); ok {
				data["collection_ttl"] = int(v)
			}

			// Handle retention_ttl
			if v, ok := args["retention_ttl"].(float64); ok {
				data["retention_ttl"] = int(v)
			}

			// Handle ignore_cert
			if v, ok := args["ignore_cert"].(bool); ok {
				data["ignore_cert"] = v
			}

			resp := lc.Dict{}
			if err := org.ExtensionRequest(&resp, "ext-velociraptor", "collect", data, false); err != nil {
				return tools.ErrorResultf("failed to collect velociraptor artifacts: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}
