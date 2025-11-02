package artifacts

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/auth"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register artifact tools
	RegisterListArtifacts()
	RegisterGetArtifact()
}

// getOrganization retrieves or creates an Organization instance from context
func getOrganization(ctx context.Context) (*lc.Organization, error) {
	cache, err := auth.GetSDKCache(ctx)
	if err != nil {
		return nil, err
	}

	return cache.GetFromContext(ctx)
}

// RegisterListArtifacts registers the list_artifacts tool
func RegisterListArtifacts() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_artifacts",
		Description: "List collected artifacts and logs",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("list_artifacts",
			mcp.WithDescription("List collected artifacts and logs"),
			mcp.WithString("sid",
				mcp.Description("Sensor ID to filter by")),
			mcp.WithString("artifact_type",
				mcp.Description("Artifact type to filter by")),
			mcp.WithNumber("start",
				mcp.Description("Start timestamp")),
			mcp.WithNumber("end",
				mcp.Description("End timestamp")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// Build query parameters
			params := lc.Dict{}

			if sid, ok := args["sid"].(string); ok {
				params["sid"] = sid
			}

			if artifactType, ok := args["artifact_type"].(string); ok {
				params["type"] = artifactType
			}

			if start, ok := args["start"].(float64); ok {
				params["start"] = int64(start)
			}

			if end, ok := args["end"].(float64); ok {
				params["end"] = int64(end)
			}

			// List artifacts via REST API
			// TODO: SDK needs Request() method or ListArtifacts() method
			_ = params
			_ = org

			return tools.ErrorResult("SDK does not yet have org.Request() method - needs to be added"), nil
		},
	})
}

// RegisterGetArtifact registers the get_artifact tool
func RegisterGetArtifact() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_artifact",
		Description: "Download or get URL for a specific artifact",
		Profile:     "historical_data",
		RequiresOID: true,
		Schema: mcp.NewTool("get_artifact",
			mcp.WithDescription("Download or get URL for a specific artifact"),
			mcp.WithString("artifact_id",
				mcp.Required(),
				mcp.Description("Artifact ID to retrieve")),
			mcp.WithBoolean("get_url_only",
				mcp.Description("If true, return signed URL instead of downloading (default: false)")),
			mcp.WithString("oid",
				mcp.Description("Organization ID (required in UID mode)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			artifactID, ok := args["artifact_id"].(string)
			if !ok {
				return tools.ErrorResult("artifact_id parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			getURLOnly := false
			if val, ok := args["get_url_only"].(bool); ok {
				getURLOnly = val
			}

			// Export artifact
			// TODO: SDK ExportArtifact needs time.Time parameter
			_ = artifactID
			_ = org
			_ = getURLOnly

			return tools.ErrorResult("SDK ExportArtifact method signature mismatch - needs update"), nil
		},
	})
}
