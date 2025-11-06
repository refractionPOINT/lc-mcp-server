package artifacts

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register artifact tools
	RegisterListArtifacts()
	RegisterGetArtifact()
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
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
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

			// List artifacts via GenericGETRequest
			resp := lc.Dict{}
			path := fmt.Sprintf("insight/%s/artifacts", org.GetOID())
			if err := org.GenericGETRequest(path, params, &resp); err != nil {
				return tools.ErrorResultf("failed to list artifacts: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
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
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			artifactID, ok := args["artifact_id"].(string)
			if !ok {
				return tools.ErrorResult("artifact_id parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			getURLOnly := false
			if val, ok := args["get_url_only"].(bool); ok {
				getURLOnly = val
			}

			// Export artifact using the SDK method
			// Use a deadline 5 minutes from now
			deadline := time.Now().Add(5 * time.Minute)

			reader, err := org.ExportArtifact(artifactID, deadline)
			if err != nil {
				return tools.ErrorResultf("failed to export artifact: %v", err), nil
			}
			defer reader.Close()

			if getURLOnly {
				// For URL-only mode, we need to use a different approach
				// The SDK returns a reader, but we want just the URL
				// We'll use the GenericGETRequest to get the artifact metadata which includes the URL
				metadata := lc.Dict{}
				path := fmt.Sprintf("insight/%s/artifacts/%s", org.GetOID(), artifactID)
				if err := org.GenericGETRequest(path, lc.Dict{}, &metadata); err != nil {
					return tools.ErrorResultf("failed to get artifact URL: %v", err), nil
				}

				return tools.SuccessResult(map[string]interface{}{
					"artifact_id": artifactID,
					"metadata":    metadata,
				}), nil
			}

			// Read the artifact data
			data, err := io.ReadAll(reader)
			if err != nil {
				return tools.ErrorResultf("failed to read artifact data: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"artifact_id": artifactID,
				"size":        len(data),
				"data":        base64.StdEncoding.EncodeToString(data),
			}), nil
		},
	})
}
