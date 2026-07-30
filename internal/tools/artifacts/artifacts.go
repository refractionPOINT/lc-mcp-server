package artifacts

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
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
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("list_artifacts",
			mcp.WithDescription("List collected artifacts and logs in a time range. Returns {logs, next_cursor}; pass next_cursor back as cursor to get the following page. The range is capped at 30 days server-side."),
			mcp.WithString("source",
				mcp.Description("Optional source (sensor ID or adapter ID) to filter the artifacts by")),
			mcp.WithString("hint",
				mcp.Description("Optional artifact type to filter by (the artifact's 'hint', e.g. 'wel', 'pcap', 'text')")),
			mcp.WithNumber("start",
				mcp.Required(),
				mcp.Description("Start of the range in Unix epoch SECONDS (not milliseconds - millisecond values are rejected)")),
			mcp.WithNumber("end",
				mcp.Required(),
				mcp.Description("End of the range in Unix epoch SECONDS (not milliseconds - millisecond values are rejected). Must be within 30 days of start.")),
			mcp.WithString("cursor",
				mcp.Description("Pagination cursor: the next_cursor of a previous call")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			// start/end are required: the handler rejects a call with either
			// missing and no cursor ("start, end or cursor required parameter
			// required").
			start, ok := args["start"].(float64)
			if !ok {
				return tools.ErrorResult("start parameter is required (Unix epoch seconds)"), nil
			}
			end, ok := args["end"].(float64)
			if !ok {
				return tools.ErrorResult("end parameter is required (Unix epoch seconds)"), nil
			}

			params := lc.Dict{
				"start": int64(start),
				"end":   int64(end),
			}

			// The filters are named source (sensor/adapter) and hint (type).
			if source, ok := args["source"].(string); ok && source != "" {
				params["source"] = source
			}

			if hint, ok := args["hint"].(string); ok && hint != "" {
				params["hint"] = hint
			}

			if cursor, ok := args["cursor"].(string); ok && cursor != "" {
				params["cursor"] = cursor
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
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("get_artifact",
			mcp.WithDescription("Download an artifact, or get a signed URL for it. Prefer get_url_only for large artifacts: downloading returns the whole body base64-encoded."),
			mcp.WithString("artifact_id",
				mcp.Required(),
				mcp.Description("Artifact ID to retrieve")),
			mcp.WithBoolean("get_url_only",
				mcp.Description("If true, return the signed URL ('export') and its expiry instead of downloading the body (default: false)")),
			mcp.WithReadOnlyHintAnnotation(true),
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

			if getURLOnly {
				// The originals endpoint already returns the signed export URL
				// alongside the size and path, so ExportArtifact - which
				// downloads and buffers the whole body - must be skipped here.
				// That download is the entire point of get_url_only for a
				// multi-gigabyte artifact.
				metadata := lc.Dict{}
				path := fmt.Sprintf("insight/%s/artifacts/originals/%s", org.GetOID(), url.PathEscape(artifactID))
				if err := org.GenericGETRequest(path, lc.Dict{}, &metadata); err != nil {
					return tools.ErrorResultf("failed to get artifact URL: %v", err), nil
				}

				result := map[string]interface{}{
					"artifact_id": artifactID,
					"metadata":    metadata,
				}
				// Surface the fields a caller actually needs instead of leaving
				// them buried in the metadata blob.
				for _, key := range []string{"export", "expires", "size", "path", "type", "source", "ts"} {
					if v, ok := metadata[key]; ok {
						result[key] = v
					}
				}

				return tools.SuccessResult(result), nil
			}

			// Export artifact using the SDK method
			// Use a deadline 5 minutes from now
			deadline := time.Now().Add(5 * time.Minute)

			reader, err := org.ExportArtifact(artifactID, deadline)
			if err != nil {
				return tools.ErrorResultf("failed to export artifact: %v", err), nil
			}
			defer reader.Close()

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
