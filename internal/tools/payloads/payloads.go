package payloads

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register payload management tools
	RegisterListPayloads()
	RegisterCreatePayload()
	RegisterGetPayload()
	RegisterDeletePayload()
}

// getOrganization retrieves the organization from the context
func getOrganization(ctx context.Context) (*lc.Organization, error) {
	return tools.GetOrganization(ctx)
}

// validateFilePath validates a file path for security
func validateFilePath(path string) error {
	// Require absolute path
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path must be absolute, got: %s", path)
	}

	// Clean the path to resolve any ".." or "." components
	cleanPath := filepath.Clean(path)

	// Prevent access to sensitive system paths
	blockedPrefixes := []string{
		"/etc",
		"/sys",
		"/proc",
		"/dev",
		"/boot",
		"/root",
	}

	for _, prefix := range blockedPrefixes {
		if strings.HasPrefix(cleanPath, prefix+"/") || cleanPath == prefix {
			return fmt.Errorf("access to '%s' is not allowed", prefix)
		}
	}

	return nil
}

// RegisterListPayloads registers the list_payloads tool
func RegisterListPayloads() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_payloads",
		Description: "List all payloads (executables/scripts) in the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_payloads",
			mcp.WithDescription("List all payloads (executables/scripts) available for deployment to sensors. Returns payload names, sizes, creators, and creation timestamps."),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			payloads, err := org.Payloads()
			if err != nil {
				return tools.ErrorResultf("failed to list payloads: %v", err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"payloads": payloads,
				"count":    len(payloads),
			}), nil
		},
	})
}

// RegisterCreatePayload registers the create_payload tool
func RegisterCreatePayload() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "create_payload",
		Description: "Upload a payload from a file on disk or base64-encoded content",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("create_payload",
			mcp.WithDescription("Upload a payload (executable or script) to be deployed and executed on sensors. The file extension in the name determines execution type (.exe, .ps1, .bat, .sh). Provide either file_path OR file_content (base64-encoded), not both."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name for the payload (include file extension for execution type)")),
			mcp.WithString("file_path",
				mcp.Description("Absolute path to the file on disk to upload (mutually exclusive with file_content)")),
			mcp.WithString("file_content",
				mcp.Description("Base64-encoded file content to upload (mutually exclusive with file_path)")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("name parameter is required"), nil
			}

			filePath, hasPath := args["file_path"].(string)
			fileContent, hasContent := args["file_content"].(string)

			// Validate mutual exclusivity: exactly one must be provided
			pathProvided := hasPath && filePath != ""
			contentProvided := hasContent && fileContent != ""

			if !pathProvided && !contentProvided {
				return tools.ErrorResult("exactly one of 'file_path' or 'file_content' must be provided"), nil
			}
			if pathProvided && contentProvided {
				return tools.ErrorResult("exactly one of 'file_path' or 'file_content' must be provided, not both"), nil
			}

			var reader io.Reader
			var size int64

			if contentProvided {
				// Decode base64 content
				decoded, err := base64.StdEncoding.DecodeString(fileContent)
				if err != nil {
					return tools.ErrorResultf("invalid base64 content: %v", err), nil
				}
				reader = bytes.NewReader(decoded)
				size = int64(len(decoded))
			} else {
				// Security: Validate file path
				if err := validateFilePath(filePath); err != nil {
					return tools.ErrorResultf("invalid file path: %v", err), nil
				}

				// Open and read file
				file, err := os.Open(filePath)
				if err != nil {
					return tools.ErrorResultf("failed to open file '%s': %v", filePath, err), nil
				}
				defer file.Close()

				// Get file info for size reporting
				fileInfo, err := file.Stat()
				if err != nil {
					return tools.ErrorResultf("failed to stat file '%s': %v", filePath, err), nil
				}
				reader = file
				size = fileInfo.Size()
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			if err := org.CreatePayloadFromReader(name, reader); err != nil {
				return tools.ErrorResultf("failed to upload payload '%s': %v", name, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":      true,
				"message":      fmt.Sprintf("Successfully uploaded payload '%s' (%d bytes)", name, size),
				"payload_name": name,
				"size":         size,
			}), nil
		},
	})
}

// RegisterGetPayload registers the get_payload tool
func RegisterGetPayload() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_payload",
		Description: "Download a payload to a file on disk",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_payload",
			mcp.WithDescription("Download a payload to a local file path."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name of the payload to retrieve")),
			mcp.WithString("file_path",
				mcp.Required(),
				mcp.Description("Absolute path where to save the payload")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("name parameter is required"), nil
			}

			filePath, ok := args["file_path"].(string)
			if !ok || filePath == "" {
				return tools.ErrorResult("file_path parameter is required"), nil
			}

			// Security: Validate destination path
			if err := validateFilePath(filePath); err != nil {
				return tools.ErrorResultf("invalid file path: %v", err), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			data, err := org.Payload(name)
			if err != nil {
				return tools.ErrorResultf("failed to download payload '%s': %v", name, err), nil
			}

			// Create parent directories if needed
			dir := filepath.Dir(filePath)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return tools.ErrorResultf("failed to create directory '%s': %v", dir, err), nil
			}

			// Write file
			if err := os.WriteFile(filePath, data, 0644); err != nil {
				return tools.ErrorResultf("failed to write file '%s': %v", filePath, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":      true,
				"message":      fmt.Sprintf("Successfully downloaded payload '%s' to '%s'", name, filePath),
				"payload_name": name,
				"file_path":    filePath,
				"size":         len(data),
			}), nil
		},
	})
}

// RegisterDeletePayload registers the delete_payload tool
func RegisterDeletePayload() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_payload",
		Description: "Delete a payload from the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_payload",
			mcp.WithDescription("Delete a payload from the organization. This is permanent and cannot be undone."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name of the payload to delete")),
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

			if err := org.DeletePayload(name); err != nil {
				return tools.ErrorResultf("failed to delete payload '%s': %v", name, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted payload '%s'", name),
			}), nil
		},
	})
}
