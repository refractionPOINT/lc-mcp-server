package payloads

import (
	"context"
	"fmt"
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
		Description: "Upload a payload from a file on disk",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("create_payload",
			mcp.WithDescription("Upload a payload (executable or script) from a local file to be deployed and executed on sensors. The file extension in the name determines execution type (.exe, .ps1, .bat, .sh)."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name for the payload (include file extension for execution type)")),
			mcp.WithString("file_path",
				mcp.Required(),
				mcp.Description("Absolute path to the file on disk to upload")),
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

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			if err := org.CreatePayloadFromReader(name, file); err != nil {
				return tools.ErrorResultf("failed to upload payload '%s': %v", name, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":      true,
				"message":      fmt.Sprintf("Successfully uploaded payload '%s' (%d bytes)", name, fileInfo.Size()),
				"payload_name": name,
				"size":         fileInfo.Size(),
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
