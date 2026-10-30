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

const (
	// maxInlineUploadBytes bounds the decoded size of file_content. The HTTP
	// transport caps a whole request at 10 MiB, and base64 inflates content by 4/3,
	// so 7 MiB of payload (about 9.3 MiB encoded) is the most that can arrive in one
	// call with room left for the JSON envelope. The same bound applies in stdio so
	// the tool behaves the same everywhere; larger files go through file_path there.
	maxInlineUploadBytes = 7 * 1024 * 1024

	// maxInlineDownloadBytes bounds how much payload get_payload returns inline
	// (base64) when no file_path is given. Results above the large-result threshold
	// are moved to storage by the shared result wrapper when it is configured; this
	// cap keeps one call from materialising an unbounded response regardless.
	maxInlineDownloadBytes = 25 * 1024 * 1024

	inHTTPAlternativeUpload   = "Send the content inline instead: pass 'file_content' as base64 (up to 7 MiB decoded) and omit 'file_path'."
	inHTTPAlternativeDownload = "Omit 'file_path': the payload is returned inline as base64 in 'content_base64' (up to 25 MiB)."
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
			mcp.WithReadOnlyHintAnnotation(true),
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
		Description: "Upload a payload from base64-encoded content (or, on a local stdio server only, a file on disk)",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("create_payload",
			mcp.WithDescription("Upload a payload (executable or script) to be deployed and executed on sensors. The file extension in the name determines execution type (.exe, .ps1, .bat, .sh). Send the content inline as file_content (base64-encoded, up to 7 MiB decoded) - this works everywhere and is what to use against the hosted server. file_path (a file on the machine running the MCP server) is only honored by a local stdio server and is refused by the hosted HTTP server. Provide either file_content OR file_path, not both."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name for the payload (include file extension for execution type)")),
			mcp.WithString("file_path",
				mcp.Description("Local stdio server only: absolute path to a file on the machine running the MCP server (mutually exclusive with file_content). Refused by the hosted HTTP server; use file_content there")),
			mcp.WithString("file_content",
				mcp.Description("Base64-encoded file content to upload, up to 7 MiB decoded (mutually exclusive with file_path). Works on every server")),
			mcp.WithDestructiveHintAnnotation(false),
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

			// A caller-chosen path is only honored on the caller's own machine. Over
			// HTTP it would read the shared server's filesystem into the caller's org.
			if pathProvided {
				if refusal := tools.RefuseServerFilesystem(ctx, "create_payload", "file_path", inHTTPAlternativeUpload); refusal != nil {
					return refusal, nil
				}
			}

			if !pathProvided && !contentProvided {
				return tools.ErrorResult("exactly one of 'file_path' or 'file_content' must be provided"), nil
			}
			if pathProvided && contentProvided {
				return tools.ErrorResult("exactly one of 'file_path' or 'file_content' must be provided, not both"), nil
			}

			var reader io.Reader
			var size int64

			if contentProvided {
				// Reject on the encoded length first so an oversized value is never
				// decoded into memory.
				if len(fileContent) > base64.StdEncoding.EncodedLen(maxInlineUploadBytes) {
					return tools.ErrorResultf("file_content is too large: at most %d bytes (7 MiB) of decoded content can be sent inline", maxInlineUploadBytes), nil
				}
				decoded, err := base64.StdEncoding.DecodeString(fileContent)
				if err != nil {
					return tools.ErrorResultf("invalid base64 content: %v", err), nil
				}
				if len(decoded) > maxInlineUploadBytes {
					return tools.ErrorResultf("file_content is too large: %d bytes decoded, at most %d bytes (7 MiB) can be sent inline", len(decoded), maxInlineUploadBytes), nil
				}
				reader = bytes.NewReader(decoded)
				size = int64(len(decoded))
			} else {
				// stdio only from here: validate the path, then stream the file.
				if err := validateFilePath(filePath); err != nil {
					return tools.ErrorResultf("invalid file path: %v", err), nil
				}

				file, err := os.Open(filePath)
				if err != nil {
					return tools.ErrorResultf("failed to open file '%s': %v", filePath, err), nil
				}
				defer file.Close()

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
		Description: "Download a payload (returned inline as base64, or saved to a file on a local stdio server)",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_payload",
			mcp.WithDescription("Download a payload. By default the content is returned inline, base64-encoded in 'content_base64' (up to 25 MiB) - this works everywhere and is what to use against the hosted server. file_path (save to a file on the machine running the MCP server) is only honored by a local stdio server and is refused by the hosted HTTP server."),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Name of the payload to retrieve")),
			mcp.WithString("file_path",
				mcp.Description("Local stdio server only: absolute path on the machine running the MCP server where to save the payload. Omit to receive the content inline as base64. Refused by the hosted HTTP server")),
			// Without file_path it only reads from LimaCharlie. With file_path (stdio
			// only) it writes the local filesystem, so it is not a read-only tool.
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			name, ok := args["name"].(string)
			if !ok || name == "" {
				return tools.ErrorResult("name parameter is required"), nil
			}

			filePath, _ := args["file_path"].(string)
			toFile := filePath != ""
			if toFile {
				// A caller-chosen destination is only honored on the caller's own
				// machine. Over HTTP it would overwrite files on the shared server.
				if refusal := tools.RefuseServerFilesystem(ctx, "get_payload", "file_path", inHTTPAlternativeDownload); refusal != nil {
					return refusal, nil
				}
				if err := validateFilePath(filePath); err != nil {
					return tools.ErrorResultf("invalid file path: %v", err), nil
				}
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			data, err := org.Payload(name)
			if err != nil {
				return tools.ErrorResultf("failed to download payload '%s': %v", name, err), nil
			}

			if !toFile {
				if len(data) > maxInlineDownloadBytes {
					return tools.ErrorResultf("payload '%s' is %d bytes, above the %d byte (25 MiB) limit for inline retrieval", name, len(data), maxInlineDownloadBytes), nil
				}
				return tools.SuccessResult(map[string]interface{}{
					"success":        true,
					"payload_name":   name,
					"size":           len(data),
					"encoding":       "base64",
					"content_base64": base64.StdEncoding.EncodeToString(data),
				}), nil
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
