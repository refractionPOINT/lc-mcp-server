package response

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register Binlib binary analysis tools
	RegisterBinlibCheckHash()
	RegisterBinlibGetHashMetadata()
	RegisterBinlibGetHashData()
	RegisterBinlibTag()
	RegisterBinlibUntag()
	RegisterBinlibSearch()
	RegisterBinlibYaraScan()
}

// normalizeBinlibHashes extracts hashes from args, supporting both single "hash" and array "hashes" params
func normalizeBinlibHashes(args map[string]interface{}) []string {
	var hashes []string

	// Handle single hash parameter
	if hash, ok := args["hash"].(string); ok && hash != "" {
		hashes = append(hashes, hash)
	}

	// Handle hashes array parameter
	if hashesArr, ok := args["hashes"].([]interface{}); ok {
		for _, h := range hashesArr {
			if hashStr, ok := h.(string); ok && hashStr != "" {
				hashes = append(hashes, hashStr)
			}
		}
	}

	return hashes
}

// normalizeBinlibTags extracts tags from args, supporting both single "tag" and array "tags" params
func normalizeBinlibTags(args map[string]interface{}) []string {
	var tags []string

	// Handle single tag parameter
	if tag, ok := args["tag"].(string); ok && tag != "" {
		tags = append(tags, tag)
	}

	// Handle tags array parameter
	if tagsArr, ok := args["tags"].([]interface{}); ok {
		for _, t := range tagsArr {
			if tagStr, ok := t.(string); ok && tagStr != "" {
				tags = append(tags, tagStr)
			}
		}
	}

	return tags
}

// RegisterBinlibCheckHash registers the binlib_check_hash tool
// This tool checks if hash(es) have been seen in the binary library
func RegisterBinlibCheckHash() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "binlib_check_hash",
		Description: "Check if SHA256 hash(es) have been seen in the binary library",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("binlib_check_hash",
			mcp.WithDescription("Check if hash(es) have been seen in the binary library"),
			mcp.WithString("hash",
				mcp.Description("Single SHA256 hash to check")),
			mcp.WithArray("hashes",
				mcp.Description("Array of SHA256 hashes to check")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			hashes := normalizeBinlibHashes(args)
			if len(hashes) == 0 {
				return tools.ErrorResult("at least one hash or hashes parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			data := lc.Dict{
				"hashes": hashes,
			}

			resp := lc.Dict{}
			if err := org.ExtensionRequest(&resp, "binlib", "check_hash", data, false); err != nil {
				return tools.ErrorResultf("failed to check hashes: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterBinlibGetHashMetadata registers the binlib_get_hash_metadata tool
// This tool retrieves detailed metadata for binary hash(es)
func RegisterBinlibGetHashMetadata() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "binlib_get_hash_metadata",
		Description: "Get detailed binary metadata for SHA256 hash(es) including PE info, signatures, and tags",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("binlib_get_hash_metadata",
			mcp.WithDescription("Get detailed binary metadata for hash(es)"),
			mcp.WithString("hash",
				mcp.Description("Single SHA256 hash to get metadata for")),
			mcp.WithArray("hashes",
				mcp.Description("Array of SHA256 hashes to get metadata for")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			hashes := normalizeBinlibHashes(args)
			if len(hashes) == 0 {
				return tools.ErrorResult("at least one hash or hashes parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			data := lc.Dict{
				"hashes": hashes,
			}

			resp := lc.Dict{}
			if err := org.ExtensionRequest(&resp, "binlib", "get_hash_metadata", data, false); err != nil {
				return tools.ErrorResultf("failed to get hash metadata: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterBinlibGetHashData registers the binlib_get_hash_data tool
// This tool gets signed URLs to download binary files
func RegisterBinlibGetHashData() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "binlib_get_hash_data",
		Description: "Get signed URLs to download binary files by SHA256 hash(es)",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("binlib_get_hash_data",
			mcp.WithDescription("Get signed URLs to download binaries"),
			mcp.WithString("hash",
				mcp.Description("Single SHA256 hash to get download URL for")),
			mcp.WithArray("hashes",
				mcp.Description("Array of SHA256 hashes to get download URLs for")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			hashes := normalizeBinlibHashes(args)
			if len(hashes) == 0 {
				return tools.ErrorResult("at least one hash or hashes parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			data := lc.Dict{
				"hashes": hashes,
			}

			resp := lc.Dict{}
			if err := org.ExtensionRequest(&resp, "binlib", "get_hash_data", data, false); err != nil {
				return tools.ErrorResultf("failed to get hash data: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterBinlibTag registers the binlib_tag tool
// This tool adds tags to binary hash(es)
func RegisterBinlibTag() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "binlib_tag",
		Description: "Add tags to binary hash(es) in the library",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("binlib_tag",
			mcp.WithDescription("Add tags to hash(es)"),
			mcp.WithString("hash",
				mcp.Description("Single SHA256 hash to tag")),
			mcp.WithArray("hashes",
				mcp.Description("Array of SHA256 hashes to tag")),
			mcp.WithString("tag",
				mcp.Description("Single tag to add")),
			mcp.WithArray("tags",
				mcp.Description("Array of tags to add")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			hashes := normalizeBinlibHashes(args)
			if len(hashes) == 0 {
				return tools.ErrorResult("at least one hash or hashes parameter is required"), nil
			}

			tags := normalizeBinlibTags(args)
			if len(tags) == 0 {
				return tools.ErrorResult("at least one tag or tags parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			data := lc.Dict{
				"hashes": hashes,
				"tags":   tags,
			}

			resp := lc.Dict{}
			if err := org.ExtensionRequest(&resp, "binlib", "tag", data, false); err != nil {
				return tools.ErrorResultf("failed to tag hashes: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterBinlibUntag registers the binlib_untag tool
// This tool removes tags from binary hash(es)
func RegisterBinlibUntag() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "binlib_untag",
		Description: "Remove tags from binary hash(es) in the library",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("binlib_untag",
			mcp.WithDescription("Remove tags from hash(es)"),
			mcp.WithString("hash",
				mcp.Description("Single SHA256 hash to untag")),
			mcp.WithArray("hashes",
				mcp.Description("Array of SHA256 hashes to untag")),
			mcp.WithString("tag",
				mcp.Description("Single tag to remove")),
			mcp.WithArray("tags",
				mcp.Description("Array of tags to remove")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			hashes := normalizeBinlibHashes(args)
			if len(hashes) == 0 {
				return tools.ErrorResult("at least one hash or hashes parameter is required"), nil
			}

			tags := normalizeBinlibTags(args)
			if len(tags) == 0 {
				return tools.ErrorResult("at least one tag or tags parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			data := lc.Dict{
				"hashes": hashes,
				"tags":   tags,
			}

			resp := lc.Dict{}
			if err := org.ExtensionRequest(&resp, "binlib", "untag", data, false); err != nil {
				return tools.ErrorResultf("failed to untag hashes: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterBinlibSearch registers the binlib_search tool
// This tool searches binaries by metadata criteria
func RegisterBinlibSearch() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "binlib_search",
		Description: "Search binaries by metadata criteria (sha256, size, type, imp_hash, tlsh_hash, res_company_name, res_file_description, res_product_version, sig_issuer, sig_subject, sig_serial, sig_authentihash, tag). Operators: =, !=, LIKE, >, <, >=, <=",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("binlib_search",
			mcp.WithDescription("Search binaries by metadata criteria"),
			mcp.WithString("criteria",
				mcp.Required(),
				mcp.Description("JSON array of search criteria: [{\"column\": \"...\", \"operator\": \"...\", \"value\": \"...\"}]. Columns: sha256, size, type, imp_hash, tlsh_hash, res_company_name, res_file_description, res_product_version, sig_issuer, sig_subject, sig_serial, sig_authentihash, tag. Operators: =, !=, LIKE, >, <, >=, <=")),
			mcp.WithNumber("limit",
				mcp.Description("Maximum number of results to return")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			criteriaStr, ok := args["criteria"].(string)
			if !ok || criteriaStr == "" {
				return tools.ErrorResult("criteria parameter is required"), nil
			}

			// Parse criteria JSON
			var criteria []interface{}
			if err := json.Unmarshal([]byte(criteriaStr), &criteria); err != nil {
				return tools.ErrorResultf("invalid criteria JSON: %v", err), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			data := lc.Dict{
				"criteria": criteria,
			}

			// Handle optional limit
			if limit, ok := args["limit"].(float64); ok {
				data["limit"] = int(limit)
			}

			resp := lc.Dict{}
			if err := org.ExtensionRequest(&resp, "binlib", "search", data, false); err != nil {
				return tools.ErrorResultf("failed to search binaries: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}

// RegisterBinlibYaraScan registers the binlib_yara_scan tool
// This tool scans binaries against YARA rules
func RegisterBinlibYaraScan() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "binlib_yara_scan",
		Description: "Scan binaries in the library against YARA rules. Target binaries with criteria OR hash/hashes. Provide rules via rule_names (from yara hive) OR inline rules.",
		Profile:     "live_investigation",
		RequiresOID: true,
		Schema: mcp.NewTool("binlib_yara_scan",
			mcp.WithDescription("Scan binaries against YARA rules"),
			mcp.WithString("criteria",
				mcp.Description("JSON search criteria to select binaries to scan")),
			mcp.WithString("hash",
				mcp.Description("Single SHA256 hash to scan")),
			mcp.WithArray("hashes",
				mcp.Description("Array of SHA256 hashes to scan")),
			mcp.WithArray("rule_names",
				mcp.Description("Array of YARA rule names from org's yara hive")),
			mcp.WithString("rules",
				mcp.Description("Inline YARA rule content")),
			mcp.WithArray("tags_on_match",
				mcp.Description("Tags to automatically add to matching binaries")),
			mcp.WithNumber("limit",
				mcp.Description("Maximum number of binaries to scan")),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			// Check for target binaries - need either criteria or hash/hashes
			criteriaStr, hasCriteria := args["criteria"].(string)
			hashes := normalizeBinlibHashes(args)

			if (!hasCriteria || criteriaStr == "") && len(hashes) == 0 {
				return tools.ErrorResult("either criteria or hash/hashes parameter is required to select target binaries"), nil
			}

			// Check for YARA rules - need either rule_names or rules
			var ruleNames []string
			if ruleNamesArr, ok := args["rule_names"].([]interface{}); ok {
				for _, r := range ruleNamesArr {
					if ruleStr, ok := r.(string); ok && ruleStr != "" {
						ruleNames = append(ruleNames, ruleStr)
					}
				}
			}
			rules, hasRules := args["rules"].(string)

			if len(ruleNames) == 0 && (!hasRules || rules == "") {
				return tools.ErrorResult("either rule_names or rules parameter is required"), nil
			}

			org, err := tools.GetOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			data := lc.Dict{}

			// Add target selection
			if hasCriteria && criteriaStr != "" {
				var criteria []interface{}
				if err := json.Unmarshal([]byte(criteriaStr), &criteria); err != nil {
					return tools.ErrorResultf("invalid criteria JSON: %v", err), nil
				}
				data["criteria"] = criteria
			}
			if len(hashes) > 0 {
				data["hashes"] = hashes
			}

			// Add YARA rules
			if len(ruleNames) > 0 {
				data["rule_names"] = ruleNames
			}
			if hasRules && rules != "" {
				// API expects rules as an array of strings
				data["rules"] = []string{rules}
			}

			// Handle optional tags_on_match
			if tagsOnMatch, ok := args["tags_on_match"].([]interface{}); ok && len(tagsOnMatch) > 0 {
				var tags []string
				for _, t := range tagsOnMatch {
					if tagStr, ok := t.(string); ok && tagStr != "" {
						tags = append(tags, tagStr)
					}
				}
				if len(tags) > 0 {
					data["tags_on_match"] = tags
				}
			}

			// Handle optional limit
			if limit, ok := args["limit"].(float64); ok {
				data["limit"] = int(limit)
			}

			resp := lc.Dict{}
			if err := org.ExtensionRequest(&resp, "binlib", "yara_scan", data, false); err != nil {
				return tools.ErrorResultf("failed to scan binaries: %v", err), nil
			}

			return tools.SuccessResult(resp), nil
		},
	})
}
