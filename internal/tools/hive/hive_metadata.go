package hive

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	RegisterSetHiveRecordEnabled()
	RegisterSetHiveRecordTags()
	RegisterSetHiveRecordComment()
	RegisterRenameHiveRecord()
}

// applyTagAction computes the resulting tag set given an action.
// action is one of "set", "add", "remove". For "set" the provided tags
// replace the existing ones. For "add"/"remove" the provided tags are
// merged into / removed from the existing set.
func applyTagAction(existing []string, tags []string, action string) []string {
	switch action {
	case "add":
		result := append([]string{}, existing...)
		for _, t := range tags {
			found := false
			for _, e := range result {
				if e == t {
					found = true
					break
				}
			}
			if !found {
				result = append(result, t)
			}
		}
		return result
	case "remove":
		remove := map[string]bool{}
		for _, t := range tags {
			remove[t] = true
		}
		result := []string{}
		for _, e := range existing {
			if !remove[e] {
				result = append(result, e)
			}
		}
		return result
	default: // "set"
		return tags
	}
}

// stringSlice converts an interface array argument into a []string.
func stringSlice(v interface{}) ([]string, bool) {
	arr, ok := v.([]interface{})
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// updateRecordMTD reads the existing record metadata for a hive record and
// applies the provided mutation while preserving all other usr_mtd fields.
// The mutate callback receives a copy of the existing UsrMtd and returns the
// HiveArgs metadata fields to send. We always pass every preserved field so
// the API does not clobber the ones we did not intend to change.
func updateRecordMTD(org *lc.Organization, hiveName, partitionKey, key string, mutate func(existing lc.UsrMtd) lc.HiveArgs) error {
	client := lc.NewHiveClient(org)

	existing, err := client.GetMTD(lc.HiveArgs{
		HiveName:     hiveName,
		PartitionKey: partitionKey,
		Key:          key,
	})
	if err != nil {
		return err
	}

	args := mutate(existing.UsrMtd)
	args.HiveName = hiveName
	args.PartitionKey = partitionKey
	args.Key = key

	_, err = client.Update(args)
	return err
}

// preservedArgs returns HiveArgs that carry all of the existing usr_mtd fields
// so Update (which rebuilds usr_mtd purely from args) does not drop any of them.
func preservedArgs(existing lc.UsrMtd) lc.HiveArgs {
	enabled := existing.Enabled
	expiry := existing.Expiry
	comment := existing.Comment
	args := lc.HiveArgs{
		Enabled: &enabled,
		Comment: &comment,
		Tags:    existing.Tags,
	}
	if expiry != 0 {
		args.Expiry = &expiry
	}
	// Ensure Tags is non-nil so the existing tags are always sent.
	if args.Tags == nil {
		args.Tags = []string{}
	}
	return args
}

// RegisterSetHiveRecordEnabled registers the set_hive_record_enabled tool
func RegisterSetHiveRecordEnabled() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_hive_record_enabled",
		Description: "Enable/disable any hive record (preserves config)",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_hive_record_enabled",
			mcp.WithDescription("Enable or disable any hive record while preserving its config, tags and comment"),
			mcp.WithString("hive_name",
				mcp.Required(),
				mcp.Description("Name of the hive")),
			mcp.WithString("key",
				mcp.Required(),
				mcp.Description("Key (record name)")),
			mcp.WithBoolean("enabled",
				mcp.Required(),
				mcp.Description("Whether the record should be enabled")),
			mcp.WithString("partition_key",
				mcp.Description("Hive partition (defaults to the organization OID)")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			hiveName, ok := args["hive_name"].(string)
			if !ok || hiveName == "" {
				return tools.ErrorResult("hive_name parameter is required"), nil
			}
			key, ok := args["key"].(string)
			if !ok || key == "" {
				return tools.ErrorResult("key parameter is required"), nil
			}
			enabled, ok := args["enabled"].(bool)
			if !ok {
				return tools.ErrorResult("enabled parameter is required and must be a boolean"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			partitionKey, _ := args["partition_key"].(string)
			if partitionKey == "" {
				partitionKey = org.GetOID()
			}

			err = updateRecordMTD(org, hiveName, partitionKey, key, func(existing lc.UsrMtd) lc.HiveArgs {
				a := preservedArgs(existing)
				e := enabled
				a.Enabled = &e
				return a
			})
			if err != nil {
				return tools.ErrorResultf("failed to set enabled on '%s' in hive '%s': %v", key, hiveName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":   true,
				"hive_name": hiveName,
				"key":       key,
				"enabled":   enabled,
				"message":   fmt.Sprintf("Set enabled=%v on record '%s' in hive '%s'", enabled, key, hiveName),
			}), nil
		},
	})
}

// RegisterSetHiveRecordTags registers the set_hive_record_tags tool
func RegisterSetHiveRecordTags() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_hive_record_tags",
		Description: "Set/add/remove tags on any hive record",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_hive_record_tags",
			mcp.WithDescription("Set, add or remove tags on any hive record while preserving its other metadata"),
			mcp.WithString("hive_name",
				mcp.Required(),
				mcp.Description("Name of the hive")),
			mcp.WithString("key",
				mcp.Required(),
				mcp.Description("Key (record name)")),
			mcp.WithArray("tags",
				mcp.Required(),
				mcp.Description("Tags to apply")),
			mcp.WithString("action",
				mcp.Description("How to apply the tags: 'set' (default), 'add', or 'remove'")),
			mcp.WithString("partition_key",
				mcp.Description("Hive partition (defaults to the organization OID)")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			hiveName, ok := args["hive_name"].(string)
			if !ok || hiveName == "" {
				return tools.ErrorResult("hive_name parameter is required"), nil
			}
			key, ok := args["key"].(string)
			if !ok || key == "" {
				return tools.ErrorResult("key parameter is required"), nil
			}
			tags, ok := stringSlice(args["tags"])
			if !ok {
				return tools.ErrorResult("tags parameter is required and must be an array of strings"), nil
			}
			action, _ := args["action"].(string)
			if action == "" {
				action = "set"
			}
			if action != "set" && action != "add" && action != "remove" {
				return tools.ErrorResult("action must be one of 'set', 'add', or 'remove'"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			partitionKey, _ := args["partition_key"].(string)
			if partitionKey == "" {
				partitionKey = org.GetOID()
			}

			var newTags []string
			err = updateRecordMTD(org, hiveName, partitionKey, key, func(existing lc.UsrMtd) lc.HiveArgs {
				a := preservedArgs(existing)
				newTags = applyTagAction(existing.Tags, tags, action)
				if newTags == nil {
					newTags = []string{}
				}
				a.Tags = newTags
				return a
			})
			if err != nil {
				return tools.ErrorResultf("failed to set tags on '%s' in hive '%s': %v", key, hiveName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":   true,
				"hive_name": hiveName,
				"key":       key,
				"action":    action,
				"tags":      newTags,
			}), nil
		},
	})
}

// RegisterSetHiveRecordComment registers the set_hive_record_comment tool
func RegisterSetHiveRecordComment() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_hive_record_comment",
		Description: "Set the comment on any hive record",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_hive_record_comment",
			mcp.WithDescription("Set the comment on any hive record while preserving its other metadata"),
			mcp.WithString("hive_name",
				mcp.Required(),
				mcp.Description("Name of the hive")),
			mcp.WithString("key",
				mcp.Required(),
				mcp.Description("Key (record name)")),
			mcp.WithString("comment",
				mcp.Required(),
				mcp.Description("Comment to set")),
			mcp.WithString("partition_key",
				mcp.Description("Hive partition (defaults to the organization OID)")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			hiveName, ok := args["hive_name"].(string)
			if !ok || hiveName == "" {
				return tools.ErrorResult("hive_name parameter is required"), nil
			}
			key, ok := args["key"].(string)
			if !ok || key == "" {
				return tools.ErrorResult("key parameter is required"), nil
			}
			comment, ok := args["comment"].(string)
			if !ok {
				return tools.ErrorResult("comment parameter is required and must be a string"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			partitionKey, _ := args["partition_key"].(string)
			if partitionKey == "" {
				partitionKey = org.GetOID()
			}

			err = updateRecordMTD(org, hiveName, partitionKey, key, func(existing lc.UsrMtd) lc.HiveArgs {
				a := preservedArgs(existing)
				c := comment
				a.Comment = &c
				return a
			})
			if err != nil {
				return tools.ErrorResultf("failed to set comment on '%s' in hive '%s': %v", key, hiveName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":   true,
				"hive_name": hiveName,
				"key":       key,
				"comment":   comment,
			}), nil
		},
	})
}

// RegisterRenameHiveRecord registers the rename_hive_record tool
func RegisterRenameHiveRecord() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "rename_hive_record",
		Description: "Rename a hive record",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("rename_hive_record",
			mcp.WithDescription("Rename a hive record"),
			mcp.WithString("hive_name",
				mcp.Required(),
				mcp.Description("Name of the hive")),
			mcp.WithString("key",
				mcp.Required(),
				mcp.Description("Current key (record name)")),
			mcp.WithString("new_name",
				mcp.Required(),
				mcp.Description("New name for the record")),
			mcp.WithString("partition_key",
				mcp.Description("Hive partition (defaults to the organization OID)")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			hiveName, ok := args["hive_name"].(string)
			if !ok || hiveName == "" {
				return tools.ErrorResult("hive_name parameter is required"), nil
			}
			key, ok := args["key"].(string)
			if !ok || key == "" {
				return tools.ErrorResult("key parameter is required"), nil
			}
			newName, ok := args["new_name"].(string)
			if !ok || newName == "" {
				return tools.ErrorResult("new_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			partitionKey, _ := args["partition_key"].(string)
			if partitionKey == "" {
				partitionKey = org.GetOID()
			}

			client := lc.NewHiveClient(org)
			_, err = client.Rename(lc.HiveArgs{
				HiveName:     hiveName,
				PartitionKey: partitionKey,
				Key:          key,
			}, newName)
			if err != nil {
				return tools.ErrorResultf("failed to rename '%s' to '%s' in hive '%s': %v", key, newName, hiveName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success":   true,
				"hive_name": hiveName,
				"old_name":  key,
				"new_name":  newName,
			}), nil
		},
	})
}
