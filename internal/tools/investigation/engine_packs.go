package investigation

import (
	"context"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/refractionpoint/lc-mcp-go/internal/tools/hive"
)

const packHive = "investigation_pack"

func init() {
	register("investigate_get_pack", "Read an org-authored fact pack's exact YAML, etag and enabled state. Managed packs are read with investigate_packs. Requires investigation_plan.get.", []mcp.ToolOption{
		mcp.WithString("name", mcp.Required(), mcp.Description("Org pack record name.")),
	}, handleGetPack)
	register("investigate_save_pack", "Create or conditionally replace an org-authored fact pack. Stores exactly {yaml: source} through Hive validation; unknown fields, managed-name collisions and invalid dependencies are rejected by the service. Requires investigation_plan.set. Does not change pinned runs. Use investigate_packs to inspect the resolved pack before using it.", []mcp.ToolOption{
		mcp.WithString("name", mcp.Required(), mcp.Description("Record key matching the pack YAML name.")),
		mcp.WithString("yaml", mcp.Required(), mcp.Description("Exact complete pack YAML with positive version; packs cannot contain use or investigate.")),
		mcp.WithString("etag", mcp.Description("Revision returned by investigate_get_pack to replace; omit to create only.")),
	}, handleSavePack)
	register("investigate_delete_pack", "Delete an org-authored pack. Existing admitted runs retain frozen sources; new admissions with missing dependencies fail closed. Requires investigation_plan.del.", []mcp.ToolOption{
		mcp.WithString("name", mcp.Required(), mcp.Description("Org pack record name.")),
		mcp.WithBoolean("confirm", mcp.Required(), mcp.Description("Must be true to delete.")),
	}, handleDeletePack)
}

func packName(args map[string]interface{}) (string, error) {
	name, err := optString(args, "name")
	if err != nil {
		return "", err
	}
	if !planNameRe.MatchString(name) {
		return "", refusal("invalid pack name")
	}
	return name, nil
}

func handleGetPack(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	name, err := packName(args)
	if err != nil {
		return fail(err)
	}
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return fail(err)
	}
	record, err := hive.NewClient(org).Get(lc.HiveArgs{HiveName: packHive, PartitionKey: org.GetOID(), Key: name})
	if err != nil {
		return fail(err)
	}
	return tools.SuccessResult(map[string]interface{}{"name": name, "yaml": record.Data["yaml"], "etag": record.SysMtd.Etag, "enabled": record.UsrMtd.Enabled}), nil
}

func handleSavePack(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	name, err := packName(args)
	if err != nil {
		return fail(err)
	}
	src, err := optString(args, "yaml")
	if err != nil {
		return fail(err)
	}
	if strings.TrimSpace(src) == "" {
		return tools.ErrorResult("yaml is required"), nil
	}
	etag, err := optString(args, "etag")
	if err != nil {
		return fail(err)
	}
	if _, given := args["etag"]; given && etag == "" {
		return tools.ErrorResult("etag must not be empty"), nil
	}
	if etag == "" {
		etag = createOnlyETag
	}
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return fail(err)
	}
	warning, err := hive.SetRecord(org, hive.RecordWrite{HiveName: packHive, Key: name, Data: lc.Dict{"yaml": src}, ETag: etag})
	if err != nil {
		return fail(err)
	}
	out := map[string]interface{}{"saved": true, "name": name}
	if warning != "" {
		out["hive_warning"] = warning
	}
	return tools.SuccessResult(out), nil
}

func handleDeletePack(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
	name, err := packName(args)
	if err != nil {
		return fail(err)
	}
	confirm, err := optBool(args, "confirm")
	if err != nil {
		return fail(err)
	}
	if !confirm {
		return tools.ErrorResult("confirm=true is required"), nil
	}
	org, err := tools.GetOrganization(ctx)
	if err != nil {
		return fail(err)
	}
	_, err = hive.NewClient(org).Remove(lc.HiveArgs{HiveName: packHive, PartitionKey: org.GetOID(), Key: name})
	if err != nil {
		return fail(err)
	}
	return tools.SuccessResult(map[string]interface{}{"deleted": true, "name": name}), nil
}
