package hive

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

func init() {
	// Register AI skill management tools
	RegisterListAiSkills()
	RegisterGetAiSkill()
	RegisterSetAiSkill()
	RegisterDeleteAiSkill()
}

// aiSkillHive is the hive backing Claude Code skill definitions.
const aiSkillHive = "ai_skill"

// aiSkillIndexFields are the fields that say what a skill is for, i.e. the
// subset a listing needs (matching the python CLI's ai-skill --brief).
var aiSkillIndexFields = []string{"name", "description", "when_to_use"}

// RegisterListAiSkills registers the list_ai_skills tool
func RegisterListAiSkills() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "list_ai_skills",
		Description: "List all AI skill definitions in the organization",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("list_ai_skills",
			mcp.WithDescription("List all AI skill definitions (Claude Code skills) in the organization. The full listing carries every SKILL.md body and bundled file; use brief to get just the index."),
			withBriefParam("the 'name', 'description' and 'when_to_use' fields"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			brief := briefArg(args)

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			hive := lc.NewHiveClient(org)
			skills, err := hive.List(lc.HiveArgs{
				HiveName:     aiSkillHive,
				PartitionKey: org.GetOID(),
			})
			if err != nil {
				return tools.ErrorResultf("failed to list AI skills: %v", err), nil
			}

			result := make(map[string]interface{})
			for name, data := range skills {
				payload := data.Data
				if brief {
					payload = BriefData(payload, aiSkillIndexFields...)
				}
				result[name] = map[string]interface{}{
					"data":     payload,
					"enabled":  data.UsrMtd.Enabled,
					"tags":     data.UsrMtd.Tags,
					"comment":  data.UsrMtd.Comment,
					"metadata": data.SysMtd,
				}
			}

			return tools.SuccessResult(map[string]interface{}{
				"ai_skills": result,
				"count":     len(result),
			}), nil
		},
	})
}

// RegisterGetAiSkill registers the get_ai_skill tool
func RegisterGetAiSkill() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "get_ai_skill",
		Description: "Get a specific AI skill definition",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("get_ai_skill",
			mcp.WithDescription("Get a specific AI skill definition: the SKILL.md body (content), its frontmatter fields and any bundled supporting files"),
			mcp.WithString("skill_name",
				mcp.Required(),
				mcp.Description("Name of the AI skill to retrieve")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			skillName, ok := args["skill_name"].(string)
			if !ok || skillName == "" {
				return tools.ErrorResult("skill_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			hive := lc.NewHiveClient(org)
			skill, err := hive.Get(lc.HiveArgs{
				HiveName:     aiSkillHive,
				PartitionKey: org.GetOID(),
				Key:          skillName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to get AI skill '%s': %v", skillName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"ai_skill": map[string]interface{}{
					"name":    skillName,
					"data":    skill.Data,
					"enabled": skill.UsrMtd.Enabled,
					"tags":    skill.UsrMtd.Tags,
					"comment": skill.UsrMtd.Comment,
					"metadata": map[string]interface{}{
						"created_at":  skill.SysMtd.CreatedAt,
						"created_by":  skill.SysMtd.CreatedBy,
						"last_mod":    skill.SysMtd.LastMod,
						"last_author": skill.SysMtd.LastAuthor,
						"guid":        skill.SysMtd.GUID,
					},
				},
			}), nil
		},
	})
}

// RegisterSetAiSkill registers the set_ai_skill tool
func RegisterSetAiSkill() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "set_ai_skill",
		Description: "Create or update an AI skill definition",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("set_ai_skill",
			mcp.WithDescription("Create or update an AI skill definition (a Claude Code skill). Updating an existing skill preserves its metadata (enabled state, tags, comment and the UI action buttons) unless enabled/tags/comment are given."),
			mcp.WithString("skill_name",
				mcp.Required(),
				mcp.Description("Name for the AI skill (the record key)")),
			mcp.WithObject("skill_data",
				mcp.Required(),
				mcp.Description("Skill definition. Required: content (the SKILL.md body, markdown). "+
					"Optional frontmatter, mirroring the on-disk SKILL.md keys verbatim: name (slug [a-z0-9-]{1,64}, defaults to the record key), "+
					"description, when_to_use (description + when_to_use must stay under 1536 characters combined), argument-hint, "+
					"arguments (array or space-separated string), disable-model-invocation (bool), user-invocable (bool), "+
					"allowed-tools (array or space-separated string), model, effort (low|medium|high|xhigh|max), context (fork), "+
					"agent (only meaningful with context=fork), hooks (object), paths (array or comma-separated string), shell (bash|powershell). "+
					"Optional files: an object of supporting files keyed by path relative to the skill root (max 100; SKILL.md is reserved). "+
					"Unknown fields are rejected by the server.")),
			WithMetadataOverrideParams(),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			skillName, ok := args["skill_name"].(string)
			if !ok || skillName == "" {
				return tools.ErrorResult("skill_name parameter is required"), nil
			}

			skillData, ok := args["skill_data"].(map[string]interface{})
			if !ok {
				return tools.ErrorResult("skill_data parameter is required and must be an object"), nil
			}
			if content, _ := skillData["content"].(string); content == "" {
				return tools.ErrorResult("skill_data must contain a non-empty 'content' field holding the SKILL.md body"), nil
			}

			overrides, err := ParseMetadataOverrides(args)
			if err != nil {
				return tools.ErrorResultf("%v", err), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			warning, err := SetRecord(org, RecordWrite{
				HiveName:  aiSkillHive,
				Key:       skillName,
				Data:      lc.Dict(skillData),
				Overrides: overrides,
			})
			if err != nil {
				return tools.ErrorResultf("failed to set AI skill '%s': %v", skillName, err), nil
			}

			result := map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully created/updated AI skill '%s'", skillName),
			}
			if warning != "" {
				result["warning"] = warning
			}
			return tools.SuccessResult(result), nil
		},
	})
}

// RegisterDeleteAiSkill registers the delete_ai_skill tool
func RegisterDeleteAiSkill() {
	tools.RegisterTool(&tools.ToolRegistration{
		Name:        "delete_ai_skill",
		Description: "Delete an AI skill definition",
		Profile:     "platform_admin",
		RequiresOID: true,
		Schema: mcp.NewTool("delete_ai_skill",
			mcp.WithDescription("Delete an AI skill definition"),
			mcp.WithString("skill_name",
				mcp.Required(),
				mcp.Description("Name of the AI skill to delete")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		Handler: func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			skillName, ok := args["skill_name"].(string)
			if !ok || skillName == "" {
				return tools.ErrorResult("skill_name parameter is required"), nil
			}

			org, err := getOrganization(ctx)
			if err != nil {
				return tools.ErrorResultf("failed to get organization: %v", err), nil
			}

			hive := lc.NewHiveClient(org)
			_, err = hive.Remove(lc.HiveArgs{
				HiveName:     aiSkillHive,
				PartitionKey: org.GetOID(),
				Key:          skillName,
			})
			if err != nil {
				return tools.ErrorResultf("failed to delete AI skill '%s': %v", skillName, err), nil
			}

			return tools.SuccessResult(map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Successfully deleted AI skill '%s'", skillName),
			}), nil
		},
	})
}
