package hive

import (
	"testing"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMergeUsrMtd covers the rule the whole preservation fix rests on: a hive
// write replaces usr_mtd wholesale, so every field the caller did not override
// has to be carried over from the existing record.
func TestMergeUsrMtd(t *testing.T) {
	existing := lc.UsrMtd{
		Enabled: false,
		Expiry:  1770000000000,
		Tags:    []string{"prod", "reviewed"},
		Comment: "disabled after false positives",
		UIActions: []lc.UIAction{
			{Label: "Run", Location: "sensor"},
		},
	}

	t.Run("no overrides keeps everything", func(t *testing.T) {
		got := MergeUsrMtd(existing, MetadataOverrides{})
		assert.Equal(t, existing, got)
	})

	t.Run("enabled override does not disturb other fields", func(t *testing.T) {
		enabled := true
		got := MergeUsrMtd(existing, MetadataOverrides{Enabled: &enabled})
		assert.True(t, got.Enabled)
		assert.Equal(t, existing.Tags, got.Tags)
		assert.Equal(t, existing.Comment, got.Comment)
		assert.Equal(t, existing.Expiry, got.Expiry)
		assert.Equal(t, existing.UIActions, got.UIActions)
	})

	t.Run("tags override replaces the tag set", func(t *testing.T) {
		got := MergeUsrMtd(existing, MetadataOverrides{Tags: []string{"staging"}})
		assert.Equal(t, []string{"staging"}, got.Tags)
		assert.False(t, got.Enabled, "enabled must not be forced on by a tag change")
		assert.Equal(t, existing.Comment, got.Comment)
	})

	t.Run("empty tags array clears the tags", func(t *testing.T) {
		got := MergeUsrMtd(existing, MetadataOverrides{Tags: []string{}})
		assert.Empty(t, got.Tags)
	})

	t.Run("empty comment clears the comment", func(t *testing.T) {
		comment := ""
		got := MergeUsrMtd(existing, MetadataOverrides{Comment: &comment})
		assert.Equal(t, "", got.Comment)
		assert.Equal(t, existing.Tags, got.Tags)
	})

	t.Run("expiry override keeps the enabled state", func(t *testing.T) {
		expiry := int64(1780000000000)
		got := MergeUsrMtd(existing, MetadataOverrides{Expiry: &expiry})
		assert.Equal(t, expiry, got.Expiry)
		assert.False(t, got.Enabled)
	})

	t.Run("a new record defaults to enabled", func(t *testing.T) {
		got := MergeUsrMtd(lc.UsrMtd{Enabled: true}, MetadataOverrides{})
		assert.True(t, got.Enabled)
		assert.Empty(t, got.Tags)
		assert.Equal(t, "", got.Comment)
	})

	t.Run("a new record can be created disabled", func(t *testing.T) {
		enabled := false
		got := MergeUsrMtd(lc.UsrMtd{Enabled: true}, MetadataOverrides{Enabled: &enabled})
		assert.False(t, got.Enabled)
	})
}

// TestMetadataOverridesIsEmpty verifies the distinction that decides whether a
// write sends a usr_mtd at all: an override that is present but "falsy" still
// counts as a requested change.
func TestMetadataOverridesIsEmpty(t *testing.T) {
	assert.True(t, MetadataOverrides{}.IsEmpty())

	disabled := false
	assert.False(t, MetadataOverrides{Enabled: &disabled}.IsEmpty())

	empty := ""
	assert.False(t, MetadataOverrides{Comment: &empty}.IsEmpty())

	assert.False(t, MetadataOverrides{Tags: []string{}}.IsEmpty())

	expiry := int64(0)
	assert.False(t, MetadataOverrides{Expiry: &expiry}.IsEmpty())
}

func TestParseMetadataOverrides(t *testing.T) {
	t.Run("absent parameters produce no overrides", func(t *testing.T) {
		got, err := ParseMetadataOverrides(map[string]interface{}{"rule_name": "r"})
		require.NoError(t, err)
		assert.True(t, got.IsEmpty())
	})

	t.Run("null parameters produce no overrides", func(t *testing.T) {
		got, err := ParseMetadataOverrides(map[string]interface{}{
			"enabled": nil,
			"tags":    nil,
			"comment": nil,
		})
		require.NoError(t, err)
		assert.True(t, got.IsEmpty())
	})

	t.Run("supplied parameters are parsed", func(t *testing.T) {
		got, err := ParseMetadataOverrides(map[string]interface{}{
			"enabled": false,
			"tags":    []interface{}{"a", "b"},
			"comment": "why",
		})
		require.NoError(t, err)
		require.NotNil(t, got.Enabled)
		assert.False(t, *got.Enabled)
		assert.Equal(t, []string{"a", "b"}, got.Tags)
		require.NotNil(t, got.Comment)
		assert.Equal(t, "why", *got.Comment)
	})

	t.Run("an empty tag array is an explicit clear, not an absent override", func(t *testing.T) {
		got, err := ParseMetadataOverrides(map[string]interface{}{"tags": []interface{}{}})
		require.NoError(t, err)
		require.NotNil(t, got.Tags)
		assert.Empty(t, got.Tags)
		assert.False(t, got.IsEmpty())
	})

	t.Run("wrong types are rejected instead of dropped", func(t *testing.T) {
		_, err := ParseMetadataOverrides(map[string]interface{}{"enabled": "true"})
		assert.Error(t, err)

		_, err = ParseMetadataOverrides(map[string]interface{}{"tags": "a,b"})
		assert.Error(t, err)

		_, err = ParseMetadataOverrides(map[string]interface{}{"tags": []interface{}{"a", 2}})
		assert.Error(t, err)

		_, err = ParseMetadataOverrides(map[string]interface{}{"comment": 7})
		assert.Error(t, err)
	})
}

func TestBriefData(t *testing.T) {
	t.Run("keeps only the index fields", func(t *testing.T) {
		got := BriefData(map[string]interface{}{
			"description": "what it is for",
			"text":        "a very long body",
			"when_to_use": "when X",
		}, "name", "description", "when_to_use")
		assert.Equal(t, map[string]interface{}{
			"description": "what it is for",
			"when_to_use": "when X",
		}, got)
	})

	t.Run("a nil payload stays nil", func(t *testing.T) {
		assert.Nil(t, BriefData(nil, "description"))
	})

	t.Run("a payload without any index field becomes empty", func(t *testing.T) {
		got := BriefData(map[string]interface{}{"text": "body"}, "description")
		assert.Equal(t, map[string]interface{}{}, got)
	})
}

func TestIsRecordNotFound(t *testing.T) {
	assert.False(t, isRecordNotFound(nil))
	assert.False(t, isRecordNotFound(assert.AnError))
	assert.True(t, isRecordNotFound(errRecordNotFound{}))
}

type errRecordNotFound struct{}

func (errRecordNotFound) Error() string {
	return "http status 404: {\"error\": \"RECORD_NOT_FOUND: record name 'x'\"}"
}

// TestSetToolsExposeMetadataOverrides makes sure the tools that write record
// content actually advertise the metadata overrides they honour, and that they
// stay optional — a required `enabled` would reintroduce the forced re-enable
// this whole change exists to remove.
func TestSetToolsExposeMetadataOverrides(t *testing.T) {
	setTools := []string{
		"set_rule",
		"set_cloud_sensor",
		"set_extension_config",
		"set_external_adapter",
		"set_investigation",
		"set_org_note",
		"set_sop",
		"set_saved_query",
		"set_playbook",
		"set_ai_skill",
	}

	for _, name := range setTools {
		t.Run(name, func(t *testing.T) {
			tool, exists := tools.GetTool(name)
			require.True(t, exists, "tool %s should be registered", name)

			schema := tool.Schema.InputSchema
			for _, param := range []string{"enabled", "tags", "comment"} {
				assert.Contains(t, schema.Properties, param,
					"tool %s should expose the %s metadata override", name, param)
				assert.NotContains(t, schema.Required, param,
					"the %s override on %s must stay optional", param, name)
			}
		})
	}
}

// TestBriefListingsExposeBriefParam guards the listing tools whose payloads are
// whole documents: without `brief` a listing dumps every body into the caller's
// context.
func TestBriefListingsExposeBriefParam(t *testing.T) {
	for _, name := range []string{"list_sops", "list_org_notes", "list_ai_skills"} {
		t.Run(name, func(t *testing.T) {
			tool, exists := tools.GetTool(name)
			require.True(t, exists, "tool %s should be registered", name)
			assert.Contains(t, tool.Schema.InputSchema.Properties, "brief")
			assert.NotContains(t, tool.Schema.InputSchema.Required, "brief")
		})
	}
}
