package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildRuleFromComponents(t *testing.T) {
	tests := []struct {
		name              string
		detect            interface{}
		respond           interface{}
		defaultActionName string
		wantErr           string
		check             func(t *testing.T, result map[string]interface{})
	}{
		{
			name:              "valid detect only",
			detect:            map[string]interface{}{"event": "NEW_PROCESS"},
			respond:           nil,
			defaultActionName: "test-action",
			wantErr:           "",
			check: func(t *testing.T, result map[string]interface{}) {
				assert.NotNil(t, result["detect"])
				respond := result["respond"].([]interface{})
				require.Len(t, respond, 1)
				action := respond[0].(map[string]interface{})
				assert.Equal(t, "report", action["action"])
				assert.Equal(t, "test-action", action["name"])
			},
		},
		{
			name:              "detect and respond array",
			detect:            map[string]interface{}{"event": "NEW_PROCESS"},
			respond:           []interface{}{map[string]interface{}{"action": "task", "command": "foo"}},
			defaultActionName: "ignored",
			wantErr:           "",
			check: func(t *testing.T, result map[string]interface{}) {
				respond := result["respond"].([]interface{})
				require.Len(t, respond, 1)
				action := respond[0].(map[string]interface{})
				assert.Equal(t, "task", action["action"])
			},
		},
		{
			name:              "detect and respond single object",
			detect:            map[string]interface{}{"event": "NEW_PROCESS"},
			respond:           map[string]interface{}{"action": "report", "name": "custom"},
			defaultActionName: "ignored",
			wantErr:           "",
			check: func(t *testing.T, result map[string]interface{}) {
				respond := result["respond"].([]interface{})
				require.Len(t, respond, 1)
				action := respond[0].(map[string]interface{})
				assert.Equal(t, "report", action["action"])
				assert.Equal(t, "custom", action["name"])
			},
		},
		{
			name:              "invalid detect type - string",
			detect:            "not a map",
			respond:           nil,
			defaultActionName: "test",
			wantErr:           "detect must be an object/map",
		},
		{
			name:              "invalid detect type - array",
			detect:            []interface{}{"a", "b"},
			respond:           nil,
			defaultActionName: "test",
			wantErr:           "detect must be an object/map",
		},
		{
			name:              "invalid respond type - string",
			detect:            map[string]interface{}{"event": "NEW_PROCESS"},
			respond:           "not valid",
			defaultActionName: "test",
			wantErr:           "respond must be an array or object",
		},
		{
			name:              "invalid respond type - number",
			detect:            map[string]interface{}{"event": "NEW_PROCESS"},
			respond:           123,
			defaultActionName: "test",
			wantErr:           "respond must be an array or object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := BuildRuleFromComponents(tt.detect, tt.respond, tt.defaultActionName)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				if tt.check != nil {
					tt.check(t, result)
				}
			}
		})
	}
}

func TestGetNamespaceWithDefault(t *testing.T) {
	tests := []struct {
		name string
		args map[string]interface{}
		want string
	}{
		{
			name: "no namespace returns general",
			args: map[string]interface{}{},
			want: "general",
		},
		{
			name: "empty string returns general",
			args: map[string]interface{}{"namespace": ""},
			want: "general",
		},
		{
			name: "explicit general",
			args: map[string]interface{}{"namespace": "general"},
			want: "general",
		},
		{
			name: "managed namespace",
			args: map[string]interface{}{"namespace": "managed"},
			want: "managed",
		},
		{
			name: "service namespace",
			args: map[string]interface{}{"namespace": "service"},
			want: "service",
		},
		{
			name: "wrong type returns general",
			args: map[string]interface{}{"namespace": 123},
			want: "general",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetNamespaceWithDefault(tt.args)
			assert.Equal(t, tt.want, result)
		})
	}
}
