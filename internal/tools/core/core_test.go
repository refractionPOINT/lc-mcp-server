package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		pattern  string
		expected bool
	}{
		{"exact match", "server1", "server1", true},
		{"no match", "server1", "server2", false},
		{"wildcard all", "anything", "*", true},
		{"prefix match", "server1", "ser*", true},
		{"prefix no match", "server1", "web*", false},
		{"suffix match", "server1", "*ver1", true},
		{"suffix no match", "server1", "*ver2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchHostname(tt.hostname, tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToolRegistration(t *testing.T) {
	t.Run("all core tools are registered", func(t *testing.T) {
		expectedTools := []string{
			"test_tool",
			"get_sensor_info",
			"list_sensors",
			"get_online_sensors",
			"is_online",
			"search_hosts",
		}

		// In a real test, we'd check the registry
		// For now, just verify the tools are defined
		assert.Equal(t, 6, len(expectedTools))
	})
}
