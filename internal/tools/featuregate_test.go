package tools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvestigationEngineEnabledReadsOnlyTrueAndOne(t *testing.T) {
	for value, want := range map[string]bool{
		"": false, "true": true, "TRUE": true, " 1 ": true, "1": true,
		"0": false, "false": false, "yes": false, "on": false, "enabled": false, "tru": false,
	} {
		t.Setenv(EnvInvestigationEngine, value)
		assert.Equal(t, want, InvestigationEngineEnabled(), "%q", value)
	}
}

func TestApplyFeatureGatesRemovesOnlyTheEngineProfilesWhileOff(t *testing.T) {
	mk := func() map[string][]string {
		return map[string][]string{
			"core":                          {"list_sensors"},
			"investigation_engine":          {"investigate_get"},
			"investigation_engine_readonly": {"investigate_get"},
			"live_investigation":            {"run_lcql_query"},
		}
	}

	t.Setenv(EnvInvestigationEngine, "")
	off := mk()
	applyFeatureGates(off)
	assert.Equal(t, map[string][]string{"core": {"list_sensors"}, "live_investigation": {"run_lcql_query"}}, off,
		"existing profiles, including live_investigation, must be untouched")

	t.Setenv(EnvInvestigationEngine, "true")
	on := mk()
	applyFeatureGates(on)
	assert.Equal(t, mk(), on)
}
