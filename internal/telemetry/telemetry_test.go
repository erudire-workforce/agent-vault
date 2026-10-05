package telemetry

import "testing"

// Telemetry is opt-in in this fork: unset or any value other than an
// explicit "true"/"1" keeps it off.
func TestTelemetryOffByDefault(t *testing.T) {
	for v, disabled := range map[string]bool{
		"": true, "false": true, "0": true, "yes": true, "on": true,
		"true": false, "TRUE": false, "1": false,
	} {
		t.Setenv("AGENT_VAULT_TELEMETRY", v)
		if got := IsDisabled(); got != disabled {
			t.Errorf("AGENT_VAULT_TELEMETRY=%q: IsDisabled() = %v, want %v", v, got, disabled)
		}
	}
	// A nil client (no API key, or never constructed) is a no-op.
	var tel *Telemetry
	tel.CaptureEvent("x", "y", nil)
	tel.Close()
}
