// Final-review blocker 2 at the settings API.
package server

import (
	"net/http"
	"testing"

	"github.com/Infisical/agent-vault/internal/servicepolicy"
)

// While the policy mode is active, a vault's unmatched_host_policy cannot be
// switched to passthrough.
func TestFinalFix_PolicyMode_PassthroughSettingRefused(t *testing.T) {
	t.Setenv(servicepolicy.EnvMode, servicepolicy.ModeReadonlyAllowlist)
	e := newKEnv(t, newSQLiteTestDB(t))
	if rec := e.do(http.MethodPatch, "/v1/vaults/default/settings", `{"unmatched_host_policy":"deny"}`, e.ownerToken); rec.Code/100 != 2 {
		t.Fatalf("control: setting deny in policy mode = %d %s", rec.Code, rec.Body.String())
	}
	rec := e.do(http.MethodPatch, "/v1/vaults/default/settings", `{"unmatched_host_policy":"passthrough"}`, e.ownerToken)
	if rec.Code != http.StatusForbidden {
		t.Errorf("PATCH unmatched_host_policy=passthrough in policy mode = %d, want 403", rec.Code)
	}
	if got, _ := e.st.GetVaultSetting(t.Context(), e.vaultID, "unmatched_host_policy"); got == "passthrough" {
		t.Error("unmatched_host_policy was switched to passthrough in policy mode")
	}
}
