// Final-review item 4.
package cmd

import (
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/servicepolicy"
)

// KMS *enabled* (a key id configured) without the policy mode refuses
// startup, even when AGENT_VAULT_REQUIRE_KMS is not set.
func TestFinalFix_HardenedStartupRefusesKMSEnabledWithoutPolicyMode(t *testing.T) {
	isolateEnv(t)
	unsetenv(t, servicepolicy.EnvMode)
	t.Setenv("AGENT_VAULT_KMS_KEY_ID", fakeAliasA)
	t.Setenv("AGENT_VAULT_KMS_ENCRYPTION_CONTEXT_ENV", envNameProd)
	unsetenv(t, "AGENT_VAULT_REQUIRE_KMS")

	err := requirePolicyModeForHardenedDeployments()
	if err == nil || !strings.Contains(err.Error(), servicepolicy.EnvMode) {
		t.Errorf("startup with AGENT_VAULT_KMS_KEY_ID set and no %s returned %v; want a refusal naming %s",
			servicepolicy.EnvMode, err, servicepolicy.EnvMode)
	}

	t.Setenv(servicepolicy.EnvMode, servicepolicy.ModeReadonlyAllowlist)
	if err := requirePolicyModeForHardenedDeployments(); err != nil {
		t.Errorf("control: KMS enabled with the policy mode active refused: %v", err)
	}
	unsetenv(t, servicepolicy.EnvMode)
	unsetenv(t, "AGENT_VAULT_KMS_KEY_ID")
	unsetenv(t, "AGENT_VAULT_KMS_ENCRYPTION_CONTEXT_ENV")
	if err := requirePolicyModeForHardenedDeployments(); err != nil {
		t.Errorf("control: a plain deployment (no KMS, no bootstrap) refused: %v", err)
	}
}
