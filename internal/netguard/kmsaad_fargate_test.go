// The ECS/Fargate task credentials endpoint (169.254.170.2) hands out the
// task role's AWS credentials. It must be blocked unconditionally, like IMDS,
// including with AGENT_VAULT_ALLOW_PRIVATE_RANGES=true and when an allowlist
// entry covers it. At v0.40.0 it is only in the private link-local range, so
// allowPrivate unblocks it.
package netguard

import (
	"net"
	"testing"
)

func TestKMSAAD_FargateCredentialsEndpointAlwaysBlocked(t *testing.T) {
	ip := net.ParseIP("169.254.170.2")
	cover := ParseCIDRList("169.254.0.0/16,169.254.170.2", "test")
	for name, c := range map[string]struct {
		allowPrivate bool
		allowed      []net.IPNet
	}{
		"default":                       {false, nil},
		"allow private ranges":          {true, nil},
		"allowlist covers it":           {false, cover},
		"allow private and allowlisted": {true, cover},
	} {
		if !isBlockedIP(ip, c.allowPrivate, c.allowed) {
			t.Errorf("%s: 169.254.170.2 (ECS/Fargate credentials endpoint) is not blocked", name)
		}
		if err := checkDialAddress("169.254.170.2:80", c.allowPrivate, c.allowed); err == nil {
			t.Errorf("%s: dial to 169.254.170.2:80 permitted", name)
		}
	}
	// Control: IMDS is already always blocked upstream.
	if !isBlockedIP(net.ParseIP("169.254.169.254"), true, cover) {
		t.Fatal("control: IMDS not blocked")
	}
}

func TestKMSAAD_FargateEndpointBlockedViaEnv(t *testing.T) {
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "169.254.170.2")
	if err := checkDialAddress("169.254.170.2:80", AllowPrivateFromEnv(), AllowlistFromEnv()); err == nil {
		t.Fatal("169.254.170.2 reachable with AGENT_VAULT_ALLOW_PRIVATE_RANGES=true")
	}
}
