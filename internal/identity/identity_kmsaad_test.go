// Package identity does not exist at v0.40.0. It computes the canonical
// credential identity digest that the fork publishes in
// X-Agent-Vault-Credential-Identity and that a relying service recomputes.
//
// Intended API:
//
//	// NotionDigest parses a Notion GET /v1/users/me response and returns
//	// lowercase hex of sha256("notion" 0x00 bot.workspace_id 0x00 bot.workspace_name 0x00 name).
//	// Errors if any of the three fields is missing, empty, or contains 0x00.
//	func NotionDigest(usersMe []byte) (string, error)
package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// Golden vector, mirrored in internal/crypto/FAILURE_MODES_KMS_AAD.md.
const (
	goldenWorkspaceID   = "ws-00000000-test"
	goldenWorkspaceName = "Example Workspace"
	goldenName          = "example-integration"
	goldenDigest        = "2ef5eef3617ec9f7d8894b36a385469ea039caaf97e100179cb1e70c091edfe1"
)

const goldenUsersMe = `{
  "object": "user",
  "id": "00000000-0000-4000-8000-0000000000b0",
  "name": "example-integration",
  "avatar_url": null,
  "type": "bot",
  "bot": {
    "owner": {"type": "workspace", "workspace": true},
    "workspace_name": "Example Workspace",
    "workspace_id": "ws-00000000-test",
    "workspace_limits": {"max_file_upload_size_in_bytes": 5368709120}
  },
  "request_id": "SENTINEL-AV-TEST-1101"
}`

// The golden constant must equal an independent computation of the formula,
// so a typo in either is caught here rather than on the relying side.
func TestKMSAAD_IdentityGoldenVectorMatchesFormula(t *testing.T) {
	sum := sha256.Sum256([]byte("notion\x00" + goldenWorkspaceID + "\x00" + goldenWorkspaceName + "\x00" + goldenName))
	if hex.EncodeToString(sum[:]) != goldenDigest {
		t.Fatalf("golden vector constant is wrong: formula gives %x", sum)
	}
}

func TestKMSAAD_NotionDigestGolden(t *testing.T) {
	got, err := NotionDigest([]byte(goldenUsersMe))
	if err != nil {
		t.Fatalf("NotionDigest: %v", err)
	}
	if got != goldenDigest {
		t.Fatalf("NotionDigest = %s, want %s", got, goldenDigest)
	}
}

func TestKMSAAD_NotionDigestRefusesMissingFields(t *testing.T) {
	cases := map[string]string{
		"no workspace_id":      strings.Replace(goldenUsersMe, `"workspace_id": "ws-00000000-test",`, ``, 1),
		"no workspace_name":    strings.Replace(goldenUsersMe, `"workspace_name": "Example Workspace",`, ``, 1),
		"no name":              strings.Replace(goldenUsersMe, `"name": "example-integration",`, ``, 1),
		"empty workspace_id":   strings.Replace(goldenUsersMe, `"ws-00000000-test"`, `""`, 1),
		"empty name":           strings.Replace(goldenUsersMe, `"name": "example-integration"`, `"name": ""`, 1),
		"null workspace_name":  strings.Replace(goldenUsersMe, `"Example Workspace"`, `null`, 1),
		"no bot object":        `{"object":"user","id":"x","name":"example-integration","type":"person","person":{}}`,
		"separator in name":    strings.Replace(goldenUsersMe, `"example-integration"`, `"Agent\u0000Vault"`, 1),
		"not json":             `<html>502</html>`,
	}
	for name, body := range cases {
		if d, err := NotionDigest([]byte(body)); err == nil {
			t.Errorf("%s: digest %s recorded; must refuse", name, d)
		}
	}
}
