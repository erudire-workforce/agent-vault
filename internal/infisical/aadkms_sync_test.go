// EncryptSecrets seals every synced value with row-bound AAD:
// store.CredentialValueAAD(vaultID, key, 0), where version 0 matches what
// replaceCredentialsTx inserts. Run with: go test -tags aadkms ./internal/infisical/
//
// TestEncryptSecrets_RoundTripWithRowAAD SUPERSEDES TestEncryptSecrets_RoundTrip
// (formerly sync_test.go:259), which decrypted with nil AAD and so pinned the
// unbound seal this change removes. The replacement is strictly stronger: it
// round-trips with the matching AAD and also requires the nil-AAD open to
// fail.
//
// Intended signature: EncryptSecrets(vaultID string, secs []Secret, dek []byte) ([]store.EncryptedKV, error).
// The other EncryptSecrets tests in sync_test.go and the callers in
// sync.go and the vault-create handler gain the vaultID argument; their
// assertions do not change.
package infisical

import (
	"testing"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

const (
	aadVaultA = "00000000-0000-4000-8000-00000000000a"
	aadVaultB = "00000000-0000-4000-8000-00000000000b"
)

func TestEncryptSecrets_RoundTripWithRowAAD(t *testing.T) {
	dek := makeDEK(t)
	items, err := EncryptSecrets(aadVaultA, []Secret{{Key: "FOO", Value: "bar"}, {Key: "BAZ", Value: ""}}, dek)
	if err != nil {
		t.Fatalf("EncryptSecrets: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	want := map[string]string{"FOO": "bar", "BAZ": ""}
	for _, it := range items {
		pt, err := store.CredentialValueAAD(aadVaultA, it.Key, 0).Open(it.Ciphertext, it.Nonce, dek)
		if err != nil {
			t.Fatalf("%s does not open with CredentialValueAAD(vault, key, 0): %v", it.Key, err)
		}
		if string(pt) != want[it.Key] {
			t.Fatalf("%s: got %q, want %q", it.Key, pt, want[it.Key])
		}
		if _, err := crypto.Decrypt(it.Ciphertext, it.Nonce, dek); err == nil {
			t.Errorf("%s still opens with nil AAD; the synced value is not row-bound", it.Key)
		}
	}
}

// A value sealed for vault A, key K must not open as another vault, another
// key, or another version.
func TestEncryptSecrets_ValueBoundToVaultKeyAndVersion(t *testing.T) {
	dek := makeDEK(t)
	items, err := EncryptSecrets(aadVaultA, []Secret{{Key: "KEY_K", Value: "SENTINEL-AK-0001"}}, dek)
	if err != nil {
		t.Fatalf("EncryptSecrets: %v", err)
	}
	it := items[0]
	if _, err := store.CredentialValueAAD(aadVaultA, "KEY_K", 0).Open(it.Ciphertext, it.Nonce, dek); err != nil {
		t.Fatalf("control: value does not open as vault A, key K, version 0: %v", err)
	}
	for name, aad := range map[string]crypto.AAD{
		"other vault":   store.CredentialValueAAD(aadVaultB, "KEY_K", 0),
		"other key":     store.CredentialValueAAD(aadVaultA, "KEY_K2", 0),
		"version 1":     store.CredentialValueAAD(aadVaultA, "KEY_K", 1),
		"other table":   store.OAuthRefreshTokenAAD(aadVaultA, "KEY_K", 0),
	} {
		if pt, err := aad.Open(it.Ciphertext, it.Nonce, dek); err == nil {
			t.Errorf("value sealed for vault A, key K opened as %s (%q)", name, pt)
		}
	}
}
