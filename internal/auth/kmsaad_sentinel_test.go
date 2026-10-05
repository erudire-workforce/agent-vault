//go:build kmsaad

// Runtime tests: the DEK sentinel (auth.go:96) and the password-KEK wrap of
// the DEK (auth.go:149) are sealed with nil AAD at v0.40.0. Any other
// DEK-encrypted blob of the right plaintext can then stand in for the
// sentinel, and the wrapped DEK is not bound to its role. Both must carry
// AAD: sentinel -> crypto.AAD{Table:"master_key", Field:"sentinel", Version:1},
// wrapped DEK -> crypto.AAD{Table:"master_key", Field:"dek", Version:1}.
package auth

import (
	"testing"

	"github.com/Infisical/agent-vault/internal/crypto"
)

func TestKMSAAD_SentinelIsAADBound(t *testing.T) {
	mk, rec, err := SetupPasswordless()
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()
	if pt, err := crypto.Decrypt(rec.Sentinel, rec.SentinelNonce, mk.Key()); err == nil {
		t.Fatalf("sentinel opens with nil AAD (%q); it is not bound to master_key/sentinel", pt)
	}
}

// A credential-path ciphertext of the sentinel string (an API caller can make
// the server encrypt any value under the DEK) must not verify as the sentinel.
func TestKMSAAD_SentinelSwapFromCredentialRefused(t *testing.T) {
	mk, rec, err := SetupPasswordless()
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()
	ct, n, err := crypto.Encrypt([]byte(sentinel), mk.Key()) // what POST /v1/credentials stores at v0.40.0
	if err != nil {
		t.Fatal(err)
	}
	rec.Sentinel, rec.SentinelNonce = ct, n
	if got, err := UnlockPasswordless(rec); err == nil {
		got.Wipe()
		t.Fatal("a nil-AAD ciphertext of the sentinel string was accepted as the master_key sentinel")
	}
}

func TestKMSAAD_PasswordWrappedDEKIsAADBound(t *testing.T) {
	pw := []byte("SENTINEL-AV-TEST-0401-password")
	mk, rec, err := SetupWithPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()
	kek := crypto.DeriveKey(pw, rec.Salt, rec.Params)
	defer crypto.WipeBytes(kek)
	if _, err := crypto.Decrypt(rec.DEKCiphertext, rec.DEKNonce, kek); err == nil {
		t.Fatal("password-wrapped DEK opens with nil AAD; it is not bound to master_key/dek")
	}
}
