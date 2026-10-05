package store

import (
	"context"
	"testing"
)

// The identity record is bound to the credential version, and a recreated
// row restarts its version. Every path that deletes credential rows must
// therefore delete the record too, or a new value inherits the old digest.
func TestCredentialIdentityRecordGoesWithTheRow(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	v, err := s.CreateVault(ctx, "identity-vault")
	if err != nil {
		t.Fatal(err)
	}
	record := func(key string) string {
		val, _ := s.GetVaultSetting(ctx, v.ID, CredentialIdentitySettingKey(key))
		return val
	}
	seed := func(key string) {
		t.Helper()
		if _, err := s.SetCredential(ctx, v.ID, key, []byte("ct"), []byte("nonce")); err != nil {
			t.Fatal(err)
		}
		if err := s.SetVaultSetting(ctx, v.ID, CredentialIdentitySettingKey(key), "1:digest"); err != nil {
			t.Fatal(err)
		}
		if record(key) == "" {
			t.Fatalf("seeding %s: record not written", key)
		}
	}

	seed("TOKEN_A")
	seed("TOKEN_B")
	if err := s.DeleteCredential(ctx, v.ID, "TOKEN_A"); err != nil {
		t.Fatal(err)
	}
	if got := record("TOKEN_A"); got != "" {
		t.Fatalf("identity record %q survived credential delete", got)
	}
	if record("TOKEN_B") == "" {
		t.Fatal("deleting TOKEN_A removed TOKEN_B's identity record")
	}

	// The bulk rewrite (sync / external-store connect) drops the static
	// rows, so it drops their records as well.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.replaceCredentialsTx(ctx, tx, v.ID, s.now(), []EncryptedKV{{Key: "TOKEN_B", Ciphertext: []byte("ct2"), Nonce: []byte("n2")}}); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := record("TOKEN_B"); got != "" {
		t.Fatalf("identity record %q survived credential rewrite", got)
	}
}
