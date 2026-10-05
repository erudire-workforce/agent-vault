// Package aadmigrate does not exist at v0.40.0. These tests pin the one-time
// migration of legacy (nil-AAD) ciphertexts to row-bound AAD on the SQLite
// store. Until the package is written they fail to compile with
// "undefined: Run" / "undefined: IsComplete", confined to this directory.
//
// Intended API (see internal/crypto/FAILURE_MODES_KMS_AAD.md, "Contract"):
//
//	type Result struct{ Rewrapped, AlreadyBound int }
//	func Run(ctx context.Context, db store.Store, dek []byte) (Result, error)
//	func IsComplete(ctx context.Context, db store.Store) (bool, error)
//	func RunCAKeyFile(dir string, dek []byte) error // file-backed CA root key (SQLite deployments)
//
// Row versions: store.Credential.Version, store.CredentialOAuth.Version and
// store.EncryptedCredential.Version (uint64), bumped on every write.
// AAD per field, see crypto.AAD:
//
//	credentials.ciphertext               -> {"credentials", "value", vault_id, key, version}
//	credential_oauth.refresh_token_ct    -> {"credential_oauth", "refresh_token", vault_id, credential_key, version}
//	credential_oauth.client_secret_ct    -> {"credential_oauth", "client_secret", vault_id, credential_key, version}
//	proposal_credentials.ciphertext      -> {"proposal_credentials", "value", vault_id, "<proposal_id>:<key>", version}
//	CA root key (file or ca_state)       -> {"ca_root_key", "root_key", "", "", version}
package aadmigrate

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/server"
	"github.com/Infisical/agent-vault/internal/store"
)

type env struct {
	db      store.Store
	dek     []byte
	vaultID string
	tdb     testDB
}

func newEnv(t *testing.T, tdb testDB) *env {
	t.Helper()
	db := tdb.Open(t)
	v, err := db.GetVault(context.Background(), store.DefaultVault)
	if err != nil || v == nil {
		t.Fatalf("default vault: %v", err)
	}
	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	return &env{db: db, dek: dek, vaultID: v.ID, tdb: tdb}
}

// legacy writes a v0.40.0-format (nil AAD) static credential.
func (e *env) legacy(t *testing.T, key, value string) {
	t.Helper()
	ct, nonce, err := crypto.Encrypt([]byte(value), e.dek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.SetCredential(context.Background(), e.vaultID, key, ct, nonce); err != nil {
		t.Fatal(err)
	}
}

// legacyOAuth writes a v0.40.0-format OAuth credential: access token in
// credentials, refresh token and client secret in credential_oauth.
func (e *env) legacyOAuth(t *testing.T, key, access, refresh, clientSecret string) {
	t.Helper()
	ctx := context.Background()
	enc := func(s string) ([]byte, []byte) {
		ct, n, err := crypto.Encrypt([]byte(s), e.dek)
		if err != nil {
			t.Fatal(err)
		}
		return ct, n
	}
	if _, err := e.db.SetCredential(ctx, e.vaultID, key, nil, nil); err != nil {
		t.Fatal(err)
	}
	csCT, csN := enc(clientSecret)
	if err := e.db.SetCredentialOAuth(ctx, &store.CredentialOAuth{
		VaultID: e.vaultID, CredentialKey: key, TokenURL: "https://token.example.test/token",
		ClientID: "cid", ClientSecretCT: csCT, ClientSecretNonce: csN,
	}); err != nil {
		t.Fatal(err)
	}
	aCT, aN := enc(access)
	rCT, rN := enc(refresh)
	exp := time.Now().Add(time.Hour)
	if err := e.db.UpdateCredentialOAuthTokens(ctx, e.vaultID, key, aCT, aN, rCT, rN, &exp); err != nil {
		t.Fatal(err)
	}
}

func (e *env) openValue(t *testing.T, key string) (string, error) {
	t.Helper()
	c, err := e.db.GetCredential(context.Background(), e.vaultID, key)
	if err != nil {
		return "", err
	}
	aad, err := crypto.AAD{Table: "credentials", Field: "value", VaultID: e.vaultID, Key: key, Version: c.Version}.Bytes()
	if err != nil {
		return "", err
	}
	pt, err := crypto.DecryptAAD(c.Ciphertext, c.Nonce, e.dek, aad)
	return string(pt), err
}

func (e *env) openOAuth(t *testing.T, key, field string) (string, error) {
	t.Helper()
	o, err := e.db.GetCredentialOAuth(context.Background(), e.vaultID, key)
	if err != nil {
		return "", err
	}
	aad, err := crypto.AAD{Table: "credential_oauth", Field: field, VaultID: e.vaultID, Key: key, Version: o.Version}.Bytes()
	if err != nil {
		return "", err
	}
	ct, n := o.RefreshTokenCT, o.RefreshTokenNonce
	if field == "client_secret" {
		ct, n = o.ClientSecretCT, o.ClientSecretNonce
	}
	pt, err := crypto.DecryptAAD(ct, n, e.dek, aad)
	return string(pt), err
}

func TestKMSAAD_Migration_RewrapsAllLegacyRows(t *testing.T) { forEachBackend(t, testKMSAAD_Migration_RewrapsAllLegacyRows) }

func testKMSAAD_Migration_RewrapsAllLegacyRows(t *testing.T, tdb testDB) {
	ctx := context.Background()
	e := newEnv(t, tdb)
	e.legacy(t, "STATIC_ONE", "SENTINEL-AV-TEST-0101")
	e.legacy(t, "STATIC_TWO", "SENTINEL-AV-TEST-0102")
	e.legacy(t, "EMPTY_VALUE", "")
	e.legacyOAuth(t, "GH_OAUTH", "SENTINEL-AV-TEST-0103-access", "SENTINEL-AV-TEST-0104-refresh", "SENTINEL-AV-TEST-0105-cs")

	if done, err := IsComplete(ctx, e.db); err != nil || done {
		t.Fatalf("IsComplete before Run = %v, %v; want false", done, err)
	}
	res, err := Run(ctx, e.db, e.dek)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Rewrapped < 6 { // 3 static + access + refresh + client secret
		t.Fatalf("Rewrapped = %d, want >= 6", res.Rewrapped)
	}
	if done, err := IsComplete(ctx, e.db); err != nil || !done {
		t.Fatalf("IsComplete after Run = %v, %v; want true", done, err)
	}
	for key, want := range map[string]string{
		"STATIC_ONE": "SENTINEL-AV-TEST-0101", "STATIC_TWO": "SENTINEL-AV-TEST-0102",
		"EMPTY_VALUE": "", "GH_OAUTH": "SENTINEL-AV-TEST-0103-access",
	} {
		got, err := e.openValue(t, key)
		if err != nil || got != want {
			t.Errorf("%s after migration: got %q err %v, want %q", key, got, err, want)
		}
		c, _ := e.db.GetCredential(ctx, e.vaultID, key)
		if _, lerr := crypto.Decrypt(c.Ciphertext, c.Nonce, e.dek); lerr == nil && want != "" {
			t.Errorf("%s still opens with nil AAD after migration", key)
		}
	}
	if got, err := e.openOAuth(t, "GH_OAUTH", "refresh_token"); err != nil || got != "SENTINEL-AV-TEST-0104-refresh" {
		t.Errorf("refresh token after migration: %q %v", got, err)
	}
	if got, err := e.openOAuth(t, "GH_OAUTH", "client_secret"); err != nil || got != "SENTINEL-AV-TEST-0105-cs" {
		t.Errorf("client secret after migration: %q %v", got, err)
	}
}

func TestKMSAAD_Migration_Idempotent(t *testing.T) { forEachBackend(t, testKMSAAD_Migration_Idempotent) }

func testKMSAAD_Migration_Idempotent(t *testing.T, tdb testDB) {
	ctx := context.Background()
	e := newEnv(t, tdb)
	e.legacy(t, "STATIC_ONE", "SENTINEL-AV-TEST-0111")
	if _, err := Run(ctx, e.db, e.dek); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	before, _ := e.db.GetCredential(ctx, e.vaultID, "STATIC_ONE")
	res, err := Run(ctx, e.db, e.dek)
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if res.Rewrapped != 0 {
		t.Fatalf("second Run rewrapped %d rows; must be a no-op", res.Rewrapped)
	}
	after, _ := e.db.GetCredential(ctx, e.vaultID, "STATIC_ONE")
	if string(before.Ciphertext) != string(after.Ciphertext) || before.Version != after.Version {
		t.Fatal("second Run rewrote an already-bound row")
	}
}

// Crash mid-migration: some rows already bound (written by a previous Run that
// died), others still legacy. Run must finish the job without double-wrapping
// and without losing a value.
func TestKMSAAD_Migration_ResumesAfterCrash(t *testing.T) { forEachBackend(t, testKMSAAD_Migration_ResumesAfterCrash) }

func testKMSAAD_Migration_ResumesAfterCrash(t *testing.T, tdb testDB) {
	ctx := context.Background()
	e := newEnv(t, tdb)
	e.legacy(t, "LEGACY_ROW", "SENTINEL-AV-TEST-0121")
	// Simulate a row a crashed Run already rewrapped: written via the new path.
	if _, err := e.db.SetCredential(ctx, e.vaultID, "BOUND_ROW", nil, nil); err != nil {
		t.Fatal(err)
	}
	c, _ := e.db.GetCredential(ctx, e.vaultID, "BOUND_ROW")
	aad, err := crypto.AAD{Table: "credentials", Field: "value", VaultID: e.vaultID, Key: "BOUND_ROW", Version: c.Version + 1}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	ct, n, err := crypto.EncryptAAD([]byte("SENTINEL-AV-TEST-0122"), e.dek, aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.SetCredential(ctx, e.vaultID, "BOUND_ROW", ct, n); err != nil {
		t.Fatal(err)
	}
	if done, _ := IsComplete(ctx, e.db); done {
		t.Fatal("IsComplete true before any Run finished")
	}

	res, err := Run(ctx, e.db, e.dek)
	if err != nil {
		t.Fatalf("Run on mixed state: %v", err)
	}
	if res.Rewrapped != 1 || res.AlreadyBound < 1 {
		t.Fatalf("Run result %+v, want Rewrapped=1 AlreadyBound>=1", res)
	}
	for key, want := range map[string]string{"LEGACY_ROW": "SENTINEL-AV-TEST-0121", "BOUND_ROW": "SENTINEL-AV-TEST-0122"} {
		if got, err := e.openValue(t, key); err != nil || got != want {
			t.Errorf("%s: got %q err %v want %q", key, got, err, want)
		}
	}
}

// A row the migration cannot open (wrong DEK, corrupted) must stop the
// migration and leave it incomplete, not be silently skipped or dropped.
func TestKMSAAD_Migration_UndecryptableRowFailsLoudly(t *testing.T) { forEachBackend(t, testKMSAAD_Migration_UndecryptableRowFailsLoudly) }

func testKMSAAD_Migration_UndecryptableRowFailsLoudly(t *testing.T, tdb testDB) {
	ctx := context.Background()
	e := newEnv(t, tdb)
	e.legacy(t, "GOOD_ROW", "SENTINEL-AV-TEST-0131")
	if _, err := e.db.SetCredential(ctx, e.vaultID, "CORRUPT_ROW", []byte("not-a-ciphertext-at-all"), make([]byte, 12)); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx, e.db, e.dek); err == nil {
		t.Fatal("Run succeeded although a row could not be decrypted")
	}
	if done, _ := IsComplete(ctx, e.db); done {
		t.Fatal("migration marked complete with an undecryptable row present")
	}
	if c, err := e.db.GetCredential(ctx, e.vaultID, "CORRUPT_ROW"); err != nil || c == nil {
		t.Fatal("undecryptable row was deleted")
	}
}

// Proposal ciphertexts are covered by the migration too.
func TestKMSAAD_Migration_CoversProposalCredentials(t *testing.T) { forEachBackend(t, testKMSAAD_Migration_CoversProposalCredentials) }

func testKMSAAD_Migration_CoversProposalCredentials(t *testing.T, tdb testDB) {
	ctx := context.Background()
	e := newEnv(t, tdb)
	sess, err := e.db.CreateScopedSession(ctx, store.CreateScopedSessionParams{VaultID: e.vaultID, VaultRole: "proxy"})
	if err != nil {
		t.Fatal(err)
	}
	ct, n, _ := crypto.Encrypt([]byte("SENTINEL-AV-TEST-0141"), e.dek)
	p, err := e.db.CreateProposal(ctx, e.vaultID, sess.ID, `[]`, `[{"action":"set","key":"P_KEY","has_value":true}]`, "m", "", map[string]store.EncryptedCredential{"P_KEY": {Ciphertext: ct, Nonce: n}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx, e.db, e.dek); err != nil {
		t.Fatalf("Run: %v", err)
	}
	creds, err := e.db.GetProposalCredentials(ctx, e.vaultID, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	enc := creds["P_KEY"]
	aad, err := crypto.AAD{Table: "proposal_credentials", Field: "value", VaultID: e.vaultID, Key: fmt.Sprintf("%d:%s", p.ID, "P_KEY"), Version: enc.Version}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := crypto.DecryptAAD(enc.Ciphertext, enc.Nonce, e.dek, aad); err != nil || string(pt) != "SENTINEL-AV-TEST-0141" {
		t.Fatalf("proposal credential not migrated: %q %v", pt, err)
	}
}

// After the migration is complete, a legacy nil-AAD value planted in the DB
// (restored backup, attacker with file write, buggy writer) must be refused
// by the production read path, not silently accepted via a legacy fallback.
func TestKMSAAD_PostMigration_LegacyReadRefused(t *testing.T) { forEachBackend(t, testKMSAAD_PostMigration_LegacyReadRefused) }

func testKMSAAD_PostMigration_LegacyReadRefused(t *testing.T, tdb testDB) {
	ctx := context.Background()
	e := newEnv(t, tdb)
	e.legacy(t, "SVC_TOKEN", "SENTINEL-AV-TEST-0151")
	if _, err := Run(ctx, e.db, e.dek); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := e.db.SetBrokerConfig(ctx, e.vaultID, `[{"name":"svc","host":"api.example.test","auth":{"type":"bearer","token":"SVC_TOKEN"}}]`); err != nil {
		t.Fatal(err)
	}
	srv := server.New("127.0.0.1:0", e.db, e.dek, nil, true, "http://127.0.0.1:14321", slog.New(slog.DiscardHandler))
	cp := srv.CredentialProvider()

	// Control: the migrated row is usable through the real provider.
	res, err := cp.Inject(ctx, e.vaultID, "api.example.test", 0, "/")
	if err != nil || res.Headers["Authorization"] != "Bearer SENTINEL-AV-TEST-0151" {
		t.Fatalf("control: migrated credential not injectable: %v %v", res, err)
	}

	// Plant a legacy value directly in SQLite (bypassing the store API).
	ct, n, _ := crypto.Encrypt([]byte("SENTINEL-AV-TEST-0152-legacy"), e.dek)
	e.tdb.Exec(t, `UPDATE credentials SET ciphertext = ?, nonce = ? WHERE vault_id = ? AND key = ?`, ct, n, e.vaultID, "SVC_TOKEN")
	res, err = cp.Inject(ctx, e.vaultID, "api.example.test", 0, "/")
	if err == nil {
		t.Fatalf("legacy nil-AAD value accepted after migration complete: %v", res.Headers)
	}
	if !errors.Is(err, brokercore.ErrCredentialMissing) {
		t.Logf("note: error is %v", err)
	}
}

// The SQLite deployment keeps the CA root key in a file (cmd/server.go:211-214
// only uses ca_state on Postgres). The file key must be migrated as well.
func TestKMSAAD_Migration_CAKeyFile(t *testing.T) { forEachBackend(t, testKMSAAD_Migration_CAKeyFile) }

func testKMSAAD_Migration_CAKeyFile(t *testing.T, tdb testDB) {
	e := newEnv(t, tdb)
	dir := t.TempDir()
	if err := writeLegacyCAForTest(dir, e.dek); err != nil {
		t.Fatal(err)
	}
	if err := RunCAKeyFile(dir, e.dek); err != nil {
		t.Fatalf("RunCAKeyFile: %v", err)
	}
	if err := RunCAKeyFile(dir, e.dek); err != nil {
		t.Fatalf("RunCAKeyFile second run (must be idempotent): %v", err)
	}
	if err := assertCAKeyFileIsBound(dir, e.dek); err != nil {
		t.Fatal(err)
	}
}

func writeLegacyCAForTest(dir string, dek []byte) error {
	// ca.New at v0.40.0 writes the root key sealed with nil AAD.
	_, err := ca.New(dek, ca.Options{Dir: dir})
	return err
}

func assertCAKeyFileIsBound(dir string, dek []byte) error {
	raw, err := os.ReadFile(filepath.Join(dir, "ca.key.enc"))
	if err != nil {
		return fmt.Errorf("reading CA key file: %w", err)
	}
	var f struct {
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("parsing CA key file: %w", err)
	}
	n, _ := base64.StdEncoding.DecodeString(f.Nonce)
	ct, _ := base64.StdEncoding.DecodeString(f.Ciphertext)
	if _, err := crypto.Decrypt(ct, n, dek); err == nil {
		return errors.New("CA root key file still opens with nil AAD after RunCAKeyFile")
	}
	if _, err := ca.New(dek, ca.Options{Dir: dir}); err != nil {
		return fmt.Errorf("CA no longer loads after RunCAKeyFile: %w", err)
	}
	return nil
}
