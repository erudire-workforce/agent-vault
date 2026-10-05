//go:build kmsaad

// Runtime tests for KMS-wrapped DEK startup on the SQLite store, driven
// through the real unlock entry points in cmd/server.go (unlockOrSetup,
// unlockOrSetupWithPassword). They compile against v0.40.0 and fail at
// runtime because the env vars below are ignored today.
//
// The KMS is an in-memory fake that speaks the AWS KMS JSON 1.1 wire
// protocol (TrentService.Encrypt / GenerateDataKey / Decrypt / DescribeKey),
// reached through AWS_ENDPOINT_URL_KMS. It enforces the encryption context
// and the key id exactly like AWS KMS. No real AWS endpoint or credential is
// used; the AWS_* values set here are obvious fakes.
package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	"github.com/Infisical/agent-vault/internal/auth"
)

const (
	fakeKeyA     = "1111aaaa-0000-4000-8000-000000000001"
	fakeKeyB     = "2222bbbb-0000-4000-8000-000000000002"
	fakeAccount  = "000000000000"
	fakeRegion   = "us-east-1"
	fakeAliasA   = "alias/agent-vault-test-a"
	envNameProd  = "prod"
	envNameStage = "staging"
)

func fakeARN(id string) string { return "arn:aws:kms:" + fakeRegion + ":" + fakeAccount + ":key/" + id }

type kmsCall struct {
	Op    string
	KeyID string
	Ctx   map[string]string
}

type fakeAWSKMS struct {
	mu    sync.Mutex
	srv   *httptest.Server
	blobs map[string]kmsBlob
	calls []kmsCall
}

type kmsBlob struct {
	plaintext []byte
	keyID     string // canonical key id
	ctx       map[string]string
}

func (f *fakeAWSKMS) resolve(keyID string) (string, bool) {
	switch keyID {
	case fakeKeyA, fakeARN(fakeKeyA), fakeAliasA, "arn:aws:kms:" + fakeRegion + ":" + fakeAccount + ":" + fakeAliasA:
		return fakeKeyA, true
	case fakeKeyB, fakeARN(fakeKeyB):
		return fakeKeyB, true
	}
	return "", false
}

func kmsErr(w http.ResponseWriter, typ, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("X-Amzn-ErrorType", typ)
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": typ, "message": msg})
}

func (f *fakeAWSKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target := r.Header.Get("X-Amz-Target")
	op := strings.TrimPrefix(target, "TrentService.")
	body, _ := io.ReadAll(r.Body)
	var req struct {
		KeyId             string
		Plaintext         []byte
		CiphertextBlob    []byte
		EncryptionContext map[string]string
		NumberOfBytes     int
		KeySpec           string
	}
	if err := json.Unmarshal(body, &req); err != nil {
		kmsErr(w, "SerializationException", err.Error())
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, kmsCall{Op: op, KeyID: req.KeyId, Ctx: maps.Clone(req.EncryptionContext)})

	newBlob := func(pt []byte, keyID string) []byte {
		h := make([]byte, 24)
		_, _ = rand.Read(h)
		handle := "fakekms-v1:" + hex.EncodeToString(h)
		f.blobs[handle] = kmsBlob{plaintext: append([]byte(nil), pt...), keyID: keyID, ctx: maps.Clone(req.EncryptionContext)}
		return []byte(handle)
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	switch op {
	case "DescribeKey":
		id, ok := f.resolve(req.KeyId)
		if !ok {
			kmsErr(w, "NotFoundException", "key not found")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"KeyMetadata": map[string]any{
			"KeyId": id, "Arn": fakeARN(id), "Enabled": true, "KeyState": "Enabled",
			"KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "SYMMETRIC_DEFAULT",
		}})
	case "Encrypt":
		id, ok := f.resolve(req.KeyId)
		if !ok {
			kmsErr(w, "NotFoundException", "key not found")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"CiphertextBlob": newBlob(req.Plaintext, id), "KeyId": fakeARN(id), "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
		})
	case "GenerateDataKey":
		id, ok := f.resolve(req.KeyId)
		if !ok {
			kmsErr(w, "NotFoundException", "key not found")
			return
		}
		n := 32
		if req.NumberOfBytes > 0 {
			n = req.NumberOfBytes
		}
		pt := make([]byte, n)
		_, _ = rand.Read(pt)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"CiphertextBlob": newBlob(pt, id), "Plaintext": pt, "KeyId": fakeARN(id),
		})
	case "Decrypt":
		b, ok := f.blobs[string(req.CiphertextBlob)]
		if !ok {
			kmsErr(w, "InvalidCiphertextException", "unknown ciphertext")
			return
		}
		if req.KeyId != "" {
			id, ok := f.resolve(req.KeyId)
			if !ok || id != b.keyID {
				kmsErr(w, "IncorrectKeyException", "ciphertext was not encrypted under the specified key")
				return
			}
		}
		if !maps.Equal(req.EncryptionContext, b.ctx) {
			kmsErr(w, "InvalidCiphertextException", "encryption context mismatch")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Plaintext": b.plaintext, "KeyId": fakeARN(b.keyID), "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
		})
	default:
		kmsErr(w, "UnknownOperationException", op)
	}
}

func newFakeAWSKMS(t *testing.T) *fakeAWSKMS {
	t.Helper()
	f := &fakeAWSKMS{blobs: map[string]kmsBlob{}}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAWSKMS) snapshot() []kmsCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]kmsCall(nil), f.calls...)
}

// closedEndpoint returns an http URL on which nothing listens.
func closedEndpoint(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return "http://" + addr
}

func unsetenv(t *testing.T, k string) {
	t.Helper()
	t.Setenv(k, "") // registers restore
	_ = os.Unsetenv(k)
}

// isolateEnv clears every variable that could make the test touch a real AWS
// account or a real master password, and points stdin at /dev/null so an
// unexpected interactive prompt fails instead of blocking.
func isolateEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"AGENT_VAULT_MASTER_PASSWORD", "AGENT_VAULT_KMS_KEY_ID", "AGENT_VAULT_KMS_ENCRYPTION_CONTEXT_ENV",
		"AGENT_VAULT_REQUIRE_KMS", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN",
		"AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_ENDPOINT_URL",
	} {
		unsetenv(t, k)
	}
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", empty)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", empty)
	t.Setenv("AWS_REGION", fakeRegion)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAVTESTFAKE000000")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "SENTINEL-AV-TEST-FAKE-AWS-SECRET-NOT-REAL")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_MAX_ATTEMPTS", "1")

	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = devnull
	t.Cleanup(func() { os.Stdin = old; _ = devnull.Close() })
}

func kmsMode(t *testing.T, endpoint, keyID, envName string) {
	t.Helper()
	t.Setenv("AWS_ENDPOINT_URL_KMS", endpoint)
	t.Setenv("AGENT_VAULT_KMS_KEY_ID", keyID)
	t.Setenv("AGENT_VAULT_KMS_ENCRYPTION_CONTEXT_ENV", envName)
	t.Setenv("AGENT_VAULT_REQUIRE_KMS", "1")
}

func quietCmd() *cobra.Command {
	c := &cobra.Command{}
	c.SetOut(io.Discard)
	c.SetErr(io.Discard)
	return c
}

// sqliteFilesContain reports whether needle appears in the SQLite database
// file or its WAL/SHM side files. Postgres is covered by RowBytesContain.
func sqliteFilesContain(path string, needle []byte) bool {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if bytes.Contains(b, needle) {
			return true
		}
	}
	return false
}

// setupKMSInstance runs first startup in KMS mode and returns the DEK.
func setupKMSInstance(t *testing.T, tdb testDB, f *fakeAWSKMS, keyID, envName string) []byte {
	t.Helper()
	kmsMode(t, f.srv.URL, keyID, envName)
	db := tdb.Open(t)
	mk, err := unlockOrSetup(quietCmd(), db, false)
	if err != nil {
		t.Fatalf("first startup in KMS mode (AGENT_VAULT_KMS_KEY_ID set, AGENT_VAULT_REQUIRE_KMS=1, no password) failed; "+
			"expected a new DEK wrapped by KMS: %v", err)
	}
	dek := append([]byte(nil), mk.Key()...)
	mk.Wipe()
	_ = db.Close()
	return dek
}

func TestKMSAAD_FakeAWSKMS_KnownPositive(t *testing.T) {
	f := newFakeAWSKMS(t)
	post := func(op string, body any) (int, map[string]any) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, f.srv.URL, bytes.NewReader(b))
		req.Header.Set("X-Amz-Target", "TrentService."+op)
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	ctxProd := map[string]string{"env": envNameProd}
	code, out := post("Encrypt", map[string]any{"KeyId": fakeAliasA, "Plaintext": []byte("SENTINEL-AV-TEST-0201"), "EncryptionContext": ctxProd})
	if code != 200 {
		t.Fatalf("encrypt: %d %v", code, out)
	}
	blob, _ := base64.StdEncoding.DecodeString(out["CiphertextBlob"].(string))
	if bytes.Contains(blob, []byte("SENTINEL")) {
		t.Fatal("fake ciphertext leaks plaintext")
	}
	if code, _ := post("Decrypt", map[string]any{"CiphertextBlob": blob, "EncryptionContext": map[string]string{"env": envNameStage}}); code != 400 {
		t.Fatalf("fake accepted wrong encryption context (status %d)", code)
	}
	if code, _ := post("Decrypt", map[string]any{"CiphertextBlob": blob, "EncryptionContext": ctxProd, "KeyId": fakeKeyB}); code != 400 {
		t.Fatalf("fake accepted wrong key id (status %d)", code)
	}
	code, out = post("Decrypt", map[string]any{"CiphertextBlob": blob, "EncryptionContext": ctxProd, "KeyId": fakeKeyA})
	if code != 200 {
		t.Fatalf("fake rejected correct decrypt: %d %v", code, out)
	}
	if pt, _ := base64.StdEncoding.DecodeString(out["Plaintext"].(string)); string(pt) != "SENTINEL-AV-TEST-0201" {
		t.Fatalf("fake decrypt returned %q", pt)
	}
}

func TestKMSAAD_Startup_FreshStore_WrapsDEKWithKMS_AndUnwrapsOnRestart(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		isolateEnv(t)
		f := newFakeAWSKMS(t)
		dek := setupKMSInstance(t, tdb, f, fakeAliasA, envNameProd)

		db := tdb.Open(t)
		rec, err := db.GetMasterKeyRecord(context.Background())
		if err != nil || rec == nil {
			t.Fatalf("no master key record after KMS setup: %v", err)
		}
		if rec.DEKPlaintext != nil {
			t.Fatal("dek_plaintext is set: the DEK was stored unwrapped in KMS mode")
		}
		if rec.Salt != nil || rec.KDFTime != nil {
			t.Fatal("KMS setup produced a password (Argon2id) wrapped DEK")
		}
		if tdb.RowBytesContain(t, "master_key", dek) {
			t.Fatal("raw DEK bytes found in the master_key row")
		}
		if tdb.Kind == "sqlite" && sqliteFilesContain(tdb.DSN, dek) {
			t.Fatal("raw DEK bytes found in the SQLite file/WAL")
		}
		var sawWrap bool
		for _, c := range f.snapshot() {
			if (c.Op == "Encrypt" || c.Op == "GenerateDataKey") && c.Ctx["env"] == envNameProd {
				sawWrap = true
			}
		}
		if !sawWrap {
			t.Fatalf("KMS was never asked to wrap the DEK under the configured encryption context; calls=%v", f.snapshot())
		}
		_ = db.Close()

		db2 := tdb.Open(t)
		mk, err := unlockOrSetup(quietCmd(), db2, false)
		if err != nil {
			t.Fatalf("restart in KMS mode failed: %v", err)
		}
		defer mk.Wipe()
		if !bytes.Equal(mk.Key(), dek) {
			t.Fatal("DEK after restart differs from the DEK created at setup")
		}
		var sawDecrypt bool
		for _, c := range f.snapshot() {
			if c.Op == "Decrypt" {
				sawDecrypt = true
			}
		}
		if !sawDecrypt {
			t.Fatal("restart did not unwrap the DEK through KMS")
		}
	})
}

func TestKMSAAD_Startup_EncryptionContextChanged_Refused(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		isolateEnv(t)
		f := newFakeAWSKMS(t)
		setupKMSInstance(t, tdb, f, fakeAliasA, envNameProd)

		kmsMode(t, f.srv.URL, fakeAliasA, envNameStage)
		if mk, err := unlockOrSetup(quietCmd(), tdb.Open(t), false); err == nil {
			mk.Wipe()
			t.Fatal("startup succeeded although AGENT_VAULT_KMS_ENCRYPTION_CONTEXT_ENV changed (prod -> staging)")
		}
	})
}

func TestKMSAAD_Startup_KeyIDChanged_Refused(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		isolateEnv(t)
		f := newFakeAWSKMS(t)
		setupKMSInstance(t, tdb, f, fakeAliasA, envNameProd)

		kmsMode(t, f.srv.URL, fakeKeyB, envNameProd)
		if mk, err := unlockOrSetup(quietCmd(), tdb.Open(t), false); err == nil {
			mk.Wipe()
			t.Fatal("startup succeeded although AGENT_VAULT_KMS_KEY_ID points at a different key than the one that wrapped the DEK")
		}
	})
}

func TestKMSAAD_Startup_KMSDownOnRestart_FailsClosed(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		isolateEnv(t)
		f := newFakeAWSKMS(t)
		setupKMSInstance(t, tdb, f, fakeAliasA, envNameProd)

		kmsMode(t, closedEndpoint(t), fakeAliasA, envNameProd)
		t.Setenv("AGENT_VAULT_MASTER_PASSWORD", "SENTINEL-AV-TEST-0202-password")
		if mk, err := unlockOrSetup(quietCmd(), tdb.Open(t), false); err == nil {
			mk.Wipe()
			t.Fatal("startup succeeded with KMS unreachable")
		}
	})
}

// Fresh instance, KMS required but unreachable, and a master password is also
// present in the environment: must fail closed, must NOT fall back to the
// password (or passwordless) path, and must not persist any master key record.
func TestKMSAAD_Startup_KMSUnavailableOnFreshStore_NoFallback(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		isolateEnv(t)
		kmsMode(t, closedEndpoint(t), fakeAliasA, envNameProd)
		t.Setenv("AGENT_VAULT_MASTER_PASSWORD", "SENTINEL-AV-TEST-0203-password")

		db := tdb.Open(t)
		mk, err := unlockOrSetup(quietCmd(), db, false)
		if err == nil {
			mk.Wipe()
			t.Error("startup succeeded with AGENT_VAULT_REQUIRE_KMS=1 and KMS unreachable (fell back to another unlock mode)")
		}
		rec, rerr := db.GetMasterKeyRecord(context.Background())
		if rerr != nil {
			t.Fatal(rerr)
		}
		if rec != nil {
			t.Errorf("a master key record was persisted without KMS (dek_plaintext=%v, password-wrapped=%v)", rec.DEKPlaintext != nil, rec.Salt != nil)
		}
	})
}

// dek_plaintext row (the "unwrapped" case) while KMS is required: refuse.
func TestKMSAAD_Startup_UnwrappedDEKRecord_RefusedWhenKMSRequired(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		isolateEnv(t)
		f := newFakeAWSKMS(t)
		db := tdb.Open(t)
		_, rec, err := auth.SetupPasswordless()
		if err != nil {
			t.Fatal(err)
		}
		if err := db.SetMasterKeyRecord(context.Background(), verificationToStoreRecord(rec)); err != nil {
			t.Fatal(err)
		}

		kmsMode(t, f.srv.URL, fakeAliasA, envNameProd)
		if mk, err := unlockOrSetup(quietCmd(), db, false); err == nil {
			mk.Wipe()
			t.Error("unlockOrSetup started from a dek_plaintext record although AGENT_VAULT_REQUIRE_KMS=1")
		}
		if mk, err := unlockOrSetupWithPassword(db, []byte("SENTINEL-AV-TEST-0204-password")); err == nil {
			mk.Wipe()
			t.Error("unlockOrSetupWithPassword started from a dek_plaintext record although AGENT_VAULT_REQUIRE_KMS=1")
		}
	})
}

func TestKMSAAD_Startup_PasswordWrappedDEKRecord_RefusedWhenKMSRequired(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		isolateEnv(t)
		f := newFakeAWSKMS(t)
		db := tdb.Open(t)
		pw := "SENTINEL-AV-TEST-0205-password"
		mk, err := unlockOrSetupWithPassword(db, []byte(pw)) // KMS env not set yet: legacy password setup
		if err != nil {
			t.Fatalf("precondition: password setup: %v", err)
		}
		mk.Wipe()

		kmsMode(t, f.srv.URL, fakeAliasA, envNameProd)
		t.Setenv("AGENT_VAULT_MASTER_PASSWORD", pw)
		if mk, err := unlockOrSetup(quietCmd(), db, false); err == nil {
			mk.Wipe()
			t.Error("unlockOrSetup started from a password-wrapped DEK although AGENT_VAULT_REQUIRE_KMS=1")
		}
		if mk, err := unlockOrSetupWithPassword(db, []byte(pw)); err == nil {
			mk.Wipe()
			t.Error("unlockOrSetupWithPassword started from a password-wrapped DEK although AGENT_VAULT_REQUIRE_KMS=1")
		}
	})
}
