// Package kmscontract_test pins the KMS key-wrapping API the patch must add
// to internal/auth and internal/store. It is a separate directory so the
// expected pre-patch compile failure ("undefined: auth.SetupWithKMS" ...) does
// not stop the existing internal/auth tests from running under -tags kmsaad.
//
// Intended API (see internal/crypto/FAILURE_MODES_KMS_AAD.md, "Contract"):
//
//	type KeyWrapper interface {
//	    Wrap(ctx context.Context, dek []byte, encCtx map[string]string) (wrapped []byte, keyID string, err error)
//	    Unwrap(ctx context.Context, wrapped []byte, keyID string, encCtx map[string]string) ([]byte, error)
//	}
//	func SetupWithKMS(ctx context.Context, w KeyWrapper, encCtx map[string]string) (*MasterKey, *VerificationRecord, error)
//	func UnlockWithKMS(ctx context.Context, w KeyWrapper, rec *VerificationRecord, encCtx map[string]string) (*MasterKey, error)
//	VerificationRecord gains: KMSWrappedDEK []byte; KMSKeyID string
//	store.MasterKeyRecord gains: KMSWrappedDEK []byte; KMSKeyID string (persisted on SQLite)
package kmscontract_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"maps"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/store"
)

// fakeKMS is an in-memory KeyWrapper that enforces the encryption context
// and the key id exactly like AWS KMS does: the wrapped blob is an opaque
// handle; the DEK never appears in it.
type fakeKMS struct {
	mu       sync.Mutex
	keyID    string
	down     bool
	blobs    map[string]fakeBlob
	wraps    int
	unwraps  int
	lastCtxs []map[string]string
}

type fakeBlob struct {
	dek   []byte
	keyID string
	ctx   map[string]string
}

var errKMSDown = errors.New("fakekms: endpoint unavailable")

func newFakeKMS(keyID string) *fakeKMS {
	return &fakeKMS{keyID: keyID, blobs: map[string]fakeBlob{}}
}

func (f *fakeKMS) Wrap(_ context.Context, dek []byte, encCtx map[string]string) ([]byte, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, "", errKMSDown
	}
	f.wraps++
	f.lastCtxs = append(f.lastCtxs, maps.Clone(encCtx))
	h := make([]byte, 16)
	_, _ = rand.Read(h)
	handle := "fakekms:" + hex.EncodeToString(h)
	f.blobs[handle] = fakeBlob{dek: append([]byte(nil), dek...), keyID: f.keyID, ctx: maps.Clone(encCtx)}
	return []byte(handle), f.keyID, nil
}

func (f *fakeKMS) Unwrap(_ context.Context, wrapped []byte, keyID string, encCtx map[string]string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errKMSDown
	}
	f.unwraps++
	b, ok := f.blobs[string(wrapped)]
	if !ok {
		return nil, errors.New("fakekms: InvalidCiphertextException")
	}
	if keyID != b.keyID || keyID != f.keyID {
		return nil, errors.New("fakekms: IncorrectKeyException")
	}
	if !maps.Equal(encCtx, b.ctx) {
		return nil, errors.New("fakekms: InvalidCiphertextException (encryption context mismatch)")
	}
	return append([]byte(nil), b.dek...), nil
}

var ctxProd = map[string]string{"service": "agent-vault", "environment": "prod"}

// Known-positive for the fake itself: it must reject a wrong context and a
// wrong key id, otherwise the tests below could pass vacuously.
func TestKMSAAD_FakeKMSEnforcesContextAndKeyID(t *testing.T) {
	f := newFakeKMS("key-A")
	w, kid, err := f.Wrap(context.Background(), []byte("0123456789abcdef0123456789abcdef"), ctxProd)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Unwrap(context.Background(), w, kid, map[string]string{"service": "agent-vault", "environment": "staging"}); err == nil {
		t.Fatal("fake accepted a wrong encryption context")
	}
	if _, err := f.Unwrap(context.Background(), w, "key-B", ctxProd); err == nil {
		t.Fatal("fake accepted a wrong key id")
	}
	if _, err := f.Unwrap(context.Background(), w, kid, ctxProd); err != nil {
		t.Fatalf("fake rejected the correct context: %v", err)
	}
}

func TestKMSAAD_SetupWithKMS_WrapsAndUnlocks(t *testing.T) {
	ctx := context.Background()
	f := newFakeKMS("key-A")
	mk, rec, err := auth.SetupWithKMS(ctx, f, ctxProd)
	if err != nil {
		t.Fatalf("SetupWithKMS: %v", err)
	}
	if len(mk.Key()) != 32 {
		t.Fatalf("DEK length %d", len(mk.Key()))
	}
	if rec.DEKPlaintext != nil {
		t.Fatal("KMS setup left DEKPlaintext set (unwrapped DEK would be persisted)")
	}
	if rec.Salt != nil || rec.DEKCiphertext != nil || rec.Params.Time != 0 {
		t.Fatal("KMS setup also produced a password-wrapped DEK")
	}
	if rec.KMSKeyID != "key-A" || len(rec.KMSWrappedDEK) == 0 {
		t.Fatalf("record missing KMS fields: keyID=%q wrapped=%d bytes", rec.KMSKeyID, len(rec.KMSWrappedDEK))
	}
	if bytes.Contains(rec.KMSWrappedDEK, mk.Key()) {
		t.Fatal("wrapped blob contains the DEK")
	}
	if f.wraps != 1 || !maps.Equal(f.lastCtxs[0], ctxProd) {
		t.Fatalf("KMS Wrap not called once with the configured context: wraps=%d ctxs=%v", f.wraps, f.lastCtxs)
	}

	mk2, err := auth.UnlockWithKMS(ctx, f, rec, ctxProd)
	if err != nil {
		t.Fatalf("UnlockWithKMS: %v", err)
	}
	if !bytes.Equal(mk.Key(), mk2.Key()) {
		t.Fatal("unlocked DEK differs from setup DEK")
	}
}

func TestKMSAAD_UnlockWithKMS_WrongEncryptionContextRefused(t *testing.T) {
	ctx := context.Background()
	f := newFakeKMS("key-A")
	_, rec, err := auth.SetupWithKMS(ctx, f, ctxProd)
	if err != nil {
		t.Fatalf("SetupWithKMS: %v", err)
	}
	if mk, err := auth.UnlockWithKMS(ctx, f, rec, map[string]string{"service": "agent-vault", "environment": "staging"}); err == nil || mk != nil {
		t.Fatal("unlock succeeded with a different encryption context")
	}
}

func TestKMSAAD_UnlockWithKMS_KeyIDMismatchRefused(t *testing.T) {
	ctx := context.Background()
	f := newFakeKMS("key-A")
	_, rec, err := auth.SetupWithKMS(ctx, f, ctxProd)
	if err != nil {
		t.Fatalf("SetupWithKMS: %v", err)
	}
	// Operator rotated AGENT_VAULT_KMS_KEY_ID to key-B but the stored DEK is under key-A.
	other := newFakeKMS("key-B")
	other.blobs = f.blobs
	if mk, err := auth.UnlockWithKMS(ctx, other, rec, ctxProd); err == nil || mk != nil {
		t.Fatal("unlock succeeded although the configured key id differs from the stored one")
	}
	// Tampered record pointing at another key id.
	rec.KMSKeyID = "key-B"
	if mk, err := auth.UnlockWithKMS(ctx, f, rec, ctxProd); err == nil || mk != nil {
		t.Fatal("unlock succeeded with a tampered key id in the record")
	}
}

func TestKMSAAD_KMSUnavailable_FailsClosed(t *testing.T) {
	ctx := context.Background()
	f := newFakeKMS("key-A")
	f.down = true
	if mk, rec, err := auth.SetupWithKMS(ctx, f, ctxProd); err == nil || mk != nil || rec != nil {
		t.Fatal("SetupWithKMS succeeded with KMS down")
	}
	f.down = false
	_, rec, err := auth.SetupWithKMS(ctx, f, ctxProd)
	if err != nil {
		t.Fatal(err)
	}
	f.down = true
	if mk, err := auth.UnlockWithKMS(ctx, f, rec, ctxProd); err == nil || mk != nil {
		t.Fatal("UnlockWithKMS succeeded with KMS down")
	}
}

// UnlockWithKMS must refuse records that are not KMS-wrapped instead of
// silently falling back to the plaintext or password path.
func TestKMSAAD_UnlockWithKMS_RefusesNonKMSRecords(t *testing.T) {
	ctx := context.Background()
	f := newFakeKMS("key-A")

	_, plain, err := auth.SetupPasswordless()
	if err != nil {
		t.Fatal(err)
	}
	if mk, err := auth.UnlockWithKMS(ctx, f, plain, ctxProd); err == nil || mk != nil {
		t.Fatal("UnlockWithKMS accepted an unwrapped (dek_plaintext) record")
	}

	_, pw, err := auth.SetupWithPassword([]byte("SENTINEL-AV-TEST-0002-password"))
	if err != nil {
		t.Fatal(err)
	}
	if mk, err := auth.UnlockWithKMS(ctx, f, pw, ctxProd); err == nil || mk != nil {
		t.Fatal("UnlockWithKMS accepted a password-wrapped record")
	}
	if f.unwraps != 0 {
		t.Fatalf("KMS Unwrap called %d times for non-KMS records", f.unwraps)
	}
}

// The KMS fields must survive a store round trip on the deployment target
// (Postgres, 20260617143022_postgres_baseline.go) and on SQLite.
func TestKMSAAD_StorePersistsKMSFields(t *testing.T) {
	forEachBackend(t, testStorePersistsKMSFields)
}

func testStorePersistsKMSFields(t *testing.T, tdb testDB) {
	ctx := context.Background()
	db := tdb.Open(t)
	f := newFakeKMS("key-A")
	mk, rec, err := auth.SetupWithKMS(ctx, f, ctxProd)
	if err != nil {
		t.Fatalf("SetupWithKMS: %v", err)
	}
	if err := db.SetMasterKeyRecord(ctx, &store.MasterKeyRecord{
		Sentinel: rec.Sentinel, SentinelNonce: rec.SentinelNonce,
		KMSWrappedDEK: rec.KMSWrappedDEK, KMSKeyID: rec.KMSKeyID,
	}); err != nil {
		t.Fatalf("SetMasterKeyRecord: %v", err)
	}
	_ = db.Close()

	db = tdb.Open(t)
	if tdb.RowBytesContain(t, "master_key", mk.Key()) {
		t.Fatal("raw DEK bytes persisted in master_key")
	}
	got, err := db.GetMasterKeyRecord(ctx)
	if err != nil || got == nil {
		t.Fatalf("GetMasterKeyRecord: %v", err)
	}
	if got.DEKPlaintext != nil {
		t.Fatal("dek_plaintext populated for a KMS record")
	}
	if got.KMSKeyID != "key-A" || !bytes.Equal(got.KMSWrappedDEK, rec.KMSWrappedDEK) {
		t.Fatalf("KMS fields not persisted: keyID=%q", got.KMSKeyID)
	}
	mk2, err := auth.UnlockWithKMS(ctx, f, &auth.VerificationRecord{
		Sentinel: got.Sentinel, SentinelNonce: got.SentinelNonce,
		KMSWrappedDEK: got.KMSWrappedDEK, KMSKeyID: got.KMSKeyID,
	}, ctxProd)
	if err != nil || !bytes.Equal(mk2.Key(), mk.Key()) {
		t.Fatalf("unlock after SQLite round trip failed: %v", err)
	}
}
