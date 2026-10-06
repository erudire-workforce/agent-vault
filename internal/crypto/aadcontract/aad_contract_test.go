// Package aadcontract_test pins the API and the byte format of the
// row-bound AAD in internal/crypto.
//
// API (see internal/crypto/FAILURE_MODES_KMS_AAD.md, section "Contract"):
//
//	type AAD struct {
//	    Table   string // "credentials", "credential_oauth", "proposal_credentials", "ca_root_key"
//	    Field   string // "value", "refresh_token", "client_secret", "root_key"
//	    VaultID string // "" only for instance-level rows (CA root key)
//	    Key     string // credential key / proposal "<id>:<key>" / "" for CA
//	    Version uint64 // monotonic per row, bumped on every rewrite
//	}
//	func (a AAD) Bytes() ([]byte, error)  // table 0x00 field 0x00 vault 0x00 key 0x00 decimal(version)
//	func EncryptAAD(plaintext, key, aad []byte) (ciphertext, nonce []byte, err error)
//	func DecryptAAD(ciphertext, nonce, key, aad []byte) ([]byte, error)
package aadcontract_test

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/crypto"
)

const sentinel = "SENTINEL-AV-TEST-0001"

func key32(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func base() crypto.AAD {
	return crypto.AAD{Table: "credentials", Field: "value", VaultID: "vault-1", Key: "STRIPE_KEY", Version: 3}
}

func mustBytes(t *testing.T, a crypto.AAD) []byte {
	t.Helper()
	b, err := a.Bytes()
	if err != nil {
		t.Fatalf("AAD.Bytes(%+v): %v", a, err)
	}
	return b
}

// The exact encoding is part of the stored-data contract: changing it later
// needs a migration, so it is pinned byte-for-byte here.
func TestKMSAAD_AADEncodingIsExact(t *testing.T) {
	got := mustBytes(t, base())
	want := []byte("credentials\x00value\x00vault-1\x00STRIPE_KEY\x003")
	if !bytes.Equal(got, want) {
		t.Fatalf("AAD bytes = %q, want %q", got, want)
	}
}

// A component containing the separator would make two different rows encode
// to the same AAD ("a\x00b" + "c" vs "a" + "b\x00c"). Must be rejected.
func TestKMSAAD_AADRejectsSeparatorInComponents(t *testing.T) {
	for name, a := range map[string]crypto.AAD{
		"table":   {Table: "cred\x00entials", Field: "value", VaultID: "v", Key: "K", Version: 1},
		"field":   {Table: "credentials", Field: "va\x00lue", VaultID: "v", Key: "K", Version: 1},
		"vault":   {Table: "credentials", Field: "value", VaultID: "v\x00x", Key: "K", Version: 1},
		"key":     {Table: "credentials", Field: "value", VaultID: "v", Key: "K\x00Y", Version: 1},
		"emptyTb": {Table: "", Field: "value", VaultID: "v", Key: "K", Version: 1},
		"emptyFd": {Table: "credentials", Field: "", VaultID: "v", Key: "K", Version: 1},
	} {
		if _, err := a.Bytes(); err == nil {
			t.Errorf("%s: AAD.Bytes accepted an ambiguous/empty component: %+v", name, a)
		}
	}
}

func TestKMSAAD_RoundTrip(t *testing.T) {
	k := key32(t)
	aad := mustBytes(t, base())
	ct, nonce, err := crypto.EncryptAAD([]byte(sentinel), k, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte(sentinel)) {
		t.Fatal("ciphertext contains plaintext")
	}
	pt, err := crypto.DecryptAAD(ct, nonce, k, aad)
	if err != nil {
		t.Fatalf("DecryptAAD with matching AAD: %v", err)
	}
	if string(pt) != sentinel {
		t.Fatalf("got %q", pt)
	}
}

// Every component of the AAD must be load-bearing: change any one and the
// ciphertext must not open. This is the unit-level form of the row swap,
// cross-vault, key-name, cross-field, cross-table and old-version replay cases.
func TestKMSAAD_EveryComponentIsBound(t *testing.T) {
	k := key32(t)
	ct, nonce, err := crypto.EncryptAAD([]byte(sentinel), k, mustBytes(t, base()))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(a *crypto.AAD){
		"other table (credentials->proposal_credentials)": func(a *crypto.AAD) { a.Table = "proposal_credentials" },
		"other field (value->refresh_token)":              func(a *crypto.AAD) { a.Field = "refresh_token" },
		"other vault (cross-vault swap)":                  func(a *crypto.AAD) { a.VaultID = "vault-2" },
		"other key (row swap / key-name swap)":            func(a *crypto.AAD) { a.Key = "OTHER_KEY" },
		"older version (replay)":                          func(a *crypto.AAD) { a.Version = 2 },
		"newer version":                                   func(a *crypto.AAD) { a.Version = 4 },
	}
	for name, mutate := range cases {
		a := base()
		mutate(&a)
		if pt, err := crypto.DecryptAAD(ct, nonce, k, mustBytes(t, a)); err == nil {
			t.Errorf("%s: DecryptAAD succeeded (%q); AAD component is not bound", name, pt)
		}
	}
}

// v0.40.0 ciphertexts were sealed with nil AAD. They must not open under the
// AAD path, and AAD ciphertexts must not open under the legacy path (otherwise
// a legacy fallback becomes a bypass).
func TestKMSAAD_LegacyAndBoundAreMutuallyExclusive(t *testing.T) {
	k := key32(t)
	aad := mustBytes(t, base())

	legacyCT, legacyNonce, err := crypto.Encrypt([]byte(sentinel), k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.DecryptAAD(legacyCT, legacyNonce, k, aad); err == nil {
		t.Error("legacy nil-AAD ciphertext opened under DecryptAAD")
	}

	boundCT, boundNonce, err := crypto.EncryptAAD([]byte(sentinel), k, aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.Decrypt(boundCT, boundNonce, k); err == nil {
		t.Error("AAD-bound ciphertext opened under legacy Decrypt (nil AAD)")
	}
}

func TestKMSAAD_NonceUniqueness(t *testing.T) {
	k := key32(t)
	aad := mustBytes(t, base())
	seen := make(map[string]struct{}, 20000)
	for i := 0; i < 20000; i++ {
		_, nonce, err := crypto.EncryptAAD([]byte("x"), k, aad)
		if err != nil {
			t.Fatal(err)
		}
		if len(nonce) != 12 {
			t.Fatalf("nonce length %d, want 12 (AES-GCM standard nonce)", len(nonce))
		}
		if _, dup := seen[string(nonce)]; dup {
			t.Fatalf("nonce repeated after %d encryptions", i)
		}
		seen[string(nonce)] = struct{}{}
	}
}

func TestKMSAAD_ZeroLengthAndLargeValues(t *testing.T) {
	k := key32(t)
	aad := mustBytes(t, base())

	ct, nonce, err := crypto.EncryptAAD(nil, k, aad)
	if err != nil {
		t.Fatalf("zero-length encrypt: %v", err)
	}
	pt, err := crypto.DecryptAAD(ct, nonce, k, aad)
	if err != nil || len(pt) != 0 {
		t.Fatalf("zero-length round trip: pt=%q err=%v", pt, err)
	}
	// A zero-length value must still be bound (the tag covers the AAD).
	other := base()
	other.Key = "OTHER_KEY"
	if _, err := crypto.DecryptAAD(ct, nonce, k, mustBytes(t, other)); err == nil {
		t.Error("zero-length ciphertext opened under another row's AAD")
	}

	big := []byte(strings.Repeat(sentinel, (4<<20)/len(sentinel))) // ~4 MiB
	ct, nonce, err = crypto.EncryptAAD(big, k, aad)
	if err != nil {
		t.Fatalf("large encrypt: %v", err)
	}
	pt, err = crypto.DecryptAAD(ct, nonce, k, aad)
	if err != nil || !bytes.Equal(pt, big) {
		t.Fatalf("large round trip failed: err=%v equal=%v", err, bytes.Equal(pt, big))
	}
}

func TestKMSAAD_TamperedCiphertextOrNonceFails(t *testing.T) {
	k := key32(t)
	aad := mustBytes(t, base())
	ct, nonce, err := crypto.EncryptAAD([]byte(sentinel), k, aad)
	if err != nil {
		t.Fatal(err)
	}
	ct2 := append([]byte(nil), ct...)
	ct2[0] ^= 0x01
	if _, err := crypto.DecryptAAD(ct2, nonce, k, aad); err == nil {
		t.Error("flipped ciphertext bit accepted")
	}
	n2 := append([]byte(nil), nonce...)
	n2[0] ^= 0x01
	if _, err := crypto.DecryptAAD(ct, n2, k, aad); err == nil {
		t.Error("flipped nonce bit accepted")
	}
	if _, err := crypto.DecryptAAD(ct, nonce, key32(t), aad); err == nil {
		t.Error("wrong DEK accepted")
	}
}
