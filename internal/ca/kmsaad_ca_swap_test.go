//go:build kmsaad

// Runtime tests: the CA root private key is sealed with nil AAD
// (soft.go:276/363), so any DEK ciphertext of an EC key DER can replace it.
// An API caller can obtain such a ciphertext from the credential write path
// (POST /v1/credentials stores crypto.Encrypt(value, DEK) at v0.40.0). With
// write access to ca_state (Postgres) or the CA key file (SQLite deployments)
// that yields a MITM root the attacker holds the key for. Root key must carry
// crypto.AAD{Table:"ca_root_key", Field:"root_key", Version:n}.
package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
)

// attackerRoot returns a self-signed CA cert and the DER of its key, sealed
// the way the credential write path seals any value.
func attackerRoot(t *testing.T, dek []byte) (certPEM, keyCT, keyNonce []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242), Subject: pkix.Name{CommonName: "attacker root SENTINEL-AV-TEST-0501"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ct, n, err := crypto.Encrypt(keyDER, dek) // the credential-path oracle
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ct, n
}

func TestKMSAAD_CAKeyFileSwapFromCredentialCiphertextRefused(t *testing.T) {
	dek := testMasterKey()
	dir := t.TempDir()
	if _, err := New(dek, Options{Dir: dir}); err != nil {
		t.Fatalf("precondition: create CA: %v", err)
	}
	certPEM, ct, n := attackerRoot(t, dek)
	if err := os.WriteFile(filepath.Join(dir, rootCertFile), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(encryptedKeyFile{Nonce: base64.StdEncoding.EncodeToString(n), Ciphertext: base64.StdEncoding.EncodeToString(ct)})
	if err := os.WriteFile(filepath.Join(dir, rootKeyFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := New(dek, Options{Dir: dir}); err == nil {
		t.Fatalf("CA loaded an attacker root whose key is a credential-path ciphertext (root CN %q)", c.rootCert.Subject.CommonName)
	}
}

type memCAStore struct{ rec *CAStateRecord }

func (m *memCAStore) GetCAState(context.Context) (*CAStateRecord, error) { return m.rec, nil }
func (m *memCAStore) SetCAState(_ context.Context, r *CAStateRecord) error {
	if m.rec == nil {
		m.rec = r
	}
	return nil
}

// Postgres deployments keep the root in ca_state (cmd/server.go:212-214).
func TestKMSAAD_CAStateSwapFromCredentialCiphertextRefused(t *testing.T) {
	dek := testMasterKey()
	st := &memCAStore{}
	if _, err := New(dek, Options{Store: st}); err != nil {
		t.Fatalf("precondition: create DB-backed CA: %v", err)
	}
	certPEM, ct, n := attackerRoot(t, dek)
	st.rec = &CAStateRecord{RootCert: certPEM, RootKeyCT: ct, RootKeyNonce: n}
	if c, err := New(dek, Options{Store: st}); err == nil {
		t.Fatalf("DB-backed CA loaded an attacker root whose key is a credential-path ciphertext (root CN %q)", c.rootCert.Subject.CommonName)
	}
}

// Freshly generated root keys must already be bound (nil-AAD open fails).
func TestKMSAAD_NewCAKeyIsAADBound(t *testing.T) {
	dek := testMasterKey()
	st := &memCAStore{}
	if _, err := New(dek, Options{Store: st}); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.Decrypt(st.rec.RootKeyCT, st.rec.RootKeyNonce, dek); err == nil {
		t.Fatal("new CA root key opens with nil AAD")
	}
}
