package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Encrypt encrypts plaintext using AES-256-GCM with the given 32-byte key.
// It returns the ciphertext and a randomly generated nonce.
//
// Encrypt seals with nil additional data. Every stored DEK-encrypted value
// uses EncryptAAD instead; Encrypt remains for values that are not bound to
// a row (and for tests that build legacy fixtures).
func Encrypt(plaintext, key []byte) (ciphertext, nonce []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with the given 32-byte key and nonce.
func Decrypt(ciphertext, nonce, key []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("decrypting: bad nonce length")
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

// AAD identifies the row and field a DEK-encrypted value belongs to. It is
// bound into the AES-GCM tag as additional authenticated data so that a
// ciphertext copied to another row, vault, field, table or version fails to
// open. The encoding is part of the stored-data contract:
//
//	table 0x00 field 0x00 vault_id 0x00 key 0x00 decimal(version)
type AAD struct {
	Table   string
	Field   string
	VaultID string
	Key     string
	Version uint64
}

// Bytes returns the canonical AAD encoding. Table and Field must be
// non-empty and no component may contain the 0x00 separator.
func (a AAD) Bytes() ([]byte, error) {
	if a.Table == "" || a.Field == "" {
		return nil, fmt.Errorf("aad: table and field are required")
	}
	for _, v := range []string{a.Table, a.Field, a.VaultID, a.Key} {
		if strings.IndexByte(v, 0) >= 0 {
			return nil, fmt.Errorf("aad: component contains a 0x00 byte")
		}
	}
	out := make([]byte, 0, len(a.Table)+len(a.Field)+len(a.VaultID)+len(a.Key)+24)
	out = append(out, a.Table...)
	out = append(out, 0)
	out = append(out, a.Field...)
	out = append(out, 0)
	out = append(out, a.VaultID...)
	out = append(out, 0)
	out = append(out, a.Key...)
	out = append(out, 0)
	out = strconv.AppendUint(out, a.Version, 10)
	return out, nil
}

// Seal encrypts plaintext bound to this AAD.
func (a AAD) Seal(plaintext, key []byte) (ciphertext, nonce []byte, err error) {
	b, err := a.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return EncryptAAD(plaintext, key, b)
}

// Open decrypts a ciphertext bound to this AAD.
func (a AAD) Open(ciphertext, nonce, key []byte) ([]byte, error) {
	b, err := a.Bytes()
	if err != nil {
		return nil, err
	}
	return DecryptAAD(ciphertext, nonce, key, b)
}

// EncryptAAD seals plaintext with AES-256-GCM, binding aad into the tag.
// An empty aad is refused: the legacy nil-AAD form is only reachable
// through Encrypt.
func EncryptAAD(plaintext, key, aad []byte) (ciphertext, nonce []byte, err error) {
	if len(aad) == 0 {
		return nil, nil, fmt.Errorf("encrypt: empty AAD")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generating nonce: %w", err)
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nonce, nil
}

// DecryptAAD opens a ciphertext sealed by EncryptAAD with the same aad.
func DecryptAAD(ciphertext, nonce, key, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, fmt.Errorf("decrypt: empty AAD")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("decrypting: bad nonce length")
	}
	pt, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	if pt == nil {
		pt = []byte{}
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	return gcm, nil
}
