package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/mail"

	"github.com/Infisical/agent-vault/internal/crypto"
)

// sentinel is the known plaintext encrypted with the DEK during setup and
// verified during unlock.
const sentinel = "agent-vault-master-key-check"

// ErrWrongPassword is returned when the master password does not match.
var ErrWrongPassword = errors.New("wrong master password")

// AAD for the two DEK-related values in master_key. Without it any other
// DEK-encrypted blob of the sentinel string (an API caller can make the
// server encrypt arbitrary values) would verify as the sentinel.
var (
	sentinelAAD   = crypto.AAD{Table: "master_key", Field: "sentinel", Version: 1}
	wrappedDEKAAD = crypto.AAD{Table: "master_key", Field: "dek", Version: 1}
)

// MasterKey holds the DEK (Data Encryption Key) in memory.
type MasterKey struct {
	key []byte
}

// Key returns the raw 32-byte DEK.
func (mk *MasterKey) Key() []byte {
	return mk.key
}

// Wipe zeros the key material. Call this when the server shuts down.
func (mk *MasterKey) Wipe() {
	crypto.WipeBytes(mk.key)
}

// VerificationRecord holds the artifacts needed to unlock the DEK
// on subsequent startups.
type VerificationRecord struct {
	Sentinel      []byte // sentinel ciphertext (encrypted with DEK)
	SentinelNonce []byte // sentinel GCM nonce
	DEKCiphertext []byte // KEK-wrapped DEK (nil in passwordless mode)
	DEKNonce      []byte // DEK wrapping nonce (nil in passwordless mode)
	DEKPlaintext  []byte // unwrapped DEK (nil when password-protected)
	Salt          []byte // KDF salt for KEK derivation (nil in passwordless mode)
	Params        crypto.KDFParams
	KMSWrappedDEK []byte // DEK wrapped by a KMS key (nil unless KMS mode)
	KMSKeyID      string // KMS key that wrapped KMSWrappedDEK
}

// IsKMS reports whether the record holds a KMS-wrapped DEK.
func (r *VerificationRecord) IsKMS() bool { return len(r.KMSWrappedDEK) > 0 }

// KeyWrapper wraps and unwraps the DEK with an external key (AWS KMS in
// production). Implementations must bind encCtx (the KMS encryption context)
// and refuse to unwrap under a different key id or context.
type KeyWrapper interface {
	Wrap(ctx context.Context, dek []byte, encCtx map[string]string) (wrapped []byte, keyID string, err error)
	Unwrap(ctx context.Context, wrapped []byte, keyID string, encCtx map[string]string) ([]byte, error)
}

// DataKeyGenerator is a KeyWrapper that can mint the DEK itself (AWS KMS
// GenerateDataKey): it returns the plaintext DEK, used in memory only, and
// the wrapped copy to store. SetupWithKMS uses it when the wrapper offers
// it, so the key policy never needs kms:Encrypt.
type DataKeyGenerator interface {
	GenerateDataKey(ctx context.Context, encCtx map[string]string) (dek, wrapped []byte, keyID string, err error)
}

// ErrNotKMSRecord is returned by UnlockWithKMS for a record that is not
// KMS-wrapped (passwordless or password-wrapped). There is no fallback.
var ErrNotKMSRecord = errors.New("master key record is not KMS-wrapped")

// SetupWithKMS creates a new random DEK, seals the sentinel with it and wraps
// the DEK with w under encCtx. The record carries neither the plaintext DEK
// nor a password-wrapped copy. Any KMS failure is returned; nothing falls back.
func SetupWithKMS(ctx context.Context, w KeyWrapper, encCtx map[string]string) (*MasterKey, *VerificationRecord, error) {
	if w == nil {
		return nil, nil, errors.New("KMS key wrapper not configured")
	}
	var (
		dek, sentinelCT, sentinelNonce, wrapped []byte
		keyID                                   string
		err                                     error
	)
	if g, ok := w.(DataKeyGenerator); ok {
		// The DEK comes from KMS; only its wrapped copy is stored.
		dek, wrapped, keyID, err = g.GenerateDataKey(ctx, encCtx)
		if err != nil {
			return nil, nil, fmt.Errorf("generating DEK with KMS: %w", err)
		}
		if len(dek) != 32 {
			crypto.WipeBytes(dek)
			return nil, nil, fmt.Errorf("generating DEK with KMS: got %d bytes, want 32", len(dek))
		}
		if sentinelCT, sentinelNonce, err = sentinelAAD.Seal([]byte(sentinel), dek); err != nil {
			crypto.WipeBytes(dek)
			return nil, nil, fmt.Errorf("encrypting sentinel: %w", err)
		}
	} else {
		if dek, sentinelCT, sentinelNonce, err = generateDEK(); err != nil {
			return nil, nil, err
		}
		if wrapped, keyID, err = w.Wrap(ctx, dek, encCtx); err != nil {
			crypto.WipeBytes(dek)
			return nil, nil, fmt.Errorf("wrapping DEK with KMS: %w", err)
		}
	}
	if len(wrapped) == 0 || keyID == "" {
		crypto.WipeBytes(dek)
		return nil, nil, errors.New("wrapping DEK with KMS: empty result")
	}
	return &MasterKey{key: dek}, &VerificationRecord{
		Sentinel:      sentinelCT,
		SentinelNonce: sentinelNonce,
		KMSWrappedDEK: wrapped,
		KMSKeyID:      keyID,
	}, nil
}

// UnlockWithKMS unwraps the DEK through w and verifies the sentinel. It
// refuses records that are not KMS-wrapped instead of falling back to the
// passwordless or password path.
func UnlockWithKMS(ctx context.Context, w KeyWrapper, rec *VerificationRecord, encCtx map[string]string) (*MasterKey, error) {
	if w == nil {
		return nil, errors.New("KMS key wrapper not configured")
	}
	if rec == nil || !rec.IsKMS() || rec.KMSKeyID == "" {
		return nil, ErrNotKMSRecord
	}
	if rec.DEKPlaintext != nil || rec.DEKCiphertext != nil {
		return nil, fmt.Errorf("%w: record also carries a non-KMS DEK", ErrNotKMSRecord)
	}
	dek, err := w.Unwrap(ctx, rec.KMSWrappedDEK, rec.KMSKeyID, encCtx)
	if err != nil {
		return nil, fmt.Errorf("unwrapping DEK with KMS: %w", err)
	}
	if len(dek) != 32 {
		crypto.WipeBytes(dek)
		return nil, errors.New("unwrapping DEK with KMS: unexpected key length")
	}
	if err := verifySentinel(dek, rec.Sentinel, rec.SentinelNonce); err != nil {
		crypto.WipeBytes(dek)
		return nil, err
	}
	return &MasterKey{key: dek}, nil
}

// SetupWithPassword creates a new random DEK, encrypts the sentinel with it,
// then wraps the DEK under a KEK derived from the password via Argon2id.
func SetupWithPassword(password []byte) (*MasterKey, *VerificationRecord, error) {
	dek, sentinelCT, sentinelNonce, err := generateDEK()
	if err != nil {
		return nil, nil, err
	}

	salt, dekCT, dekNonce, params, err := WrapDEK(dek, password)
	if err != nil {
		crypto.WipeBytes(dek)
		return nil, nil, fmt.Errorf("wrapping DEK: %w", err)
	}

	return &MasterKey{key: dek}, &VerificationRecord{
		Sentinel:      sentinelCT,
		SentinelNonce: sentinelNonce,
		DEKCiphertext: dekCT,
		DEKNonce:      dekNonce,
		Salt:          salt,
		Params:        params,
	}, nil
}

// SetupPasswordless creates a new random DEK and encrypts the sentinel with it.
// The DEK is stored in plaintext — security depends on filesystem access controls.
func SetupPasswordless() (*MasterKey, *VerificationRecord, error) {
	dek, sentinelCT, sentinelNonce, err := generateDEK()
	if err != nil {
		return nil, nil, err
	}

	// Copy the DEK for storage — the MasterKey holds the original.
	dekCopy := make([]byte, len(dek))
	copy(dekCopy, dek)

	return &MasterKey{key: dek}, &VerificationRecord{
		Sentinel:      sentinelCT,
		SentinelNonce: sentinelNonce,
		DEKPlaintext:  dekCopy,
	}, nil
}

// generateDEK creates a random 32-byte DEK and encrypts the sentinel with it.
func generateDEK() (dek, sentinelCT, sentinelNonce []byte, err error) {
	dek, err = crypto.GenerateSalt(32)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generating DEK: %w", err)
	}

	sentinelCT, sentinelNonce, err = sentinelAAD.Seal([]byte(sentinel), dek)
	if err != nil {
		crypto.WipeBytes(dek)
		return nil, nil, nil, fmt.Errorf("encrypting sentinel: %w", err)
	}

	return dek, sentinelCT, sentinelNonce, nil
}

// Unlock derives the KEK from the password, unwraps the DEK, and verifies
// the sentinel. Returns ErrWrongPassword if the password is incorrect.
func Unlock(password []byte, record *VerificationRecord) (*MasterKey, error) {
	kek := crypto.DeriveKey(password, record.Salt, record.Params)

	dek, err := wrappedDEKAAD.Open(record.DEKCiphertext, record.DEKNonce, kek)
	crypto.WipeBytes(kek)
	if err != nil {
		return nil, ErrWrongPassword
	}

	if err := verifySentinel(dek, record.Sentinel, record.SentinelNonce); err != nil {
		crypto.WipeBytes(dek)
		return nil, err
	}

	return &MasterKey{key: dek}, nil
}

// UnlockPasswordless loads the DEK from plaintext storage and verifies the sentinel.
func UnlockPasswordless(record *VerificationRecord) (*MasterKey, error) {
	// Make a copy so the caller's record isn't shared with the MasterKey.
	dek := make([]byte, len(record.DEKPlaintext))
	copy(dek, record.DEKPlaintext)

	if err := verifySentinel(dek, record.Sentinel, record.SentinelNonce); err != nil {
		crypto.WipeBytes(dek)
		return nil, err
	}

	return &MasterKey{key: dek}, nil
}

// WrapDEK wraps a DEK under a new KEK derived from the password.
// Returns the salt, wrapped DEK ciphertext, nonce, and KDF params.
func WrapDEK(dek, password []byte) (salt, dekCT, dekNonce []byte, params crypto.KDFParams, err error) {
	params = crypto.DefaultKDFParams()

	salt, err = crypto.GenerateSalt(int(params.SaltLen))
	if err != nil {
		return nil, nil, nil, params, fmt.Errorf("generating KEK salt: %w", err)
	}

	kek := crypto.DeriveKey(password, salt, params)
	dekCT, dekNonce, err = wrappedDEKAAD.Seal(dek, kek)
	crypto.WipeBytes(kek)
	if err != nil {
		return nil, nil, nil, params, fmt.Errorf("wrapping DEK: %w", err)
	}

	return salt, dekCT, dekNonce, params, nil
}

// verifySentinel decrypts the stored sentinel with the DEK and checks it
// matches the expected value.
func verifySentinel(dek, sentinelCT, sentinelNonce []byte) error {
	plaintext, err := sentinelAAD.Open(sentinelCT, sentinelNonce, dek)
	if err != nil {
		return ErrWrongPassword
	}
	if subtle.ConstantTimeCompare(plaintext, []byte(sentinel)) != 1 {
		return ErrWrongPassword
	}
	return nil
}

// UnlockLegacy unlocks a v0.40.0 record (password-wrapped DEK and sentinel
// sealed with nil AAD) and returns the DEK together with an upgraded record
// in the AAD-bound form. It exists only for the one-time upgrade of an
// instance whose row-bound AAD migration has not completed; callers must not
// use it once the migration is complete.
func UnlockLegacy(password []byte, record *VerificationRecord) (*MasterKey, *VerificationRecord, error) {
	kek := crypto.DeriveKey(password, record.Salt, record.Params)
	dek, err := crypto.Decrypt(record.DEKCiphertext, record.DEKNonce, kek)
	crypto.WipeBytes(kek)
	if err != nil {
		return nil, nil, ErrWrongPassword
	}
	if err := verifyLegacySentinel(dek, record.Sentinel, record.SentinelNonce); err != nil {
		crypto.WipeBytes(dek)
		return nil, nil, err
	}
	up, err := upgradedRecord(dek, password)
	if err != nil {
		crypto.WipeBytes(dek)
		return nil, nil, err
	}
	return &MasterKey{key: dek}, up, nil
}

// UnlockPasswordlessLegacy is UnlockLegacy for a passwordless record.
func UnlockPasswordlessLegacy(record *VerificationRecord) (*MasterKey, *VerificationRecord, error) {
	dek := make([]byte, len(record.DEKPlaintext))
	copy(dek, record.DEKPlaintext)
	if err := verifyLegacySentinel(dek, record.Sentinel, record.SentinelNonce); err != nil {
		crypto.WipeBytes(dek)
		return nil, nil, err
	}
	up, err := upgradedRecord(dek, nil)
	if err != nil {
		crypto.WipeBytes(dek)
		return nil, nil, err
	}
	return &MasterKey{key: dek}, up, nil
}

func upgradedRecord(dek, password []byte) (*VerificationRecord, error) {
	sentCT, sentNonce, err := sentinelAAD.Seal([]byte(sentinel), dek)
	if err != nil {
		return nil, fmt.Errorf("encrypting sentinel: %w", err)
	}
	rec := &VerificationRecord{Sentinel: sentCT, SentinelNonce: sentNonce}
	if len(password) == 0 {
		rec.DEKPlaintext = append([]byte(nil), dek...)
		return rec, nil
	}
	salt, dekCT, dekNonce, params, err := WrapDEK(dek, password)
	if err != nil {
		return nil, fmt.Errorf("wrapping DEK: %w", err)
	}
	rec.Salt, rec.DEKCiphertext, rec.DEKNonce, rec.Params = salt, dekCT, dekNonce, params
	return rec, nil
}

func verifyLegacySentinel(dek, sentinelCT, sentinelNonce []byte) error {
	plaintext, err := crypto.Decrypt(sentinelCT, sentinelNonce, dek)
	if err != nil {
		return ErrWrongPassword
	}
	if subtle.ConstantTimeCompare(plaintext, []byte(sentinel)) != 1 {
		return ErrWrongPassword
	}
	return nil
}

// HashUserPassword hashes a user password with a random salt using Argon2id.
// Returns the hash, salt, and the KDF parameters used (for storage alongside the hash).
func HashUserPassword(password []byte) (hash, salt []byte, params crypto.KDFParams, err error) {
	params = crypto.DefaultKDFParams()
	salt, err = crypto.GenerateSalt(int(params.SaltLen))
	if err != nil {
		return nil, nil, params, fmt.Errorf("generating salt: %w", err)
	}
	hash = crypto.DeriveKey(password, salt, params)
	return hash, salt, params, nil
}

// VerifyUserPassword checks a password against a stored hash, salt, and KDF params.
func VerifyUserPassword(password, hash, salt []byte, params crypto.KDFParams) bool {
	derived := crypto.DeriveKey(password, salt, params)
	return subtle.ConstantTimeCompare(derived, hash) == 1
}

// ValidateEmail performs basic email format validation.
func ValidateEmail(email string) error {
	if email == "" {
		return errors.New("email is required")
	}
	_, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email format: %w", err)
	}
	return nil
}
