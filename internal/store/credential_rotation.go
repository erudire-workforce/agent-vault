package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CredentialIdentityPinSettingKey is the vault_settings key holding the
// pinned identity digest (64 lowercase hex) for credential key: the only
// identity a value of that key may act as.
func CredentialIdentityPinSettingKey(credentialKey string) string {
	return "credential_identity_pin:" + credentialKey
}

// ErrCredentialRotationOpen is returned when a key is replaced while an
// earlier replacement's superseded value has not been proven dead.
var ErrCredentialRotationOpen = errors.New("store: a rotation of this credential is still open")

// CredentialRotation is an open provider-key rotation: the superseded value
// (sealed under CredentialValueAAD(vault, key, OldVersion)) awaiting proof
// that the provider rejects it.
type CredentialRotation struct {
	ID            int64
	VaultID       string
	CredentialKey string
	OldVersion    uint64
	NewVersion    uint64
	OldCiphertext []byte
	OldNonce      []byte
	CreatedAt     time.Time
}

// ReplaceCredentialJournaled stores a value sealed for version (the row's
// next version) and, in the same transaction, journals the value it
// replaces. It is a compare-and-set like SetCredentialVersion: the write
// lands only if the row is at version-1. A new row (nothing replaced) is
// written without a journal row. ErrCredentialRotationOpen is returned while
// the key has an open rotation; if the journal row cannot be written,
// nothing is replaced.
func (s *SQLStore) ReplaceCredentialJournaled(ctx context.Context, vaultID, key string, ciphertext, nonce []byte, version uint64) (*Credential, error) {
	if version == 0 {
		return nil, fmt.Errorf("replacing credential: version must be > 0")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var curCT, curNonce []byte
	var curVersion int64
	err = tx.QueryRowContext(ctx, s.dialect.Rebind(`SELECT ciphertext, nonce, version FROM credentials WHERE vault_id = ? AND key = ?`),
		vaultID, key).Scan(&curCT, &curNonce, &curVersion)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Nothing replaced: a plain compare-and-set insert.
		if err := tx.Rollback(); err != nil {
			return nil, err
		}
		return s.SetCredentialVersion(ctx, vaultID, key, ciphertext, nonce, version)
	case err != nil:
		return nil, fmt.Errorf("reading credential: %w", err)
	}
	if uint64(curVersion) != version-1 {
		return nil, ErrVersionConflict
	}
	var open int
	if err := tx.QueryRowContext(ctx, s.dialect.Rebind(`SELECT COUNT(*) FROM credential_rotations
		WHERE vault_id = ? AND credential_key = ? AND closed_at IS NULL`), vaultID, key).Scan(&open); err != nil {
		return nil, fmt.Errorf("checking open rotations: %w", err)
	}
	if open > 0 {
		return nil, ErrCredentialRotationOpen
	}
	if _, err := tx.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO credential_rotations
		(vault_id, credential_key, old_version, new_version, old_ciphertext, old_nonce, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`),
		vaultID, key, curVersion, int64(version), curCT, curNonce, s.now()); err != nil {
		return nil, fmt.Errorf("journaling the replaced value: %w", err)
	}
	res, err := tx.ExecContext(ctx, s.dialect.Rebind(`UPDATE credentials SET ciphertext = ?, nonce = ?, version = ?, updated_at = ?
		WHERE vault_id = ? AND key = ? AND version = ?`),
		ciphertext, nonce, int64(version), s.now(), vaultID, key, curVersion)
	if err != nil {
		return nil, fmt.Errorf("replacing credential: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrVersionConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetCredential(ctx, vaultID, key)
}

// HasOpenCredentialRotation reports whether key has an open rotation.
func (s *SQLStore) HasOpenCredentialRotation(ctx context.Context, vaultID, key string) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT COUNT(*) FROM credential_rotations
		WHERE vault_id = ? AND credential_key = ? AND closed_at IS NULL`), vaultID, key).Scan(&n); err != nil {
		return false, fmt.Errorf("checking open rotations: %w", err)
	}
	return n > 0, nil
}

// CredentialRotationSuspended reports whether key has an open rotation
// created at or before openedBefore (its superseded value has outlived the
// grace window without being proven dead).
func (s *SQLStore) CredentialRotationSuspended(ctx context.Context, vaultID, key string, openedBefore time.Time) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT COUNT(*) FROM credential_rotations
		WHERE vault_id = ? AND credential_key = ? AND closed_at IS NULL AND created_at <= ?`),
		vaultID, key, s.dialect.FormatTime(openedBefore.UTC())).Scan(&n); err != nil {
		return false, fmt.Errorf("checking rotation suspension: %w", err)
	}
	return n > 0, nil
}

// ListOpenCredentialRotations returns every open rotation, oldest first.
func (s *SQLStore) ListOpenCredentialRotations(ctx context.Context) ([]CredentialRotation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, vault_id, credential_key, old_version, new_version, old_ciphertext, old_nonce, created_at
		FROM credential_rotations WHERE closed_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("listing open rotations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []CredentialRotation
	for rows.Next() {
		var r CredentialRotation
		var oldV, newV int64
		var createdAt interface{}
		if err := rows.Scan(&r.ID, &r.VaultID, &r.CredentialKey, &oldV, &newV, &r.OldCiphertext, &r.OldNonce, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning rotation: %w", err)
		}
		r.OldVersion, r.NewVersion = uint64(oldV), uint64(newV)
		r.CreatedAt, _ = s.dialect.ScanTime(createdAt)
		out = append(out, r)
	}
	return out, rows.Err()
}

// CloseCredentialRotation destroys the superseded value and closes the row.
// Only the first caller closes it; it reports whether this call did.
func (s *SQLStore) CloseCredentialRotation(ctx context.Context, id int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, s.dialect.Rebind(`UPDATE credential_rotations
		SET old_ciphertext = NULL, old_nonce = NULL, closed_at = ?
		WHERE id = ? AND closed_at IS NULL`), s.now(), id)
	if err != nil {
		return false, fmt.Errorf("closing rotation: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
