package store

import "gorm.io/gorm"

// Journal for provider-key rotation (a pasted value replacing an existing
// one). One row per replacement holds the superseded value, still sealed
// under its own version's AAD, until a probe proves the provider no longer
// accepts it; then old_ciphertext and old_nonce are destroyed and closed_at
// set. At most one open row per credential key (partial unique index), so
// at most two values of a key are ever live.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasTable("credential_rotations") {
			return nil
		}
		create := `CREATE TABLE credential_rotations (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			vault_id       TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
			credential_key TEXT NOT NULL,
			old_version    BIGINT NOT NULL,
			new_version    BIGINT NOT NULL,
			old_ciphertext BLOB,
			old_nonce      BLOB,
			created_at     TEXT NOT NULL DEFAULT (datetime('now')),
			closed_at      TEXT
		)`
		if db.Name() == "postgres" {
			create = `CREATE TABLE credential_rotations (
				id             BIGSERIAL PRIMARY KEY,
				vault_id       TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
				credential_key TEXT NOT NULL,
				old_version    BIGINT NOT NULL,
				new_version    BIGINT NOT NULL,
				old_ciphertext BYTEA,
				old_nonce      BYTEA,
				created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				closed_at      TIMESTAMPTZ
			)`
		}
		if err := db.Exec(create).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE UNIQUE INDEX credential_rotations_one_open_per_key
			ON credential_rotations (vault_id, credential_key) WHERE closed_at IS NULL`).Error
	})
}
