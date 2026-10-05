package store

import "gorm.io/gorm"

// Row-bound AAD and KMS-wrapped DEK.
//
//   - credentials.version, credential_oauth.version,
//     credential_oauth.client_secret_version and proposal_credentials.version
//     are monotonic per-row counters bound into the AES-GCM additional data of
//     the row's ciphertexts (see crypto.AAD). Existing rows start at 0; the
//     aadmigrate pass rewraps their nil-AAD ciphertexts and bumps the version.
//   - master_key.kms_wrapped_dek and master_key.kms_key_id hold a DEK wrapped
//     by an external KMS key (AGENT_VAULT_KMS_KEY_ID).
//
// Idempotent: every column is added only when missing, on both dialects.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		blob := "BLOB"
		if db.Name() == "postgres" {
			blob = "BYTEA"
		}
		cols := []struct{ table, column, ddl string }{
			{"credentials", "version", "BIGINT NOT NULL DEFAULT 0"},
			{"credential_oauth", "version", "BIGINT NOT NULL DEFAULT 0"},
			{"credential_oauth", "client_secret_version", "BIGINT NOT NULL DEFAULT 0"},
			{"proposal_credentials", "version", "BIGINT NOT NULL DEFAULT 0"},
			{"master_key", "kms_wrapped_dek", blob},
			{"master_key", "kms_key_id", "TEXT"},
		}
		for _, c := range cols {
			if !db.Migrator().HasTable(c.table) || db.Migrator().HasColumn(c.table, c.column) {
				continue
			}
			if err := db.Exec("ALTER TABLE " + c.table + " ADD COLUMN " + c.column + " " + c.ddl).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
