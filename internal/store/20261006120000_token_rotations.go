package store

import "gorm.io/gorm"

// Journal for executor-token rotation (bootstrap). One row per rotation,
// moving planned -> minted -> published -> done; at most one row per agent
// is open (not done), enforced by a partial unique index. new_session_id
// and old_session_id are stored session IDs (sha256 hex of the raw token,
// as sessions.id), never raw tokens.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasTable("token_rotations") {
			return nil
		}
		create := `CREATE TABLE token_rotations (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			agent_id       TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
			state          TEXT NOT NULL CHECK (state IN ('planned', 'minted', 'published', 'done')),
			old_session_id TEXT,
			new_session_id TEXT,
			published_at   TEXT,
			written_at     TEXT,
			created_at     TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
		)`
		if db.Name() == "postgres" {
			create = `CREATE TABLE token_rotations (
				id             BIGSERIAL PRIMARY KEY,
				agent_id       TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
				state          TEXT NOT NULL CHECK (state IN ('planned', 'minted', 'published', 'done')),
				old_session_id TEXT,
				new_session_id TEXT,
				published_at   TIMESTAMPTZ,
				written_at     TIMESTAMPTZ,
				created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
			)`
		}
		if err := db.Exec(create).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE UNIQUE INDEX token_rotations_one_open_per_agent
			ON token_rotations (agent_id) WHERE state <> 'done'`).Error
	})
}
