package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Token rotation journal states, in order.
const (
	RotationPlanned   = "planned"
	RotationMinted    = "minted"
	RotationPublished = "published"
	RotationDone      = "done"
)

// TokenRotation is one row of the executor-token rotation journal. Session
// IDs are stored IDs (SessionID of the raw token), never raw tokens.
type TokenRotation struct {
	ID           int64
	AgentID      string
	State        string
	OldSessionID string // the delivered session when the rotation was planned; "" if none was readable
	NewSessionID string // the minted session; "" while planned
	PublishedAt  *time.Time
}

// ErrRotationState is returned when a journal row is not in the state a
// step requires (another runner moved it, or it was closed).
var ErrRotationState = errors.New("store: token rotation is not in the expected state")

// SessionID returns the stored ID of a raw session or agent token.
func SessionID(rawToken string) string { return hashSessionToken(rawToken) }

// OpenTokenRotation returns the agent's open (not done) rotation, or nil.
func (s *SQLStore) OpenTokenRotation(ctx context.Context, agentID string) (*TokenRotation, error) {
	var r TokenRotation
	var oldID, newID sql.NullString
	var publishedAt interface{}
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT id, agent_id, state, old_session_id, new_session_id, published_at
		FROM token_rotations WHERE agent_id = ? AND state <> 'done' ORDER BY id DESC LIMIT 1`), agentID).
		Scan(&r.ID, &r.AgentID, &r.State, &oldID, &newID, &publishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading token rotation: %w", err)
	}
	r.OldSessionID, r.NewSessionID = oldID.String, newID.String
	r.PublishedAt, _ = s.dialect.ScanNullableTime(publishedAt)
	return &r, nil
}

// PlanTokenRotation writes a planned row for agentID. The partial unique
// index refuses a second open row for the same agent.
func (s *SQLStore) PlanTokenRotation(ctx context.Context, agentID, oldSessionID string) (*TokenRotation, error) {
	now := s.now()
	var id int64
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`INSERT INTO token_rotations
		(agent_id, state, old_session_id, created_at, updated_at) VALUES (?, 'planned', ?, ?, ?) RETURNING id`),
		agentID, nullableString(oldSessionID), now, now).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("planning token rotation: %w", err)
	}
	return &TokenRotation{ID: id, AgentID: agentID, State: RotationPlanned, OldSessionID: oldSessionID}, nil
}

// MintTokenRotation mints the rotation's new session in one transaction:
// the session left by an earlier attempt of this row (never published) is
// deleted, a new agent token is created expiring at pendingUntil, every
// other session of the agent except the delivered old one is deleted, the
// old one is cut to pendingUntil (never extended), and the row moves to
// minted naming the new session. It returns the raw token.
func (s *SQLStore) MintTokenRotation(ctx context.Context, rotationID int64, pendingUntil time.Time) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var agentID, state string
	var oldID, prevID sql.NullString
	if err := tx.QueryRowContext(ctx, s.dialect.Rebind(`SELECT agent_id, state, old_session_id, new_session_id
		FROM token_rotations WHERE id = ?`), rotationID).Scan(&agentID, &state, &oldID, &prevID); err != nil {
		return "", fmt.Errorf("reading token rotation: %w", err)
	}
	if state != RotationPlanned && state != RotationMinted {
		return "", ErrRotationState
	}
	if prevID.String != "" {
		if _, err := tx.ExecContext(ctx, s.dialect.Rebind(`DELETE FROM sessions WHERE id = ? AND agent_id = ?`), prevID.String, agentID); err != nil {
			return "", fmt.Errorf("deleting unpublished session: %w", err)
		}
	}

	raw := newAgentToken()
	newID := hashSessionToken(raw)
	until := s.dialect.FormatTime(pendingUntil.UTC())
	if _, err := tx.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO sessions (id, agent_id, expires_at, created_at) VALUES (?, ?, ?, ?)`),
		newID, agentID, until, s.now()); err != nil {
		return "", fmt.Errorf("creating pending session: %w", err)
	}
	if oldID.String != "" {
		// Only the delivered old token and the new one may stay valid.
		if _, err := tx.ExecContext(ctx, s.dialect.Rebind(`DELETE FROM sessions WHERE agent_id = ? AND id <> ? AND id <> ?`),
			agentID, newID, oldID.String); err != nil {
			return "", fmt.Errorf("revoking stray sessions: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, s.dialect.Rebind(`UPDATE sessions SET expires_at = ?
		WHERE agent_id = ? AND id <> ? AND (expires_at IS NULL OR expires_at > ?)`),
		until, agentID, newID, until); err != nil {
		return "", fmt.Errorf("cutting old sessions: %w", err)
	}
	res, err := tx.ExecContext(ctx, s.dialect.Rebind(`UPDATE token_rotations SET state = 'minted', new_session_id = ?, updated_at = ?
		WHERE id = ? AND state IN ('planned', 'minted')`), newID, s.now(), rotationID)
	if err != nil {
		return "", fmt.Errorf("recording mint: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrRotationState
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return raw, nil
}

// PublishTokenRotation records a confirmed publish: the new session gets
// fullExpiry, every other session of the agent is cut to overlapUntil
// (never extended), and the row moves to published at publishedAt.
func (s *SQLStore) PublishTokenRotation(ctx context.Context, rotationID int64, fullExpiry, overlapUntil, publishedAt time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var agentID, state string
	var newID sql.NullString
	if err := tx.QueryRowContext(ctx, s.dialect.Rebind(`SELECT agent_id, state, new_session_id FROM token_rotations WHERE id = ?`), rotationID).
		Scan(&agentID, &state, &newID); err != nil {
		return fmt.Errorf("reading token rotation: %w", err)
	}
	if state != RotationMinted || newID.String == "" {
		return ErrRotationState
	}
	res, err := tx.ExecContext(ctx, s.dialect.Rebind(`UPDATE sessions SET expires_at = ? WHERE id = ? AND agent_id = ?`),
		s.dialect.FormatTime(fullExpiry.UTC()), newID.String, agentID)
	if err != nil {
		return fmt.Errorf("extending published session: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("extending published session: %w", sql.ErrNoRows)
	}
	until := s.dialect.FormatTime(overlapUntil.UTC())
	if _, err := tx.ExecContext(ctx, s.dialect.Rebind(`UPDATE sessions SET expires_at = ?
		WHERE agent_id = ? AND id <> ? AND (expires_at IS NULL OR expires_at > ?)`),
		until, agentID, newID.String, until); err != nil {
		return fmt.Errorf("cutting old sessions: %w", err)
	}
	if _, err := tx.ExecContext(ctx, s.dialect.Rebind(`UPDATE token_rotations SET state = 'published', published_at = ?, updated_at = ?
		WHERE id = ? AND state = 'minted'`), s.dialect.FormatTime(publishedAt.UTC()), s.now(), rotationID); err != nil {
		return fmt.Errorf("recording publish: %w", err)
	}
	return tx.Commit()
}

// RevokeTokenRotationOld deletes every session of the rotation's agent
// except its new (published) one. Repeating it is a no-op.
func (s *SQLStore) RevokeTokenRotationOld(ctx context.Context, rotationID int64) error {
	var agentID, state string
	var newID sql.NullString
	if err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT agent_id, state, new_session_id FROM token_rotations WHERE id = ?`), rotationID).
		Scan(&agentID, &state, &newID); err != nil {
		return fmt.Errorf("reading token rotation: %w", err)
	}
	if state != RotationPublished || newID.String == "" {
		return ErrRotationState
	}
	if _, err := s.db.ExecContext(ctx, s.dialect.Rebind(`DELETE FROM sessions WHERE agent_id = ? AND id <> ?`), agentID, newID.String); err != nil {
		return fmt.Errorf("revoking old sessions: %w", err)
	}
	return nil
}

// FinishTokenRotation closes a published rotation.
func (s *SQLStore) FinishTokenRotation(ctx context.Context, rotationID int64) error {
	res, err := s.db.ExecContext(ctx, s.dialect.Rebind(`UPDATE token_rotations SET state = 'done', updated_at = ?
		WHERE id = ? AND state = 'published'`), s.now(), rotationID)
	if err != nil {
		return fmt.Errorf("closing token rotation: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrRotationState
	}
	return nil
}

// CapAgentSessionsExcept cuts every session of agentID except keepSessionID
// (a stored ID) to until. It only ever shortens an expiry.
func (s *SQLStore) CapAgentSessionsExcept(ctx context.Context, agentID, keepSessionID string, until time.Time) (int64, error) {
	u := s.dialect.FormatTime(until.UTC())
	res, err := s.db.ExecContext(ctx, s.dialect.Rebind(`UPDATE sessions SET expires_at = ?
		WHERE agent_id = ? AND id <> ? AND (expires_at IS NULL OR expires_at > ?)`), u, agentID, keepSessionID, u)
	if err != nil {
		return 0, fmt.Errorf("capping agent sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
