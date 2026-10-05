package store

import (
	"context"
	"fmt"
	"time"
)

// CapAgentTokenExpiry shortens every token of agentID except keepRawToken
// so it expires no later than until. Tokens already expiring earlier are
// left alone. Used by declarative bootstrap rotation: the new token is
// delivered first, then the previous ones get a short overlap instead of
// being deleted outright, so an executor holding the old token is never
// cut off mid-rotation. Returns the number of tokens shortened.
func (s *SQLStore) CapAgentTokenExpiry(ctx context.Context, agentID, keepRawToken string, until time.Time) (int64, error) {
	untilVal := s.dialect.FormatTime(until.UTC())
	res, err := s.db.ExecContext(ctx,
		s.dialect.Rebind(`UPDATE sessions SET expires_at = ?
		 WHERE agent_id = ? AND id <> ? AND (expires_at IS NULL OR expires_at > ?)`),
		untilVal, agentID, hashSessionToken(keepRawToken), untilVal,
	)
	if err != nil {
		return 0, fmt.Errorf("capping agent token expiry: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
