package store

import (
	"context"
	"fmt"
	"time"
)

// CapAgentTokenExpiry shortens every token of agentID except keepRawToken
// so it expires no later than until. Tokens already expiring earlier are
// left alone. Returns the number of tokens shortened. No production code
// calls it since the rotation journal (CapAgentSessionsExcept); see
// bootstrap.TokenCapper for the one test that still does.
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
