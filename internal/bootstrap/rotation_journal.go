package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// Journaled executor-token rotation (fork change 17).
//
// Every rotation is a token_rotations row that moves
//
//	planned -> minted -> published -> done
//
// and is resumed from its state by the next run (Apply at startup, or any
// RotateIfDue tick), so a crash at any point is recovered:
//
//   - planned: nothing minted yet; the next run mints.
//   - minted: a session exists with a PendingExpiry expiry and the old
//     session is cut to the same bound. The next run reads the sink back:
//     if it holds the new token the write landed and the rotation is
//     published as is; otherwise the unpublished session is replaced.
//   - published: the new session has its full TTL (only after the sink was
//     written AND read back with a matching digest); the old one is cut to
//     RotationOverlap and revoked RevokeAfter later.
//   - done: closed.
//
// At most two executor sessions are valid at any time: the delivered old
// one and one unpublished or newly published replacement.

// PendingExpiry is the new session's expiry until its publish is confirmed,
// and the cut applied to the old session at mint. Measured on the wall
// clock, as the proxy checks expiry.
const PendingExpiry = 15 * time.Minute

// RevokeAfter is the delay between publishing the new token and revoking
// the old one, measured on Options.Now. A variable so tests can shorten it.
var RevokeAfter = 10 * time.Minute

// RotationTickInterval is the default rotation-loop tick.
var RotationTickInterval = time.Minute

// Fault points of a rotation, for FaultHook.
const (
	FaultAfterPlan        = "after-plan"         // planned row committed, nothing minted
	FaultAfterMint        = "after-mint"         // minted row committed, secret not written
	FaultAfterSecretWrite = "after-secret-write" // secret written, row not yet published
	FaultAfterPublished   = "after-published"    // published row committed, old not revoked
	FaultAfterRevoke      = "after-revoke"       // old revoked, row not yet done
)

// FaultHook, when non-nil, is called at each fault point of a rotation. A
// non-nil return aborts the run there exactly as a crash would: nothing
// after it runs, and the run returns an error wrapping it. Tests only.
var FaultHook func(point string) error

func fault(point string) error {
	if FaultHook == nil {
		return nil
	}
	if err := FaultHook(point); err != nil {
		return fmt.Errorf("bootstrap: rotation stopped at %s: %w", point, err)
	}
	return nil
}

// RotationJournal is the store surface for the rotation journal. The SQL
// store implements it; bootstrap refuses to rotate without it.
type RotationJournal interface {
	OpenTokenRotation(ctx context.Context, agentID string) (*store.TokenRotation, error)
	PlanTokenRotation(ctx context.Context, agentID, oldSessionID string) (*store.TokenRotation, error)
	MintTokenRotation(ctx context.Context, rotationID int64, pendingUntil time.Time) (string, error)
	PublishTokenRotation(ctx context.Context, rotationID int64, fullExpiry, overlapUntil, publishedAt time.Time) error
	RevokeTokenRotationOld(ctx context.Context, rotationID int64) error
	FinishTokenRotation(ctx context.Context, rotationID int64) error
	CapAgentSessionsExcept(ctx context.Context, agentID, keepSessionID string, until time.Time) (int64, error)
}

// ensureToken keeps a valid, delivered token for agentID. It first resumes
// any open rotation. Otherwise it plans one when the sink cannot be read,
// holds nothing, holds a token the store no longer accepts, or holds one
// within RotateBefore of expiry; a run with nothing to do still caps the
// agent's other sessions to RotationOverlap. It reports whether a new
// token was published.
func ensureToken(ctx context.Context, o Options, agentID string, ttl time.Duration) (bool, error) {
	if o.Tokens == nil {
		return false, errors.New("bootstrap: no token sink")
	}
	if agentID == "" {
		return false, errors.New("bootstrap: executor agent missing")
	}
	j, ok := o.Store.(RotationJournal)
	if !ok {
		return false, errors.New("bootstrap: store has no token rotation journal")
	}
	open, err := j.OpenTokenRotation(ctx, agentID)
	if err != nil {
		return false, fmt.Errorf("bootstrap: %w", err)
	}
	if open != nil {
		published, err := resumeRotation(ctx, o, j, open, ttl)
		if err != nil || published || open.State != store.RotationDone {
			return published, err
		}
		// The open rotation just closed; check below whether the token
		// it delivered is itself due.
	}

	var oldID string
	if tok, exp, err := o.Tokens.GetToken(ctx, o.Executor); err == nil && tok != "" {
		if sess := liveSession(ctx, o.Store, tok, agentID); sess != nil && sess.ExpiresAt != nil {
			oldID = store.SessionID(tok)
			// The store's expiry is authoritative; the sink's copy can
			// only make rotation earlier.
			if sess.ExpiresAt.Before(exp) {
				exp = *sess.ExpiresAt
			}
			if o.now().Before(exp.Add(-RotateBefore)) {
				// Nothing to rotate, but every run caps the agent's
				// other sessions (one left by a crash or an earlier
				// failure) to the overlap.
				if _, err := j.CapAgentSessionsExcept(ctx, agentID, oldID, time.Now().Add(RotationOverlap)); err != nil {
					return false, fmt.Errorf("bootstrap: older tokens not shortened: %w", err)
				}
				return false, nil
			}
		}
	} else if err != nil {
		o.log().Warn("bootstrap: delivered token unreadable; rotating", slog.String("agent", o.Executor), slog.String("error", err.Error()))
	}

	row, err := j.PlanTokenRotation(ctx, agentID, oldID)
	if err != nil {
		return false, fmt.Errorf("bootstrap: %w", err)
	}
	if err := fault(FaultAfterPlan); err != nil {
		return false, err
	}
	return resumeRotation(ctx, o, j, row, ttl)
}

// resumeRotation drives an open rotation row as far as it can go now.
func resumeRotation(ctx context.Context, o Options, j RotationJournal, row *store.TokenRotation, ttl time.Duration) (bool, error) {
	published := false
	for {
		switch row.State {
		case store.RotationPlanned, store.RotationMinted:
			if err := mintAndPublish(ctx, o, j, row, ttl); err != nil {
				return false, err
			}
			published = true
		case store.RotationPublished:
			if row.PublishedAt != nil && o.now().Before(row.PublishedAt.Add(RevokeAfter)) {
				// Waiting out the overlap; meanwhile keep everything but
				// the new token capped to it.
				if _, err := j.CapAgentSessionsExcept(ctx, row.AgentID, row.NewSessionID, time.Now().Add(RotationOverlap)); err != nil {
					return published, fmt.Errorf("bootstrap: older tokens not shortened: %w", err)
				}
				return published, nil
			}
			if err := j.RevokeTokenRotationOld(ctx, row.ID); err != nil {
				return published, fmt.Errorf("bootstrap: revoking the old token: %w", err)
			}
			if err := fault(FaultAfterRevoke); err != nil {
				return published, err
			}
			if err := j.FinishTokenRotation(ctx, row.ID); err != nil {
				return published, fmt.Errorf("bootstrap: closing the rotation: %w", err)
			}
			row.State = store.RotationDone
			o.log().Info("bootstrap: old executor token revoked", slog.String("agent", o.Executor))
			return published, nil
		default:
			return published, fmt.Errorf("bootstrap: token rotation in unexpected state %q", row.State)
		}
	}
}

// mintAndPublish takes a planned or minted row to published.
func mintAndPublish(ctx context.Context, o Options, j RotationJournal, row *store.TokenRotation, ttl time.Duration) error {
	if row.State == store.RotationMinted {
		// Did an earlier attempt's write land? Then publish it as is.
		if tok, exp, err := o.Tokens.GetToken(ctx, o.Executor); err == nil && tok != "" && store.SessionID(tok) == row.NewSessionID {
			return publish(ctx, o, j, row, exp, ttl)
		}
	}

	raw, err := j.MintTokenRotation(ctx, row.ID, time.Now().Add(PendingExpiry))
	if err != nil {
		return fmt.Errorf("bootstrap: minting token: %w", err)
	}
	row.State, row.NewSessionID = store.RotationMinted, store.SessionID(raw)
	if err := fault(FaultAfterMint); err != nil {
		return err
	}

	expiresAt := o.now().Add(ttl).UTC().Truncate(time.Second)
	if err := o.Tokens.PutToken(ctx, o.Executor, raw, expiresAt); err != nil {
		// Outcome unknown (the write may have landed): the row stays
		// minted and the next run reads the sink back to decide.
		return fmt.Errorf("bootstrap: delivering token (outcome unknown; the next run reconciles): %w", err)
	}
	if err := fault(FaultAfterSecretWrite); err != nil {
		return err
	}

	// Read back before the new token gets its full TTL and before the old
	// one is cut to the overlap.
	got, gotExp, err := o.Tokens.GetToken(ctx, o.Executor)
	if err != nil {
		return fmt.Errorf("bootstrap: reading the delivered token back: %w", err)
	}
	if store.SessionID(got) != row.NewSessionID {
		return errors.New("bootstrap: the token read back from the sink is not the one just written")
	}
	return publish(ctx, o, j, row, gotExp, ttl)
}

// publish extends the confirmed new session to the expiry the sink holds
// (never past now+ttl), cuts the others to the overlap and records it.
func publish(ctx context.Context, o Options, j RotationJournal, row *store.TokenRotation, sinkExp time.Time, ttl time.Duration) error {
	full := o.now().Add(ttl).UTC().Truncate(time.Second)
	if !sinkExp.IsZero() && sinkExp.Before(full) {
		full = sinkExp.UTC()
	}
	at := o.now()
	if err := j.PublishTokenRotation(ctx, row.ID, full, time.Now().Add(RotationOverlap), at); err != nil {
		return fmt.Errorf("bootstrap: recording the publish: %w", err)
	}
	row.State, row.PublishedAt = store.RotationPublished, &at
	o.log().Info("bootstrap: executor token delivered", slog.String("agent", o.Executor), slog.Time("expires_at", full))
	return fault(FaultAfterPublished)
}
