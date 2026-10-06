// Fork change 17: crash safety of the journaled executor-token rotation,
// ADR 0010 proof case 10 (proxy tokens), one test per crash point, plus the
// review cases (unreadable sink with an extra session, read-back mismatch,
// the bootstrap lock across two store instances, and publish refusing a
// mismatched new session).
//
// Every test runs on Postgres (the deployment target) and on SQLite, through
// the shared harness in kmsaad_backends_test.go; CI sets
// AGENT_VAULT_TEST_REQUIRE_POSTGRES=1 so the Postgres runs cannot be skipped.
//
// The fault-injection API is in package bootstrap: FaultHook and the
// FaultAfter* points, PendingExpiry, RevokeAfter and RotationTickInterval.
// Journal: table token_rotations(id, agent_id, state, old_session_id,
// new_session_id, ...), states planned, minted, published, done.
package journalcontract_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/bootstrap"
	"github.com/Infisical/agent-vault/internal/store"
)

const doc = `{
  "vaults": ["example-integration"],
  "services": [
    {"vault":"example-integration","name":"notion-read","host":"api.notion.com","path":"/v1/pages/{id}","methods":["GET"],
     "auth_type":"bearer","credential_key":"NOTION_TOKEN","strict_deny":true}
  ],
  "agents": [
    {"name":"example-executor","instance_role":"no-access","vault_roles":{"example-integration":"proxy"},"expires_in":"720h"}
  ]
}`

const pendingBound = 15*time.Minute + time.Minute

var errCrash = errors.New("simulated crash")

type source struct{}

func (source) BootstrapDocument(context.Context) ([]byte, error) { return []byte(doc), nil }

// sink is an in-memory token secret with switchable failure modes.
type sink struct {
	mu           sync.Mutex
	tok          string
	exp          time.Time
	puts         int
	failPut      bool          // PutToken fails without landing
	unreadable   bool          // GetToken fails
	readOverride string        // when set, GetToken returns this token instead of the stored one
	gate         chan struct{} // when set, the next PutToken signals entered and waits for gate to close
	entered      chan struct{}
}

func (s *sink) PutToken(_ context.Context, _ string, tok string, exp time.Time) error {
	s.mu.Lock()
	if s.gate != nil {
		gate, entered := s.gate, s.entered
		s.gate, s.entered = nil, nil
		s.mu.Unlock()
		close(entered)
		<-gate
		s.mu.Lock()
	}
	defer s.mu.Unlock()
	if s.failPut {
		return errors.New("fake sink: PutSecretValue throttled")
	}
	s.tok, s.exp = tok, exp
	s.puts++
	return nil
}

func (s *sink) GetToken(context.Context, string) (string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unreadable {
		return "", time.Time{}, errors.New("fake sink: AccessDeniedException")
	}
	if s.readOverride != "" {
		return s.readOverride, s.exp, nil
	}
	if s.tok == "" {
		return "", time.Time{}, errors.New("not found")
	}
	return s.tok, s.exp, nil
}

func (s *sink) state() (string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tok, s.puts
}

func (s *sink) set(f func(s *sink)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

func hashTok(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

type env struct {
	tdb     testDB
	st      store.Store
	sk      *sink
	opts    bootstrap.Options
	nowMu   sync.Mutex
	now     time.Time
	agentID string
	oldTok  string
}

func (e *env) clock() time.Time {
	e.nowMu.Lock()
	defer e.nowMu.Unlock()
	return e.now
}

func (e *env) advance(d time.Duration) {
	e.nowMu.Lock()
	defer e.nowMu.Unlock()
	e.now = e.now.Add(d)
}

// setup applies the document (first mint) and moves the clock inside the
// rotation window of the delivered token.
func setup(t *testing.T, tdb testDB) *env {
	t.Helper()
	st := tdb.Open(t)
	e := &env{tdb: tdb, st: st, sk: &sink{}, now: time.Now()}
	e.opts = bootstrap.Options{Store: st, Source: source{}, Tokens: e.sk, Executor: "example-executor", Now: e.clock}
	bootstrap.FaultHook = nil
	t.Cleanup(func() { bootstrap.FaultHook = nil })
	if err := bootstrap.Apply(context.Background(), e.opts); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	a, err := st.GetAgentByName(context.Background(), "example-executor")
	if err != nil || a == nil {
		t.Fatalf("executor agent: %v", err)
	}
	e.agentID = a.ID
	e.oldTok, _ = e.sk.state()
	e.nowMu.Lock()
	e.now = e.sk.exp.Add(-bootstrap.RotateBefore + 24*time.Hour)
	e.nowMu.Unlock()
	return e
}

func parseTime(v any) time.Time {
	switch x := v.(type) {
	case time.Time:
		return x.UTC()
	case []byte:
		return parseTime(string(x))
	case string:
		for _, l := range []string{time.DateTime, time.RFC3339Nano, time.RFC3339} {
			if ts, err := time.Parse(l, x); err == nil {
				return ts.UTC()
			}
		}
	}
	return time.Time{}
}

func (e *env) sessions(t *testing.T) map[string]time.Time {
	t.Helper()
	rows, err := e.tdb.Raw.Query(e.tdb.rebind(`SELECT id, expires_at FROM sessions WHERE agent_id = ?`), e.agentID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id string
		var exp any
		if err := rows.Scan(&id, &exp); err != nil {
			t.Fatal(err)
		}
		out[id] = parseTime(exp) // zero = no expiry
	}
	return out
}

func validAt(exp, at time.Time) bool { return exp.IsZero() || exp.After(at) }

func (e *env) valid(t *testing.T, at time.Time) []string {
	t.Helper()
	var ids []string
	for id, exp := range e.sessions(t) {
		if validAt(exp, at) {
			ids = append(ids, id)
		}
	}
	return ids
}

// journal returns the agent's newest rotation row (state, new_session_id).
func (e *env) journal(t *testing.T) (string, string) {
	t.Helper()
	var st string
	var newID *string
	err := e.tdb.QueryRow(`SELECT state, new_session_id FROM token_rotations WHERE agent_id = ? ORDER BY id DESC LIMIT 1`, e.agentID).Scan(&st, &newID)
	if err != nil {
		t.Fatalf("reading token_rotations: %v", err)
	}
	if newID == nil {
		return st, ""
	}
	return st, *newID
}

func (e *env) journalState(t *testing.T) string {
	t.Helper()
	st, _ := e.journal(t)
	return st
}

// assertBound checks the two-valid limit.
func (e *env) assertBound(t *testing.T, label string) {
	t.Helper()
	if n := len(e.valid(t, time.Now())); n > 2 {
		t.Errorf("%s: %d executor sessions valid; at most two", label, n)
	}
}

// expireAll ends every session of the executor (as if all had run out).
func (e *env) expireAll(t *testing.T) {
	t.Helper()
	past := time.Now().Add(-time.Hour).UTC()
	var v any = past
	if e.tdb.Kind == "sqlite" {
		v = past.Format(time.DateTime)
	}
	e.tdb.Exec(t, `UPDATE sessions SET expires_at = ? WHERE agent_id = ?`, v, e.agentID)
}

func (e *env) crashAt(t *testing.T, point string) {
	t.Helper()
	bootstrap.FaultHook = func(p string) error {
		if p == point {
			return errCrash
		}
		return nil
	}
	_, err := bootstrap.RotateIfDue(context.Background(), e.opts)
	bootstrap.FaultHook = nil
	if !errors.Is(err, errCrash) {
		t.Fatalf("rotation did not stop at fault point %s (err %v)", point, err)
	}
}

func (e *env) tick(t *testing.T) {
	t.Helper()
	if _, err := bootstrap.RotateIfDue(context.Background(), e.opts); err != nil {
		t.Fatalf("tick: %v", err)
	}
}

// RotateSlack keeps the full-expiry check robust to the fixture clock.
func RotateSlack() time.Duration { return 2 * 24 * time.Hour }

func TestRotJournal_CrashAfterPlan_NextTickMintsOnce(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := setup(t, tdb)
		before := len(e.sessions(t))
		e.crashAt(t, bootstrap.FaultAfterPlan)
		if s := e.journalState(t); s != "planned" {
			t.Fatalf("journal state after crash = %q, want planned", s)
		}
		if len(e.sessions(t)) != before {
			t.Fatal("a session was minted before the crash point after-plan")
		}
		if exp := e.sessions(t)[hashTok(e.oldTok)]; !validAt(exp, time.Now().Add(29*24*time.Hour-RotateSlack())) {
			t.Errorf("old token lost its full expiry before anything was minted (expires %v)", exp)
		}
		_, puts := e.sk.state()
		e.tick(t)
		if got := len(e.sessions(t)); got != before+1 {
			t.Errorf("next tick left %d sessions, want exactly one new session (%d)", got, before+1)
		}
		if _, p := e.sk.state(); p != puts+1 {
			t.Errorf("next tick published %d tokens, want 1", p-puts)
		}
		e.assertBound(t, "after resume")
	})
}

func TestRotJournal_CrashAfterPlan_StartupResumes(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := setup(t, tdb)
		before := len(e.sessions(t))
		e.crashAt(t, bootstrap.FaultAfterPlan)
		if err := bootstrap.Apply(context.Background(), e.opts); err != nil {
			t.Fatalf("startup Apply: %v", err)
		}
		if got := len(e.sessions(t)); got != before+1 {
			t.Errorf("startup left %d sessions, want %d", got, before+1)
		}
		if s := e.journalState(t); s == "planned" {
			t.Error("startup did not resume the planned row")
		}
	})
}

func TestRotJournal_CrashAfterMint_NextTickReplacesUnpublished(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := setup(t, tdb)
		before := e.sessions(t)
		e.crashAt(t, bootstrap.FaultAfterMint)
		after := e.sessions(t)
		var pending string
		for id := range after {
			if _, ok := before[id]; !ok {
				pending = id
			}
		}
		if pending == "" {
			t.Fatal("no session minted before the crash point after-mint")
		}
		oldCut := after[hashTok(e.oldTok)]
		if !validAt(oldCut, time.Now()) || oldCut.After(time.Now().Add(pendingBound)) {
			t.Errorf("at mint the old session's expiry is %v; want it cut to within 15 minutes", oldCut)
		}
		e.assertBound(t, "after crash")
		e.tick(t)
		now := e.sessions(t)
		if validAt(now[pending], time.Now()) {
			t.Error("the unpublished session minted before the crash is still valid after the next tick")
		}
		if !now[hashTok(e.oldTok)].Equal(oldCut) {
			t.Errorf("old session's cut expiry changed from %v to %v; it must never be extended", oldCut, now[hashTok(e.oldTok)])
		}
		if tok, _ := e.sk.state(); tok == e.oldTok {
			t.Error("the next tick did not publish a replacement token")
		}
		e.assertBound(t, "after resume")
	})
}

func TestRotJournal_CrashAfterSecretWrite_NextTickPublishesWithoutMinting(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := setup(t, tdb)
		e.crashAt(t, bootstrap.FaultAfterSecretWrite)
		written, puts := e.sk.state()
		if written == e.oldTok {
			t.Fatal("precondition: the secret was not written before the crash point after-secret-write")
		}
		count := len(e.sessions(t))
		e.tick(t)
		if got := len(e.sessions(t)); got != count {
			t.Errorf("next tick minted (%d -> %d sessions); the written token must be published as is", count, got)
		}
		if tok, p := e.sk.state(); tok != written || p != puts {
			t.Errorf("next tick changed the delivered token or wrote again (puts %d -> %d)", puts, p)
		}
		if exp := e.sessions(t)[hashTok(written)]; !validAt(exp, time.Now().Add(29*24*time.Hour-RotateSlack())) {
			t.Errorf("published token was not extended to its full TTL (expires %v)", exp)
		}
		if s := e.journalState(t); s != "published" && s != "done" {
			t.Errorf("journal state %q after resume, want published", s)
		}
	})
}

func TestRotJournal_CrashAfterPublished_RevokesOldAfterTenMinutes(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := setup(t, tdb)
		e.crashAt(t, bootstrap.FaultAfterPublished)
		old := hashTok(e.oldTok)
		e.advance(5 * time.Minute)
		e.tick(t)
		if !validAt(e.sessions(t)[old], time.Now()) {
			t.Error("old session revoked before ten minutes had passed since publishing")
		}
		e.advance(6 * time.Minute)
		e.tick(t)
		if exp, ok := e.sessions(t)[old]; ok && validAt(exp, time.Now()) {
			t.Error("old session still valid more than ten minutes after publishing")
		}
		if s := e.journalState(t); s != "done" {
			t.Errorf("journal state %q, want done", s)
		}
		e.assertBound(t, "after revoke")
	})
}

func TestRotJournal_CrashAfterRevoke_RepeatIsNoOpAndCloses(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := setup(t, tdb)
		// Reach the revoke step: publish, then let ten minutes pass and
		// crash after the revoke.
		e.crashAt(t, bootstrap.FaultAfterPublished)
		e.advance(bootstrap.RevokeAfter + time.Minute)
		e.crashAt(t, bootstrap.FaultAfterRevoke)
		if s := e.journalState(t); s == "done" {
			t.Fatal("precondition: row already done at the crash point after-revoke")
		}
		e.tick(t)
		if s := e.journalState(t); s != "done" {
			t.Errorf("journal state %q after the repeated revoke, want done", s)
		}
		if exp, ok := e.sessions(t)[hashTok(e.oldTok)]; ok && validAt(exp, time.Now()) {
			t.Error("old session valid after the revoke")
		}
	})
}

func TestRotJournal_NeverReturnsAfterMint_BothExpireWithin15Minutes(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := setup(t, tdb)
		before := e.sessions(t)
		mintedAt := time.Now()
		e.crashAt(t, bootstrap.FaultAfterMint)
		limit := mintedAt.Add(pendingBound)
		for id, exp := range e.sessions(t) {
			if _, existed := before[id]; existed && id != hashTok(e.oldTok) {
				continue
			}
			if !validAt(exp, time.Now()) {
				continue
			}
			if exp.IsZero() || exp.After(limit) {
				t.Errorf("session %s… stays valid until %v with no tick ever running; want at most 15 minutes after the mint", id[:8], exp)
			}
		}
	})
}

func TestRotJournal_PutFailingSeveralTicks_StaysMintedWithinBound(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := setup(t, tdb)
		e.sk.set(func(s *sink) { s.failPut = true })
		seen := map[string]bool{}
		for id := range e.sessions(t) {
			seen[id] = true
		}
		var lastPending string
		for i := 1; i <= 3; i++ {
			_, _ = bootstrap.RotateIfDue(context.Background(), e.opts)
			if s := e.journalState(t); s != "minted" {
				t.Errorf("tick %d: journal state %q, want minted", i, s)
			}
			e.assertBound(t, "failing tick")
			ss := e.sessions(t)
			var pending string
			for id := range ss {
				if !seen[id] {
					pending = id
					seen[id] = true
				}
			}
			if pending == "" {
				t.Errorf("tick %d did not replace the unpublished session", i)
			}
			if lastPending != "" && validAt(ss[lastPending], time.Now()) {
				t.Errorf("tick %d left the previous unpublished session valid", i)
			}
			lastPending = pending
		}
	})
}

// secondOptions returns Options for a second vault task. On Postgres it
// opens a separate store (its own connection pool), so the two tasks
// contend on pg_try_advisory_lock exactly as two ECS tasks would. SQLite
// deployments are single-process and LockVault is an in-process mutex per
// store, so there the second task shares the store instance.
func (e *env) secondOptions(t *testing.T) bootstrap.Options {
	t.Helper()
	o := e.opts
	if e.tdb.Kind == "postgres" {
		o.Store = e.tdb.Open(t)
	}
	return o
}

func TestRotJournal_TwoTasksTickAtOnce_OneMint(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := setup(t, tdb)
		other := e.secondOptions(t)
		before := len(e.sessions(t))
		_, puts := e.sk.state()
		var wg sync.WaitGroup
		for _, o := range []bootstrap.Options{e.opts, other} {
			wg.Add(1)
			go func(o bootstrap.Options) {
				defer wg.Done()
				_, _ = bootstrap.RotateIfDue(context.Background(), o)
			}(o)
		}
		wg.Wait()
		if got := len(e.sessions(t)); got != before+1 {
			t.Errorf("two concurrent ticks left %d sessions, want exactly one mint (%d)", got, before+1)
		}
		if _, p := e.sk.state(); p != puts+1 {
			t.Errorf("two concurrent ticks published %d tokens, want 1", p-puts)
		}
	})
}

// Deterministic form of the lock check: task A is held inside its rotation
// (in PutToken, after minting, holding the bootstrap lock) while task B
// ticks. B must not mint while A holds the lock. A no-op LockVault lets B
// resume A's open row, read the sink (still the old token), and mint a
// second session.
func TestRotJournal_TickWaitsForTheBootstrapLock(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := setup(t, tdb)
		other := e.secondOptions(t)
		before := len(e.sessions(t))
		gate, entered := make(chan struct{}), make(chan struct{})
		e.sk.set(func(s *sink) { s.gate, s.entered = gate, entered })

		aDone := make(chan error, 1)
		go func() {
			_, err := bootstrap.RotateIfDue(context.Background(), e.opts)
			aDone <- err
		}()
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			close(gate)
			t.Fatal("task A never reached PutToken")
		}

		ctxB, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		bDone := make(chan error, 1)
		go func() {
			_, err := bootstrap.RotateIfDue(ctxB, other)
			bDone <- err
		}()
		bFinished := false
		select {
		case <-bDone:
			bFinished = true
		case <-time.After(3 * time.Second):
		}
		if got := len(e.sessions(t)); got != before+1 {
			t.Errorf("while task A held the bootstrap lock inside its rotation, task B minted too (%d sessions, want %d)", got, before+1)
		}

		close(gate)
		if err := <-aDone; err != nil {
			t.Fatalf("task A: %v", err)
		}
		if !bFinished {
			<-bDone
		}
		if got := len(e.sessions(t)); got != before+1 {
			t.Errorf("after both tasks finished there are %d sessions, want exactly one mint (%d)", got, before+1)
		}
		e.assertBound(t, "after both tasks")
	})
}

// Review gap 1: the sink is unreadable, every put fails, and a live extra
// session exists beside the delivered one. With the sink unreadable the plan
// uses the agent's newest live session as the old session, so the mint
// expires every other one: at most two stay valid after every tick.
func TestRotJournal_UnreadableSinkWithExtraSession_AtMostTwoValid(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := setup(t, tdb)
		full := time.Now().Add(720 * time.Hour)
		if _, err := e.st.CreateAgentToken(context.Background(), e.agentID, &full); err != nil {
			t.Fatal(err)
		}
		if n := len(e.valid(t, time.Now())); n != 2 {
			t.Fatalf("precondition: want the delivered and one extra live session, have %d valid", n)
		}
		e.sk.set(func(s *sink) { s.unreadable, s.failPut = true, true })
		for i := 1; i <= 3; i++ {
			_, _ = bootstrap.RotateIfDue(context.Background(), e.opts)
			if n := len(e.valid(t, time.Now())); n > 2 {
				t.Errorf("tick %d with an unreadable sink: %d executor sessions valid; at most two", i, n)
			}
		}
	})
}

// Review gap 1, second form: no live session exists when the sink becomes
// unreadable, so the row has no old session and only the attempt's own
// unpublished session may be valid. Each retry must expire the previous
// attempt's session (the prevID expiry in MintTokenRotation); without it
// they accumulate.
func TestRotJournal_UnreadableSinkNoLiveSession_PreviousAttemptExpired(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := setup(t, tdb)
		e.expireAll(t)
		e.sk.set(func(s *sink) { s.unreadable, s.failPut = true, true })
		for i := 1; i <= 3; i++ {
			_, _ = bootstrap.RotateIfDue(context.Background(), e.opts)
			if n := len(e.valid(t, time.Now())); n > 1 {
				t.Errorf("tick %d with no old session: %d executor sessions valid; only the current unpublished attempt may be", i, n)
			}
		}
	})
}

// Review gap 2: the sink's read-back returns a different token after a
// successful write. The row must stay minted, the new session must stay
// within its 15-minute pending expiry, the old session must not be revoked
// or extended, and the next tick must mint again.
func TestRotJournal_ReadBackMismatch_StaysMintedAndRemints(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := setup(t, tdb)
		old := hashTok(e.oldTok)
		e.sk.set(func(s *sink) { s.readOverride = e.oldTok }) // stale read: the write lands, the read-back shows the old token
		_, puts := e.sk.state()

		_, _ = bootstrap.RotateIfDue(context.Background(), e.opts)
		if _, p := e.sk.state(); p != puts+1 {
			t.Fatalf("precondition: the rotation did not write the new token (puts %d -> %d)", puts, p)
		}
		state, newID := e.journal(t)
		if state != "minted" {
			t.Errorf("journal state %q after a mismatched read-back, want minted", state)
		}
		ss := e.sessions(t)
		if exp, ok := ss[newID]; !ok || !validAt(exp, time.Now()) || exp.IsZero() || exp.After(time.Now().Add(pendingBound)) {
			t.Errorf("new session expires at %v after a mismatched read-back; want it pending (within 15 minutes)", ss[newID])
		}
		oldExp, ok := ss[old]
		if !ok || !validAt(oldExp, time.Now()) {
			t.Error("old session was revoked although the new token was never confirmed")
		}
		if oldExp.IsZero() || oldExp.After(time.Now().Add(pendingBound)) {
			t.Errorf("old session expires at %v; it must keep the cut it got at mint, never extended", oldExp)
		}

		_, _ = bootstrap.RotateIfDue(context.Background(), e.opts)
		state2, newID2 := e.journal(t)
		if newID2 == "" || newID2 == newID {
			t.Errorf("next tick did not mint again after the mismatched read-back (state %q)", state2)
		}
		if validAt(e.sessions(t)[newID], time.Now()) {
			t.Error("the unconfirmed session from the mismatched attempt is still valid after the re-mint")
		}
		e.assertBound(t, "after re-mint")
	})
}

// journalV2 is the store surface the publish check needs: PublishTokenRotation
// takes the new session ID the caller confirmed and refuses a row that names
// another one.
type journalV2 interface {
	PlanTokenRotation(ctx context.Context, agentID, oldSessionID string) (*store.TokenRotation, error)
	MintTokenRotation(ctx context.Context, rotationID int64, pendingUntil, oldUntil time.Time) (string, error)
	PublishTokenRotation(ctx context.Context, rotationID int64, expectedNewSessionID string, fullExpiry, overlapUntil, publishedAt time.Time) error
}

// Review gap 3: PublishTokenRotation refuses when the caller's confirmed
// new session ID does not match the row (another runner re-minted in
// between), and leaves the row and sessions unchanged.
func TestRotJournal_PublishRefusesMismatchedNewSessionID(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := setup(t, tdb)
		j, ok := e.st.(journalV2)
		if !ok {
			t.Fatal("store has no PublishTokenRotation(ctx, rotationID, expectedNewSessionID, fullExpiry, overlapUntil, publishedAt)")
		}
		ctx := context.Background()
		row, err := j.PlanTokenRotation(ctx, e.agentID, hashTok(e.oldTok))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := j.MintTokenRotation(ctx, row.ID, time.Now().Add(bootstrap.PendingExpiry), time.Now().Add(bootstrap.RotationOverlap))
		if err != nil {
			t.Fatal(err)
		}
		full := time.Now().Add(720 * time.Hour)
		err = j.PublishTokenRotation(ctx, row.ID, hashTok("some-other-token"), full, time.Now().Add(bootstrap.RotationOverlap), time.Now())
		if !errors.Is(err, store.ErrRotationState) {
			t.Errorf("publish with a mismatched new session ID returned %v, want ErrRotationState", err)
		}
		if s := e.journalState(t); s != "minted" {
			t.Errorf("journal state %q after a refused publish, want minted", s)
		}
		if exp := e.sessions(t)[hashTok(raw)]; exp.IsZero() || exp.After(time.Now().Add(pendingBound)) {
			t.Errorf("the minted session was extended (%v) by a refused publish", exp)
		}
		if err := j.PublishTokenRotation(ctx, row.ID, hashTok(raw), full, time.Now().Add(bootstrap.RotationOverlap), time.Now()); err != nil {
			t.Errorf("control: publish with the matching new session ID: %v", err)
		}
	})
}

func TestRotJournal_DefaultTickIsOneMinute(t *testing.T) {
	if bootstrap.RotationTickInterval != time.Minute {
		t.Errorf("RotationTickInterval = %v, want one minute", bootstrap.RotationTickInterval)
	}
	if bootstrap.PendingExpiry != 15*time.Minute {
		t.Errorf("PendingExpiry = %v, want 15 minutes", bootstrap.PendingExpiry)
	}
	if bootstrap.RevokeAfter != 10*time.Minute {
		t.Errorf("RevokeAfter = %v, want 10 minutes", bootstrap.RevokeAfter)
	}
}
