// Fork change 17: crash safety of the journaled executor-token rotation,
// ADR 0010 proof case 10 (proxy tokens), one test per crash point.
//
// This directory holds only tests. They use the fault-injection API below,
// so until it exists the package fails to compile ("undefined:
// bootstrap.FaultHook" ...) without stopping the other bootstrap tests.
//
// Intended API in package bootstrap:
//
//	// FaultHook, when non-nil, is called at each named step of a rotation.
//	// A non-nil return aborts the run at that point exactly as a crash
//	// would: nothing after it runs, and the run returns an error wrapping it.
//	var FaultHook func(point string) error
//	const (
//	    FaultAfterPlan        = "after-plan"         // planned row committed, nothing minted
//	    FaultAfterMint        = "after-mint"         // minted row committed, secret not written
//	    FaultAfterSecretWrite = "after-secret-write" // PutSecretValue done, row not yet published
//	    FaultAfterPublished   = "after-published"    // published row committed, old not revoked
//	    FaultAfterRevoke      = "after-revoke"       // old revoked, row not yet done
//	)
//	const PendingExpiry = 15 * time.Minute       // new session's expiry until publish is confirmed; old session's cut
//	var RevokeAfter = 10 * time.Minute           // publish -> revoke delay, measured on Options.Now
//	var RotationTickInterval = time.Minute       // default tick
//
// Journal: table token_rotations(agent_id, state, new_session_id, ...),
// states planned, minted, published, done, at most one open row per agent.
package journalcontract_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
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

type sink struct {
	mu      sync.Mutex
	tok     string
	exp     time.Time
	puts    int
	failPut bool
}

func (s *sink) PutToken(_ context.Context, _ string, tok string, exp time.Time) error {
	s.mu.Lock()
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

func hashTok(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

type env struct {
	st      store.Store
	raw     *sql.DB
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
func setup(t *testing.T) *env {
	t.Helper()
	path := filepath.Join(t.TempDir(), "av.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	raw, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	e := &env{st: st, raw: raw, sk: &sink{}, now: time.Now()}
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
	rows, err := e.raw.Query(`SELECT id, expires_at FROM sessions WHERE agent_id = ?`, e.agentID)
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

func (e *env) journalState(t *testing.T) string {
	t.Helper()
	var st string
	err := e.raw.QueryRow(`SELECT state FROM token_rotations WHERE agent_id = ? ORDER BY rowid DESC LIMIT 1`, e.agentID).Scan(&st)
	if err != nil {
		t.Fatalf("reading token_rotations: %v", err)
	}
	return st
}

// assertBound checks the two-valid limit and that nothing but the delivered
// token outlives the 15-minute window while a rotation is open.
func (e *env) assertBound(t *testing.T, label string) {
	t.Helper()
	if n := len(e.valid(t, time.Now())); n > 2 {
		t.Errorf("%s: %d executor sessions valid; at most two", label, n)
	}
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

func TestRotJournal_CrashAfterPlan_NextTickMintsOnce(t *testing.T) {
	e := setup(t)
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
}

// RotateSlack keeps the full-expiry check robust to the fixture clock.
func RotateSlack() time.Duration { return 2 * 24 * time.Hour }

func TestRotJournal_CrashAfterPlan_StartupResumes(t *testing.T) {
	e := setup(t)
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
}

func TestRotJournal_CrashAfterMint_NextTickReplacesUnpublished(t *testing.T) {
	e := setup(t)
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
}

func TestRotJournal_CrashAfterSecretWrite_NextTickPublishesWithoutMinting(t *testing.T) {
	e := setup(t)
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
}

func TestRotJournal_CrashAfterPublished_RevokesOldAfterTenMinutes(t *testing.T) {
	e := setup(t)
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
}

func TestRotJournal_CrashAfterRevoke_RepeatIsNoOpAndCloses(t *testing.T) {
	e := setup(t)
	bootstrap.FaultHook = nil
	// Reach the revoke step: publish, then let ten minutes pass and crash
	// after the revoke.
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
}

func TestRotJournal_NeverReturnsAfterMint_BothExpireWithin15Minutes(t *testing.T) {
	e := setup(t)
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
}

func TestRotJournal_PutFailingSeveralTicks_StaysMintedWithinBound(t *testing.T) {
	e := setup(t)
	e.sk.mu.Lock()
	e.sk.failPut = true
	e.sk.mu.Unlock()
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
}

func TestRotJournal_TwoTasksTickAtOnce_OneMint(t *testing.T) {
	e := setup(t)
	before := len(e.sessions(t))
	_, puts := e.sk.state()
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = bootstrap.RotateIfDue(context.Background(), e.opts)
		}()
	}
	wg.Wait()
	if got := len(e.sessions(t)); got != before+1 {
		t.Errorf("two concurrent ticks left %d sessions, want exactly one mint (%d)", got, before+1)
	}
	if _, p := e.sk.state(); p != puts+1 {
		t.Errorf("two concurrent ticks published %d tokens, want 1", p-puts)
	}
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
