// Fork change 17 (journaled executor-token rotation, ADR 0010 part 8 and
// fork change 9). The crash-point cases, which use the FaultHook
// fault-injection API, run on Postgres and SQLite in ./journalcontract.
//
// Contract pinned here:
//   - table token_rotations(agent_id, state, new_session_id, ...) with states
//     planned, minted, published, done; new_session_id is the new session's
//     stored ID (sha256 hex of the raw token, as sessions.id);
//   - a new session is minted with a pending expiry of at most 15 minutes and
//     extended to its full TTL only after the token is written to the sink
//     AND read back with a matching digest;
//   - at most two sessions of the executor are valid at any time;
//   - cmd's default rotation tick is bootstrap.RotationTickInterval (one
//     minute), not an hour.
package bootstrap

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

const pendingBound = 15*time.Minute + time.Minute // 15-minute pending expiry plus clock slack

type sessRow struct {
	id  string
	exp time.Time // zero = no expiry
}

func scanTime(v any) (time.Time, bool) {
	switch x := v.(type) {
	case time.Time:
		return x.UTC(), true
	case string:
		for _, layout := range []string{time.DateTime, time.RFC3339Nano, time.RFC3339} {
			if t, err := time.Parse(layout, x); err == nil {
				return t.UTC(), true
			}
		}
	case []byte:
		return scanTime(string(x))
	}
	return time.Time{}, false
}

// agentSessions lists the executor's sessions straight from the database.
func agentSessions(t *testing.T, tdb testDB, agentID string) []sessRow {
	t.Helper()
	rows, err := tdb.Raw.Query(tdb.rebind(`SELECT id, expires_at FROM sessions WHERE agent_id = ?`), agentID)
	if err != nil {
		t.Fatalf("listing sessions: %v", err)
	}
	defer rows.Close()
	var out []sessRow
	for rows.Next() {
		var id string
		var exp any
		if err := rows.Scan(&id, &exp); err != nil {
			t.Fatal(err)
		}
		r := sessRow{id: id}
		if exp != nil {
			ts, ok := scanTime(exp)
			if !ok {
				t.Fatalf("unparseable expires_at %v", exp)
			}
			r.exp = ts
		}
		out = append(out, r)
	}
	return out
}

// countValid counts sessions valid beyond after (no expiry counts as valid).
func countValid(rows []sessRow, after time.Time) int {
	n := 0
	for _, r := range rows {
		if r.exp.IsZero() || r.exp.After(after) {
			n++
		}
	}
	return n
}

func sessionByToken(rows []sessRow, raw string) (sessRow, bool) {
	h := tokenHash(raw)
	for _, r := range rows {
		if r.id == h {
			return r, true
		}
	}
	return sessRow{}, false
}

// journalRows returns (state, new_session_id) for the agent's rotation rows.
func journalRows(tdb testDB, agentID string) ([][2]string, error) {
	rows, err := tdb.Raw.Query(tdb.rebind(`SELECT state, COALESCE(new_session_id, '') FROM token_rotations WHERE agent_id = ?`), agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var st, ns string
		if err := rows.Scan(&st, &ns); err != nil {
			return nil, err
		}
		out = append(out, [2]string{st, ns})
	}
	return out, rows.Err()
}

// observingSink wraps the fixture sink and runs a hook on every call.
type observingSink struct {
	*fakeTokenSink
	onPut func(token string)
	onGet func(token string)
}

func (s *observingSink) PutToken(ctx context.Context, agent, tok string, exp time.Time) error {
	if s.onPut != nil {
		s.onPut(tok)
	}
	return s.fakeTokenSink.PutToken(ctx, agent, tok, exp)
}

func (s *observingSink) GetToken(ctx context.Context, agent string) (string, time.Time, error) {
	tok, exp, err := s.fakeTokenSink.GetToken(ctx, agent)
	if err == nil && s.onGet != nil {
		s.onGet(tok)
	}
	return tok, exp, err
}

type journalFixture struct {
	*fixture
	tdb     testDB
	sink    *observingSink
	agentID string
}

// newJournalFixture applies the document once (first mint) with an
// observing sink and returns the fixture.
func newJournalFixture(t *testing.T) *journalFixture {
	t.Helper()
	tdb := newSQLiteTestDB(t)
	fx := newFixture(t, tdb.Open(t), docJSON)
	jf := &journalFixture{fixture: fx, tdb: tdb, sink: &observingSink{fakeTokenSink: fx.tokens}}
	fx.opts.Tokens = jf.sink
	return jf
}

func (jf *journalFixture) applyFirst(t *testing.T) {
	t.Helper()
	if err := Apply(context.Background(), jf.opts); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	a, err := jf.st.GetAgentByName(context.Background(), "example-executor")
	if err != nil || a == nil {
		t.Fatalf("executor agent: %v", err)
	}
	jf.agentID = a.ID
}

// makeDue moves the fixture clock inside RotateBefore of the delivered
// token's expiry.
func (jf *journalFixture) makeDue(t *testing.T) {
	t.Helper()
	_, exp, err := jf.sink.fakeTokenSink.GetToken(context.Background(), "example-executor")
	if err != nil {
		t.Fatal(err)
	}
	jf.now = exp.Add(-RotateBefore + 24*time.Hour)
}

// 1. A journal row naming the new session exists before every mint is
// published (it is written before the mint, in state planned, and is at
// minted when the token reaches the sink).
func TestRotJournal_JournalRowBeforeEveryMint(t *testing.T) {
	jf := newJournalFixture(t)
	var failures []string
	jf.sink.onPut = func(tok string) {
		a, _ := jf.st.GetAgentByName(context.Background(), "example-executor")
		if a == nil {
			failures = append(failures, "executor agent missing at mint")
			return
		}
		rows, err := journalRows(jf.tdb, a.ID)
		if err != nil {
			failures = append(failures, "no token_rotations journal: "+err.Error())
			return
		}
		for _, r := range rows {
			if r[1] == tokenHash(tok) && r[0] == "minted" {
				return
			}
		}
		failures = append(failures, "no minted journal row names the session being published")
	}
	jf.applyFirst(t)
	jf.makeDue(t)
	if _, err := RotateIfDue(context.Background(), jf.opts); err != nil {
		t.Fatalf("RotateIfDue: %v", err)
	}
	if jf.tokens.count() < 2 {
		t.Fatalf("precondition: expected two mints (first boot and rotation), got %d", jf.tokens.count())
	}
	for _, f := range failures {
		t.Error(f)
	}
}

// 2. A new session starts with a 15-minute pending expiry and is extended
// to its full TTL only after the publish is confirmed.
func TestRotJournal_NewSessionPendingUntilPublishConfirmed(t *testing.T) {
	jf := newJournalFixture(t)
	var atPut []string
	jf.sink.onPut = func(tok string) {
		a, _ := jf.st.GetAgentByName(context.Background(), "example-executor")
		if a == nil {
			return
		}
		s, ok := sessionByToken(agentSessions(t, jf.tdb, a.ID), tok)
		if !ok {
			atPut = append(atPut, "session for the token being published not found")
			return
		}
		if s.exp.IsZero() || s.exp.After(time.Now().Add(pendingBound)) {
			atPut = append(atPut, "session expires at "+s.exp.String()+" while its publish is unconfirmed; want a pending expiry within 15 minutes")
		}
	}
	jf.applyFirst(t)
	for _, f := range atPut {
		t.Error(f)
	}
	tok, _, _ := jf.sink.fakeTokenSink.GetToken(context.Background(), "example-executor")
	s, ok := sessionByToken(agentSessions(t, jf.tdb, jf.agentID), tok)
	if !ok || s.exp.Before(time.Now().Add(29*24*time.Hour)) {
		t.Errorf("after a confirmed publish the delivered session expires at %v; want its full TTL", s.exp)
	}
}

// 3. The secret is read back, and the digest matches, before the old token
// is revoked and before the new one gets its full TTL.
func TestRotJournal_ReadBackBeforeRevokeAndExtend(t *testing.T) {
	jf := newJournalFixture(t)
	jf.applyFirst(t)
	oldTok, _, _ := jf.sink.fakeTokenSink.GetToken(context.Background(), "example-executor")
	jf.makeDue(t)

	var newTok string
	readBack := false
	var problems []string
	jf.sink.onPut = func(tok string) { newTok = tok }
	jf.sink.onGet = func(tok string) {
		if newTok == "" || tok != newTok {
			return
		}
		readBack = true
		rows := agentSessions(t, jf.tdb, jf.agentID)
		if o, ok := sessionByToken(rows, oldTok); !ok || (!o.exp.IsZero() && !o.exp.After(time.Now())) {
			problems = append(problems, "old session was revoked before the new token was read back")
		}
		if n, ok := sessionByToken(rows, tok); ok && (n.exp.IsZero() || n.exp.After(time.Now().Add(pendingBound))) {
			problems = append(problems, "new session got its full TTL before the read-back confirmed the publish")
		}
	}
	if _, err := RotateIfDue(context.Background(), jf.opts); err != nil {
		t.Fatalf("RotateIfDue: %v", err)
	}
	if newTok == "" {
		t.Fatal("precondition: rotation did not mint")
	}
	if !readBack {
		t.Error("the rotation that published the new token never read the secret back to confirm it")
	}
	for _, p := range problems {
		t.Error(p)
	}
	if _, err := brokercore.NewStoreSessionResolver(jf.st).ResolveForProxy(context.Background(), newTok, "example-integration"); err != nil {
		t.Errorf("published token does not authenticate: %v", err)
	}
}

// failingPutSink always fails PutToken without landing it and always
// returns the original token, which is inside RotateBefore.
type failingPutSink struct {
	tok string
	exp time.Time
}

func (s *failingPutSink) PutToken(context.Context, string, string, time.Time) error {
	return errors.New("fake sink: PutSecretValue throttled")
}

func (s *failingPutSink) GetToken(context.Context, string) (string, time.Time, error) {
	return s.tok, s.exp, nil
}

// 5. The two-session bound: three failing rotations leave at most two
// sessions valid at all, and at most two valid beyond now+15m.
func TestRotJournal_TwoSessionBoundUnderFailingSink(t *testing.T) {
	jf := newJournalFixture(t)
	jf.applyFirst(t)
	tok, exp, err := jf.sink.fakeTokenSink.GetToken(context.Background(), "example-executor")
	if err != nil {
		t.Fatal(err)
	}
	jf.makeDue(t)
	jf.opts.Tokens = &failingPutSink{tok: tok, exp: exp}

	for i := 1; i <= 3; i++ {
		_, _ = RotateIfDue(context.Background(), jf.opts) // expected to report the sink failure
		rows := agentSessions(t, jf.tdb, jf.agentID)
		if n := countValid(rows, time.Now().Add(15*time.Minute)); n > 2 {
			t.Errorf("after failing rotation %d, %d sessions are valid beyond now+15m; at most two", i, n)
		}
		if n := countValid(rows, time.Now()); n > 2 {
			t.Errorf("after failing rotation %d, %d sessions are valid; at most two (the old one and one unpublished replacement)", i, n)
		}
	}
}

// 4 (sink side) is in internal/bootstrap/awssinks; 6 is in ./journalcontract.

// 7. cmd's default rotation tick is bootstrap.RotationTickInterval (one
// minute), not a literal hour. Checked on the source so it runs today.
func TestRotJournal_DefaultTickIsRotationTickInterval(t *testing.T) {
	path := filepath.Join("..", "..", "cmd", "bootstrap_aws.go")
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		id, ok := as.Lhs[0].(*ast.Ident)
		if !ok || id.Name != "period" || as.Tok != token.DEFINE {
			return true
		}
		found = true
		sel, ok := as.Rhs[0].(*ast.SelectorExpr)
		x, okx := (*ast.Ident)(nil), false
		if ok {
			x, okx = sel.X.(*ast.Ident)
		}
		if !ok || !okx || x.Name != "bootstrap" || sel.Sel.Name != "RotationTickInterval" {
			t.Errorf("cmd's default rotation period is %s; want bootstrap.RotationTickInterval (one minute)", exprString(as.Rhs[0]))
		}
		return true
	})
	if !found {
		t.Error("no `period :=` default found in cmd/bootstrap_aws.go; update this test with the new location")
	}
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.Ident:
		return v.Name
	case *ast.BasicLit:
		return v.Value
	}
	return strings.TrimSpace("<expr>")
}
