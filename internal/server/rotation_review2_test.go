// Provider-key rotation, review follow-up (fork change 17). These add to
// provider_rotation_test.go and reuse its rig (newRotEnv, keyedNotion).
//
// Failure modes, each with the test that catches it:
//
//  1. Pasting the value that is already stored opens a rotation whose
//     "superseded" key is the live key: it never answers 401, so the key is
//     suspended after 24 hours and every later paste is refused.
//     TestRotationReview2_SameValueRepasteOpensNoRotation
//  2. The same-value comparison is not constant-time.
//     TestRotationReview2_SameValueComparisonIsConstantTime
//  3. A pinned key whose identity record was lost (a crash before
//     SetCredentialIdentity) is never probed again, because passes only walk
//     open rotations, so it is refused forever.
//     TestRotationReview2_LostIdentityAfterFirstPasteRecordedOnTick
//  4. A pass closes a rotation before it has recorded the current value's
//     identity, and a failed recording is never retried.
//     TestRotationReview2_PassRecordsIdentityBeforeClosing
//  5. A delete removes a value the provider still accepts without
//     journaling it, so delete-then-paste replaces a key with no rotation;
//     or a delete during an open rotation drops a value never proven dead.
//     TestRotationReview2_DeleteDuringRotationRefused,
//     TestRotationReview2_DeleteJournalsTheRemovedValue
//  6. Proposal approval replaces or deletes a value outside the journal.
//     TestRotationReview2_ProposalApprovalGoesThroughJournal
//  7. Two concurrent first pastes both answer 200 and one silently
//     overwrites the other with no journal row.
//     TestRotationReview2_ConcurrentFirstPastesNoSilentReplace
//  8. migrate-db drops credential_rotations and token_rotations, so a
//     suspended key is served again on the new database.
//     TestRotationReview2_MigrationKeepsSuspendedRotation
//  9. A paste whose identity probe fails is accepted.
//     TestRotationReview2_PasteRefusedWhenProbeErrors
//  10. The grace window is not 24 hours.
//     TestRotationReview2_SuspensionBoundaryAt24Hours
//  11. A pinned or rotating key used through a substitution escapes the pin
//     check or the suspension.
//     TestRotationReview2_SubstitutionKeyPinChecked,
//     TestRotationReview2_SubstitutionKeySuspended
//
// No path may leave more than two live values of a key; every test that
// changes a key checks it.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
)

// journalRow is one credential_rotations row; new_version may be NULL for
// a journaled delete.
type journalRow struct {
	oldVersion      int64
	oldCT, oldNonce []byte
	closed          bool
}

func (r *rotEnv) journal() []journalRow {
	r.t.Helper()
	return journalOf(r.t, r.tdb, r.vaultID)
}

func journalOf(t *testing.T, tdb testDB, vaultID string) []journalRow {
	t.Helper()
	rs, err := tdb.Raw.Query(tdb.rebind(`SELECT old_version, old_ciphertext, old_nonce, closed_at
		FROM credential_rotations WHERE vault_id = ? AND credential_key = ? ORDER BY id`), vaultID, rotKey)
	if err != nil {
		t.Fatalf("reading credential_rotations: %v", err)
	}
	defer func() { _ = rs.Close() }()
	var out []journalRow
	for rs.Next() {
		var row journalRow
		var closedAt any
		if err := rs.Scan(&row.oldVersion, &row.oldCT, &row.oldNonce, &closedAt); err != nil {
			t.Fatal(err)
		}
		row.closed = closedAt != nil
		out = append(out, row)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// journaledValues returns the plaintext of every superseded value still
// held in an open row.
func (r *rotEnv) journaledValues() []string {
	r.t.Helper()
	var out []string
	for _, row := range r.journal() {
		if row.closed || len(row.oldCT) == 0 {
			continue
		}
		pt, err := store.CredentialValueAAD(r.vaultID, rotKey, uint64(row.oldVersion)).Open(row.oldCT, row.oldNonce, r.encKey)
		if err != nil {
			r.t.Fatalf("open journal row does not open under its own version's AAD (version %d): %v", row.oldVersion, err)
		}
		out = append(out, string(pt))
	}
	return out
}

// held counts every value of the key the vault holds: the current row (if
// any) and every superseded ciphertext not destroyed.
func (r *rotEnv) held() int {
	r.t.Helper()
	n := 0
	if c, err := r.st.GetCredential(context.Background(), r.vaultID, rotKey); err == nil && c != nil && len(c.Ciphertext) > 0 {
		n++
	}
	for _, row := range r.journal() {
		if len(row.oldCT) > 0 {
			n++
		}
	}
	return n
}

func (r *rotEnv) checkHeld(stage string) {
	r.t.Helper()
	if n := r.held(); n > 2 {
		r.t.Errorf("%s: %d values of the key held; at most 2", stage, n)
	}
}

// currentValue returns the stored value, or "" when the key has no row.
func (r *rotEnv) currentValue() string {
	r.t.Helper()
	c, err := r.st.GetCredential(context.Background(), r.vaultID, rotKey)
	if err != nil || c == nil {
		return ""
	}
	pt, err := store.CredentialValueAAD(r.vaultID, rotKey, c.Version).Open(c.Ciphertext, c.Nonce, r.encKey)
	if err != nil {
		r.t.Fatalf("current value does not open at its version %d: %v", c.Version, err)
	}
	return string(pt)
}

func (r *rotEnv) dropIdentityRecord() {
	r.t.Helper()
	if err := r.st.DeleteVaultSetting(context.Background(), r.vaultID, brokercore.IdentitySettingKey(rotKey)); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rotEnv) deleteKey() *httptest.ResponseRecorder {
	return r.do(http.MethodDelete, "/v1/credentials", `{"vault":"default","keys":["NOTION_TOKEN"]}`, r.ownerToken)
}

// openRotationWithLiveOldKey replaces rotOld with rotNew while rotOld still
// answers 200, leaving one open rotation.
func (r *rotEnv) openRotationWithLiveOldKey() {
	r.t.Helper()
	r.fake.answer(rotNew, http.StatusOK, r.pinned)
	if rec := r.paste(rotNew); rec.Code != http.StatusOK {
		r.t.Fatalf("control: replacement paste: %d %s", rec.Code, rec.Body.String())
	}
	if open := openRows(r.rows()); len(open) != 1 {
		r.t.Fatalf("control: %d open rotations after a replacement; want 1", len(open))
	}
}

func TestRotationReview2_SameValueRepasteOpensNoRotation(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb) // rotOld stored and pinned
		if rec := r.paste(rotOld); rec.Code != http.StatusOK {
			t.Fatalf("re-paste of the stored value: %d %s", rec.Code, rec.Body.String())
		}
		if open := openRows(r.rows()); len(open) != 0 {
			t.Errorf("re-pasting the stored value opened %d rotation(s) whose superseded key is the live key", len(open))
		}
		if got := r.injectedBy(r.srv); got != rotOld {
			t.Errorf("after a same-value re-paste the injection carries %q; want the stored key", got)
		}
		r.backdate(25 * time.Hour)
		r.tick()
		if got := r.injectedBy(r.srv); got != rotOld {
			t.Errorf("25 hours after a same-value re-paste the key is not served (got %q)", got)
		}
		r.fake.answer(rotNew, http.StatusOK, r.pinned)
		if rec := r.paste(rotNew); rec.Code != http.StatusOK {
			t.Errorf("a real replacement after a same-value re-paste was refused: %d %s", rec.Code, rec.Body.String())
		}
		r.checkHeld("after the replacement")
	})
}

// The same-value check compares secrets, so it must not leak timing: some
// paste-path function calls subtle.ConstantTimeCompare or hmac.Equal.
func TestRotationReview2_SameValueComparisonIsConstantTime(t *testing.T) {
	fset := token.NewFileSet()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var pasteFuncs []string
	constantTime := false
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || !strings.Contains(strings.ToLower(fd.Name.Name), "paste") {
				continue
			}
			pasteFuncs = append(pasteFuncs, fd.Name.Name)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := c.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); ok &&
					((pkg.Name == "subtle" && sel.Sel.Name == "ConstantTimeCompare") || (pkg.Name == "hmac" && sel.Sel.Name == "Equal")) {
					constantTime = true
				}
				return true
			})
		}
	}
	if len(pasteFuncs) == 0 {
		t.Fatal("no paste-path function found (names containing \"paste\")")
	}
	if !constantTime {
		t.Errorf("no paste-path function (%v) compares the pasted value with subtle.ConstantTimeCompare or hmac.Equal", pasteFuncs)
	}
}

// Sequence 1: the first pinned paste stored its value and crashed before
// SetCredentialIdentity. No rotation exists, so only a durable "identity
// missing" state can bring the key back; passes retry until it is recorded.
func TestRotationReview2_LostIdentityAfterFirstPasteRecordedOnTick(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		r.dropIdentityRecord()
		if got := r.injectedBy(r.srv); got != "" {
			t.Fatalf("control: a pinned key with no identity record was injected (%q)", got)
		}
		r.fake.answer(rotOld, http.StatusServiceUnavailable, `{"object":"error"}`)
		r.tick()
		if got := r.injectedBy(r.srv); got != "" {
			t.Errorf("a pass whose probe failed still let the key be injected (%q)", got)
		}
		r.fake.answer(rotOld, http.StatusOK, r.pinned)
		restarted := r.restart()
		tickOn(t, restarted)
		for name, srv := range map[string]*Server{"running": r.srv, "restarted": restarted} {
			if got := r.injectedBy(srv); got != rotOld {
				t.Errorf("%s instance: the lost identity record was never recorded by a later pass (injection carries %q)", name, got)
			}
		}
	})
}

// Sequence 2: a replacement stored its value and lost the identity record;
// the superseded key is already dead. The pass must record the current
// value's identity before it closes the row, and retry until it does.
func TestRotationReview2_PassRecordsIdentityBeforeClosing(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		r.openRotationWithLiveOldKey()
		r.dropIdentityRecord()
		r.fake.answer(rotOld, http.StatusUnauthorized, notion401)
		r.fake.answer(rotNew, http.StatusServiceUnavailable, `{"object":"error"}`)
		r.tick()
		if open := openRows(r.rows()); len(open) != 1 {
			t.Errorf("the pass closed the rotation although the current value's identity was not recorded (%d open rows)", len(open))
		}
		r.fake.answer(rotNew, http.StatusOK, r.pinned)
		r.tick()
		if got := r.injectedBy(r.srv); got != rotNew {
			t.Errorf("the current value's identity was never recorded by a later pass (injection carries %q)", got)
		}
		rows := r.rows()
		if len(rows) != 1 || !rows[0].closed || len(rows[0].oldCT) != 0 {
			t.Errorf("after the identity was recorded and the old key answered 401 the rotation is not closed and destroyed")
		}
	})
}

func TestRotationReview2_DeleteDuringRotationRefused(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		r.openRotationWithLiveOldKey()
		rec := r.deleteKey()
		if rec.Code/100 == 2 {
			t.Errorf("delete of a key with an open rotation answered %d", rec.Code)
		}
		if got := r.currentValue(); got != rotNew {
			t.Errorf("delete during an open rotation removed the current value")
		}
		if vals := r.journaledValues(); len(vals) != 1 || vals[0] != rotOld {
			t.Errorf("delete during an open rotation lost the superseded value (journal holds %d values)", len(vals))
		}
		r.checkHeld("after the refused delete")
	})
}

func TestRotationReview2_DeleteJournalsTheRemovedValue(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb) // rotOld stored, still accepted by the provider
		if rec := r.deleteKey(); rec.Code/100 != 2 {
			t.Fatalf("delete with no open rotation: %d %s", rec.Code, rec.Body.String())
		}
		if vals := r.journaledValues(); len(vals) != 1 || vals[0] != rotOld {
			t.Fatalf("the deleted value, still accepted by the provider, was not journaled (journal holds %d values)", len(vals))
		}
		before := r.fake.probes(rotOld)
		r.tick()
		if r.fake.probes(rotOld) == before {
			t.Error("a pass did not probe the deleted value")
		}

		// Delete-then-paste: the new value must not leave the deleted one
		// unjournaled, and no more than two values are held.
		r.fake.answer(rotNew, http.StatusOK, r.pinned)
		rec := r.paste(rotNew)
		r.checkHeld("after delete-then-paste")
		if rec.Code == http.StatusOK && r.currentValue() != rotNew {
			t.Error("the paste answered 200 but its value is not stored")
		}
		if vals := r.journaledValues(); len(vals) != 1 || vals[0] != rotOld {
			t.Errorf("after delete-then-paste the deleted value is no longer journaled (%d values) although never proven dead", len(vals))
		}

		r.fake.answer(rotOld, http.StatusUnauthorized, notion401)
		r.tick()
		if vals := r.journaledValues(); len(vals) != 0 {
			t.Error("the deleted value was kept after the provider rejected it")
		}
	})
}

func (r *rotEnv) proposal(slots string) int {
	r.t.Helper()
	ctx := context.Background()
	sess, err := r.st.CreateScopedSession(ctx, scopedParams(r.vaultID))
	if err != nil {
		r.t.Fatal(err)
	}
	p, err := r.st.CreateProposal(ctx, r.vaultID, sess.ID, `[]`, slots, "rotate", "", nil)
	if err != nil {
		r.t.Fatal(err)
	}
	return p.ID
}

func (r *rotEnv) approve(id int, creds map[string]string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]any{"vault": "default", "credentials": creds})
	return r.do(http.MethodPost, fmt.Sprintf("/v1/admin/proposals/%d/approve", id), string(b), r.ownerToken)
}

func TestRotationReview2_ProposalApprovalGoesThroughJournal(t *testing.T) {
	const setSlot = `[{"action":"set","key":"NOTION_TOKEN"}]`
	const deleteSlot = `[{"action":"delete","key":"NOTION_TOKEN"}]`
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		t.Run("set during an open rotation is refused", func(t *testing.T) {
			r := newRotEnv(t, tdb.fresh(t))
			r.openRotationWithLiveOldKey()
			r.fake.answer(rotNext, http.StatusOK, r.pinned)
			rec := r.approve(r.proposal(setSlot), map[string]string{rotKey: rotNext})
			if rec.Code/100 == 2 {
				t.Errorf("approving a replacement during an open rotation answered %d", rec.Code)
			}
			if r.currentValue() != rotNew {
				t.Error("the approval replaced the value during an open rotation")
			}
			r.checkHeld("after the refused approval")
		})
		t.Run("delete during an open rotation is refused", func(t *testing.T) {
			r := newRotEnv(t, tdb.fresh(t))
			r.openRotationWithLiveOldKey()
			rec := r.approve(r.proposal(deleteSlot), nil)
			if rec.Code/100 == 2 {
				t.Errorf("approving a delete during an open rotation answered %d", rec.Code)
			}
			if r.currentValue() != rotNew {
				t.Error("the approval deleted the value during an open rotation")
			}
			if vals := r.journaledValues(); len(vals) != 1 || vals[0] != rotOld {
				t.Error("the superseded value was lost")
			}
		})
		t.Run("set is journaled", func(t *testing.T) {
			r := newRotEnv(t, tdb.fresh(t))
			r.fake.answer(rotNew, http.StatusOK, r.pinned)
			rec := r.approve(r.proposal(setSlot), map[string]string{rotKey: rotNew})
			if rec.Code != http.StatusOK {
				t.Fatalf("approving a replacement with no open rotation: %d %s", rec.Code, rec.Body.String())
			}
			if r.currentValue() != rotNew {
				t.Fatal("control: the approved value is not stored")
			}
			if vals := r.journaledValues(); len(vals) != 1 || vals[0] != rotOld {
				t.Errorf("the value replaced by the approval was not journaled (journal holds %d values)", len(vals))
			}
			r.checkHeld("after the approval")
		})
		t.Run("delete is journaled", func(t *testing.T) {
			r := newRotEnv(t, tdb.fresh(t))
			rec := r.approve(r.proposal(deleteSlot), nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("approving a delete with no open rotation: %d %s", rec.Code, rec.Body.String())
			}
			if r.currentValue() != "" {
				t.Fatal("control: the approved delete left the value")
			}
			if vals := r.journaledValues(); len(vals) != 1 || vals[0] != rotOld {
				t.Errorf("the value deleted by the approval was not journaled (journal holds %d values)", len(vals))
			}
		})
	})
}

// barrierFront holds each probe of the listed tokens until all of them have
// arrived (or a timeout passes, so a serialized implementation still
// finishes), then answers from fake. It makes two concurrent pastes both
// finish their checks before either stores.
func barrierFront(t *testing.T, fake *keyedNotion, tokens ...string) {
	t.Helper()
	var mu sync.Mutex
	arrived := map[string]bool{}
	all := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		tok := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		for _, want := range tokens {
			if tok != want {
				continue
			}
			mu.Lock()
			if !arrived[tok] {
				arrived[tok] = true
				if len(arrived) == len(tokens) {
					close(all)
				}
			}
			mu.Unlock()
			select {
			case <-all:
			case <-time.After(3 * time.Second):
			}
		}
		fake.serve(w, req)
	})
	up := httptest.NewServer(h)
	t.Cleanup(up.Close)
	old := identityProbeBaseURL
	identityProbeBaseURL = up.URL
	t.Cleanup(func() { identityProbeBaseURL = old })
}

func TestRotationReview2_ConcurrentFirstPastesNoSilentReplace(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		// Back to a key with no stored value (behind every API path).
		tdb.Exec(t, `DELETE FROM credentials WHERE vault_id = ? AND key = ?`, r.vaultID, rotKey)
		r.dropIdentityRecord()
		r.fake.answer(rotNew, http.StatusOK, r.pinned)
		r.fake.answer(rotNext, http.StatusOK, r.pinned)
		barrierFront(t, r.fake, rotNew, rotNext)

		toks := []string{rotNew, rotNext}
		codes := make([]int, len(toks))
		var wg sync.WaitGroup
		for i, tok := range toks {
			wg.Add(1)
			go func(i int, tok string) {
				defer wg.Done()
				codes[i] = r.paste(tok).Code
			}(i, tok)
		}
		wg.Wait()

		cur := r.currentValue()
		if cur != rotNew && cur != rotNext {
			t.Fatalf("after two concurrent first pastes (codes %v) no pasted value is stored", codes)
		}
		journaled := map[string]bool{}
		for _, v := range r.journaledValues() {
			journaled[v] = true
		}
		for i, tok := range toks {
			if codes[i] == http.StatusOK && tok != cur && !journaled[tok] {
				t.Errorf("paste %d answered 200, but its value was silently replaced: neither stored nor journaled (codes %v)", i, codes)
			}
		}
		r.checkHeld("after concurrent first pastes")
	})
}

// migrate-db (store.MigrateData, SQLite to Postgres) must carry the
// rotation journals, or refuse while any rotation is open. A suspended key
// must stay suspended on the new database.
func TestRotationReview2_MigrationKeepsSuspendedRotation(t *testing.T) {
	src := newSQLiteTestDB(t)
	r := newRotEnv(t, src)
	srcSQL, ok := r.st.(*store.SQLStore)
	if !ok {
		t.Fatalf("source store is %T, not *store.SQLStore", r.st)
	}
	ctx := context.Background()
	migrate := func() (testDB, error) {
		dst, ok := newPostgresTestDB(t)
		if !ok {
			t.Skip("AGENT_VAULT_TEST_POSTGRES_URL not set; migrate-db targets Postgres")
		}
		dstSt := dst.Open(t)
		dstSQL, ok := dstSt.(*store.SQLStore)
		if !ok {
			t.Fatalf("destination store is %T", dstSt)
		}
		return dst, store.MigrateData(ctx, srcSQL, dstSQL, func(string, int) {})
	}

	// Control: with no rotation open the migration succeeds.
	if _, err := migrate(); err != nil {
		t.Fatalf("control: migration with no open rotation failed: %v", err)
	}

	// An open executor-token rotation and a suspended provider-key rotation.
	exp := time.Now().Add(time.Hour)
	r.executor("example-executor", &exp)
	var agentID string
	if err := src.QueryRow(`SELECT id FROM agents WHERE name = ?`, "example-executor").Scan(&agentID); err != nil {
		t.Fatal(err)
	}
	if _, err := srcSQL.PlanTokenRotation(ctx, agentID, ""); err != nil {
		t.Fatal(err)
	}
	r.openRotationWithLiveOldKey()
	r.backdate(25 * time.Hour)
	r.tick()
	if _, err := r.inject(r.srv); refusalCode(err) != "CREDENTIAL_ROTATION_UNVERIFIED" {
		code := refusalCode(err)
		t.Fatalf("control: the source does not suspend the key (refusal %q)", code)
	}

	dst, err := migrate()
	if err != nil {
		t.Logf("migration refused with rotations open: %v", err)
		var n int
		if qerr := dst.QueryRow(`SELECT COUNT(*) FROM credentials`).Scan(&n); qerr != nil || n != 0 {
			t.Errorf("a refused migration left %d credentials on the destination (err %v)", n, qerr)
		}
		return
	}
	var openCred, openTok int
	if err := dst.QueryRow(`SELECT COUNT(*) FROM credential_rotations WHERE closed_at IS NULL`).Scan(&openCred); err != nil {
		t.Fatal(err)
	}
	if err := dst.QueryRow(`SELECT COUNT(*) FROM token_rotations WHERE state <> 'done'`).Scan(&openTok); err != nil {
		t.Fatal(err)
	}
	if openCred != 1 {
		t.Errorf("migration succeeded but carried %d open credential rotations; want 1", openCred)
	}
	if openTok != 1 {
		t.Errorf("migration succeeded but carried %d open token rotations; want 1", openTok)
	}
	if vals := journalOf(t, dst, r.vaultID); len(vals) == 1 && len(vals[0].oldCT) > 0 {
		if pt, err := store.CredentialValueAAD(r.vaultID, rotKey, uint64(vals[0].oldVersion)).Open(vals[0].oldCT, vals[0].oldNonce, r.encKey); err != nil || string(pt) != rotOld {
			t.Errorf("the migrated superseded value does not open under its version's AAD (err %v)", err)
		}
	}
	onDst := New("127.0.0.1:0", dst.Open(t), r.encKey, nil, true, "http://127.0.0.1:14321", r.srv.logger)
	res, ierr := r.inject(onDst)
	if got := carried(res); got != "" {
		t.Errorf("after migration the suspended key is served again (%q)", got)
	}
	if code := refusalCode(ierr); code != "CREDENTIAL_ROTATION_UNVERIFIED" {
		t.Errorf("after migration the key is refused with %q; want CREDENTIAL_ROTATION_UNVERIFIED", code)
	}
}

func TestRotationReview2_PasteRefusedWhenProbeErrors(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		for _, c := range []struct {
			name   string
			status int
		}{{"503", http.StatusServiceUnavailable}, {"401", http.StatusUnauthorized}, {"500", http.StatusInternalServerError}} {
			r.fake.answer(rotNew, c.status, `{"object":"error"}`)
			rec := r.paste(rotNew)
			if rec.Code/100 == 2 {
				t.Errorf("replacement paste whose probe answered %s was accepted (%d)", c.name, rec.Code)
			}
			if r.currentValue() != rotOld {
				t.Fatalf("replacement paste whose probe answered %s replaced the value", c.name)
			}
		}
		if open := openRows(r.rows()); len(open) != 0 {
			t.Errorf("refused pastes opened %d rotations", len(open))
		}

		// A first paste (no stored value) is checked the same way.
		tdb.Exec(t, `DELETE FROM credentials WHERE vault_id = ? AND key = ?`, r.vaultID, rotKey)
		r.fake.answer(rotNext, http.StatusServiceUnavailable, `{"object":"error"}`)
		if rec := r.paste(rotNext); rec.Code/100 == 2 {
			t.Errorf("first paste whose probe failed was accepted (%d)", rec.Code)
		}
		if r.currentValue() != "" {
			t.Error("first paste whose probe failed was stored")
		}
	})
}

func TestRotationReview2_SuspensionBoundaryAt24Hours(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		r.openRotationWithLiveOldKey()
		r.backdate(24*time.Hour - time.Minute)
		if got := r.injectedBy(r.srv); got != rotNew {
			t.Errorf("suspended one minute before 24 hours (injection carries %q)", got)
		}
		r.backdate(24*time.Hour + 2*time.Second)
		res, err := r.inject(r.srv)
		if got := carried(res); got != "" {
			t.Errorf("served two seconds past 24 hours (%q)", got)
		}
		if code := refusalCode(err); code != "CREDENTIAL_ROTATION_UNVERIFIED" {
			t.Errorf("two seconds past 24 hours refused with %q; want CREDENTIAL_ROTATION_UNVERIFIED", code)
		}
	})
}

// subServices adds a passthrough service that uses NOTION_TOKEN only as a
// substitution.
const subServices = `[{"name":"notion-read","host":"api.notion.com/v1/pages/{id}","methods":["GET"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}},
 {"name":"sub-read","host":"api.example.test/v1/items/{id}","methods":["GET"],"auth":{"type":"passthrough"},
  "substitutions":[{"key":"NOTION_TOKEN","placeholder":"__tok__","in":["header"]}]}]`

func (r *rotEnv) injectSub() (*brokercore.InjectResult, error) {
	ctx := brokercore.WithRequestMethod(context.Background(), http.MethodGet)
	return r.srv.CredentialProvider().Inject(ctx, r.vaultID, "api.example.test", 443, "/v1/items/abc")
}

func subCarried(res *brokercore.InjectResult) string {
	if got := carried(res); got != "" {
		return got
	}
	if res == nil {
		return ""
	}
	for _, s := range res.Substitutions {
		for _, tok := range rotTokens {
			if strings.Contains(s.Value, tok) {
				return tok
			}
		}
	}
	return ""
}

func (r *rotEnv) useSubServices() {
	r.t.Helper()
	if _, err := r.st.SetBrokerConfig(context.Background(), r.vaultID, subServices); err != nil {
		r.t.Fatal(err)
	}
}

func TestRotationReview2_SubstitutionKeyPinChecked(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		r.useSubServices()
		if res, err := r.injectSub(); subCarried(res) != rotOld {
			t.Fatalf("control: the substitution service does not carry the pinned key (err %v)", err)
		}
		ctx := context.Background()
		c, err := r.st.GetCredential(ctx, r.vaultID, rotKey)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := brokercore.IdentityRecord{
			Binding: brokercore.VersionBinding(c.ID, c.Version), Digest: r.otherDigest,
			WorkspaceName: "Other Workspace", WorkspaceID: "ws-11111111-test", IntegrationName: "other-integration",
		}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if err := r.st.SetVaultSetting(ctx, r.vaultID, brokercore.IdentitySettingKey(rotKey), rec); err != nil {
			t.Fatal(err)
		}
		res, ierr := r.injectSub()
		if got := subCarried(res); got != "" {
			t.Errorf("a pinned key whose identity differs from the pin was injected through a substitution (%q)", got)
		}
		if code := refusalCode(ierr); code != "IDENTITY_MISMATCH" {
			t.Errorf("substitution of a mismatched pinned key refused with %q; want IDENTITY_MISMATCH", code)
		}
	})
}

func TestRotationReview2_SubstitutionKeySuspended(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		r.openRotationWithLiveOldKey()
		r.useSubServices()
		if res, err := r.injectSub(); subCarried(res) != rotNew {
			t.Fatalf("control: the substitution service does not carry the current key inside the window (err %v)", err)
		}
		r.backdate(25 * time.Hour)
		res, err := r.injectSub()
		if got := subCarried(res); got != "" {
			t.Errorf("a suspended key was injected through a substitution (%q)", got)
		}
		if code := refusalCode(err); code != "CREDENTIAL_ROTATION_UNVERIFIED" {
			t.Errorf("substitution of a suspended key refused with %q; want CREDENTIAL_ROTATION_UNVERIFIED", code)
		}
	})
}
