// Provider-key rotation (fork change 17, provider-key half). A pasted key
// that replaces an existing one is journaled, its identity is checked
// against the pinned identity, and the superseded key is probed until the
// provider rejects it. Every test runs on Postgres and SQLite.
//
// Contract the tests pin:
//
//   - Pin. The vault setting "credential_identity_pin:<KEY>" holds the
//     expected identity digest (64 lowercase hex, identity.NotionDigest) for
//     credential KEY. Bootstrap writes it from a service's identity_pin
//     (internal/bootstrap/provider_pin_test.go).
//   - Injection. While KEY has a pin, the proxy injects KEY only when the
//     identity record bound to the current row and version carries the pin
//     digest. A different digest is refused with IDENTITY_MISMATCH; no
//     record is refused too. No credential is attached to a refusal.
//   - Paste. POST /v1/credentials replacing an existing value of a key with
//     an identity probe writes, in the compare-and-set transaction that
//     stores the new version, one credential_rotations row: vault_id,
//     credential_key, old_version, new_version, old_ciphertext and
//     old_nonce (the superseded value, sealed under
//     store.CredentialValueAAD(vault, key, old_version)), created_at (the
//     dialect's FormatTime) and closed_at (NULL while open). If that row
//     cannot be written, nothing is replaced. With a pin, the new value is
//     probed before the response; a digest other than the pin answers
//     non-2xx with IDENTITY_MISMATCH. A paste while the key has an open
//     rotation is refused, so at most two values of a key are ever live.
//   - Tick. (*Server).CredentialRotationTick(ctx) error makes one pass:
//     it probes the provider identity endpoint with each open row's
//     superseded value; only a 401 proves it dead, and then old_ciphertext
//     and old_nonce are destroyed (NULL or empty) and closed_at is set. It
//     also probes a current value whose identity is not recorded. Any
//     number of passes, on any number of instances, is safe.
//   - Loop. (*Server).RunCredentialRotations(ctx, tick <-chan time.Time)
//     makes one pass at once (startup), one per tick, and returns when ctx
//     ends. Start runs it.
//   - Suspension. While a key has an open row created more than 24 hours
//     ago, every injection of it is refused with
//     CREDENTIAL_ROTATION_UNVERIFIED, from database state alone (a restarted
//     process refuses before its first pass). A pass that sees the 401 lifts
//     it.
//   - AGENT_VAULT_IDENTITY_PROBE=off disables only the scheduled background
//     probe, never the paste-time pin check or the rotation passes.
//
// Failure modes, each with the test that catches it:
//
//  1. The new version is stored with no journal row, or before it, so a
//     crash leaves a superseded key nobody probes.
//     TestProviderRotation_JournalRowWrittenWithReplacement,
//     TestProviderRotation_NoReplacementWithoutJournalRow
//  2. The journal keeps the superseded value in plaintext, or sealed under
//     the new version's AAD (so it opens as the live value).
//     TestProviderRotation_JournalRowWrittenWithReplacement,
//     TestProviderRotation_NoKeyValueInLogsOrResponses
//  3. A pasted key for another workspace or integration is accepted and
//     served. TestProviderRotation_NewKeyMustMatchPin
//  4. A value whose recorded identity differs from the pin, or that has no
//     record, is injected. TestProviderRotation_InjectionRequiresPinnedIdentity
//  5. The superseded key is never probed, or is probed with the new value.
//     TestProviderRotation_OldKeyProbedUntil401ThenDestroyed
//  6. A 5xx, 403 or network error is taken as proof the key is dead.
//     TestProviderRotation_OldKeyProbedUntil401ThenDestroyed
//  7. A 401 closes the row but leaves the superseded ciphertext in the
//     table, or later passes keep probing a closed row.
//     TestProviderRotation_OldKeyProbedUntil401ThenDestroyed
//  8. Two instances' passes double-apply or error on the same row.
//     TestProviderRotation_OldKeyProbedUntil401ThenDestroyed
//  9. A superseded key still alive after 24 hours keeps being served behind
//     the new one, or suspension starts early (before 24 hours).
//     TestProviderRotation_SuspendedAfter24hUntil401
//  10. Suspension lives only in memory, so a restart serves again.
//     TestProviderRotation_SuspendedAfter24hUntil401
//  11. Suspension is never lifted after the 401.
//     TestProviderRotation_SuspendedAfter24hUntil401
//  12. A crash after the new version is stored and before the first probe
//     is not resumed: no pass on startup, or none per tick.
//     TestProviderRotation_CrashBeforeFirstProbe_ResumedOnStartupAndTick,
//     TestProviderRotation_StartRunsRotationLoop
//  13. A second paste while a rotation is open leaves three live values, or
//     drops a superseded value that was never proven dead; concurrent pastes
//     both land. TestProviderRotation_AtMostTwoLiveValues,
//     TestProviderRotation_ConcurrentPastesLeaveOneRotation
//  14. A key value reaches a log line, a request-log record, stderr or any
//     response. TestProviderRotation_NoKeyValueInLogsOrResponses
//
// A paste racing an OAuth refresh is the compare-and-set of fork change 13,
// pinned by TestOAuthCompareAndSet_Backends; failure mode 13 covers the
// paste-against-paste race through the journal.
package server

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/identity"
	"github.com/Infisical/agent-vault/internal/store"
)

const (
	rotOld   = "SENTINEL-ROT-0001-old-key"
	rotNew   = "SENTINEL-ROT-0002-new-key"
	rotWrong = "SENTINEL-ROT-0003-other-workspace-key"
	rotNext  = "SENTINEL-ROT-0004-second-new-key"

	rotKey        = "NOTION_TOKEN"
	pinSettingKey = "credential_identity_pin:" + rotKey
	notion401     = `{"object":"error","status":401,"code":"unauthorized","message":"API token is invalid."}`
)

var rotTokens = []string{rotOld, rotNew, rotWrong, rotNext}

// keyedNotion answers /v1/users/me per bearer token. A token with no
// answer gets Notion's 401.
type keyedNotion struct {
	mu     sync.Mutex
	status map[string]int
	body   map[string]string
	seen   map[string]int
}

func (k *keyedNotion) answer(tok string, status int, body string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.status[tok], k.body[tok] = status, body
}

func (k *keyedNotion) probes(tok string) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.seen[tok]
}

func (k *keyedNotion) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != identity.NotionProbePath {
		http.NotFound(w, r)
		return
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	k.mu.Lock()
	k.seen[tok]++
	status, ok := k.status[tok]
	body := k.body[tok]
	k.mu.Unlock()
	if !ok {
		status, body = http.StatusUnauthorized, notion401
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

type rotEnv struct {
	*kenv
	fake        *keyedNotion
	pinned      string // users/me body of the pinned identity
	otherBody   string // users/me body of another workspace
	pin         string
	otherDigest string
}

// newRotEnv stores rotOld (version 1) under a pin that matches it, with its
// identity recorded.
func newRotEnv(t *testing.T, tdb testDB) *rotEnv {
	t.Helper()
	t.Setenv("AGENT_VAULT_IDENTITY_PROBE", "off")
	fake := &keyedNotion{status: map[string]int{}, body: map[string]string{}, seen: map[string]int{}}
	up := httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(up.Close)
	old := identityProbeBaseURL
	identityProbeBaseURL = up.URL
	t.Cleanup(func() { identityProbeBaseURL = old })

	r := &rotEnv{
		kenv:      newKEnv(t, tdb),
		fake:      fake,
		pinned:    usersMe(displayWSID, displayWSName, displayBotName),
		otherBody: usersMe("ws-11111111-test", "Other Workspace", "other-integration"),
	}
	var err error
	if r.pin, err = identity.NotionDigest([]byte(r.pinned)); err != nil {
		t.Fatal(err)
	}
	if r.otherDigest, err = identity.NotionDigest([]byte(r.otherBody)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := r.st.SetBrokerConfig(ctx, r.vaultID,
		`[{"name":"notion-read","host":"api.notion.com/v1/pages/{id}","methods":["GET"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}]`); err != nil {
		t.Fatal(err)
	}
	if err := r.st.SetVaultSetting(ctx, r.vaultID, pinSettingKey, r.pin); err != nil {
		t.Fatal(err)
	}
	fake.answer(rotOld, http.StatusOK, r.pinned)
	if rec := r.paste(rotOld); rec.Code != http.StatusOK {
		t.Fatalf("control: first paste of a key matching the pin: %d %s", rec.Code, rec.Body.String())
	}
	if err := r.srv.runIdentityProbe(ctx, r.vaultID, rotKey); err != nil {
		t.Fatalf("control: identity probe of the first value: %v", err)
	}
	if got := r.injectedBy(r.srv); got != rotOld {
		t.Fatalf("control: the pinned first value is not injected (got %q)", got)
	}
	return r
}

func (r *rotEnv) paste(tok string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]any{"vault": "default", "credentials": map[string]string{rotKey: tok}})
	return r.do(http.MethodPost, "/v1/credentials", string(b), r.ownerToken)
}

type rotationTicker interface {
	CredentialRotationTick(ctx context.Context) error
}

type rotationLooper interface {
	RunCredentialRotations(ctx context.Context, tick <-chan time.Time)
}

func tickOn(t *testing.T, srv *Server) {
	t.Helper()
	tk, ok := any(srv).(rotationTicker)
	if !ok {
		t.Fatal("*Server has no CredentialRotationTick(ctx) error: provider-key rotation passes are not implemented")
	}
	if err := tk.CredentialRotationTick(context.Background()); err != nil {
		t.Fatalf("CredentialRotationTick: %v", err)
	}
}

func (r *rotEnv) tick() { r.t.Helper(); tickOn(r.t, r.srv) }

// restart returns a second server on a fresh store handle over the same
// database and key, as after a process restart.
func (r *rotEnv) restart() *Server {
	r.t.Helper()
	return New("127.0.0.1:0", r.tdb.Open(r.t), r.encKey, nil, true, "http://127.0.0.1:14321", r.srv.logger)
}

type rotRow struct {
	id                     int64
	key                    string
	oldVersion, newVersion int64
	oldCT, oldNonce        []byte
	closed                 bool
}

func (r *rotEnv) rows() []rotRow {
	r.t.Helper()
	q := r.tdb.rebind(`SELECT id, credential_key, old_version, new_version, old_ciphertext, old_nonce, closed_at
		FROM credential_rotations WHERE vault_id = ? ORDER BY id`)
	rs, err := r.tdb.Raw.Query(q, r.vaultID)
	if err != nil {
		r.t.Fatalf("reading credential_rotations: %v (the provider-key rotation journal does not exist)", err)
	}
	defer func() { _ = rs.Close() }()
	var out []rotRow
	for rs.Next() {
		var row rotRow
		var closedAt any
		if err := rs.Scan(&row.id, &row.key, &row.oldVersion, &row.newVersion, &row.oldCT, &row.oldNonce, &closedAt); err != nil {
			r.t.Fatal(err)
		}
		row.closed = closedAt != nil
		out = append(out, row)
	}
	if err := rs.Err(); err != nil {
		r.t.Fatal(err)
	}
	return out
}

func openRows(rows []rotRow) []rotRow {
	var out []rotRow
	for _, row := range rows {
		if !row.closed {
			out = append(out, row)
		}
	}
	return out
}

// liveValues counts the values of the key the vault still holds: the
// current row plus every superseded ciphertext not yet destroyed.
func (r *rotEnv) liveValues() int {
	r.t.Helper()
	n := 0
	if c, err := r.st.GetCredential(context.Background(), r.vaultID, rotKey); err == nil && c != nil && len(c.Ciphertext) > 0 {
		n++
	}
	for _, row := range r.rows() {
		if len(row.oldCT) > 0 {
			n++
		}
	}
	return n
}

func (r *rotEnv) current() (uint64, string) {
	r.t.Helper()
	c, err := r.st.GetCredential(context.Background(), r.vaultID, rotKey)
	if err != nil || c == nil {
		r.t.Fatalf("reading %s: %v", rotKey, err)
	}
	pt, err := store.CredentialValueAAD(r.vaultID, rotKey, c.Version).Open(c.Ciphertext, c.Nonce, r.encKey)
	if err != nil {
		r.t.Fatalf("current %s does not open at its version %d: %v", rotKey, c.Version, err)
	}
	return c.Version, string(pt)
}

// backdate moves the open rows' created_at back by d.
func (r *rotEnv) backdate(d time.Duration) {
	r.t.Helper()
	past := time.Now().Add(-d).UTC()
	var v any = past
	if r.tdb.Kind == "sqlite" {
		v = past.Format(time.DateTime)
	}
	r.tdb.Exec(r.t, `UPDATE credential_rotations SET created_at = ? WHERE vault_id = ? AND closed_at IS NULL`, v, r.vaultID)
}

func (r *rotEnv) inject(srv *Server) (*brokercore.InjectResult, error) {
	ctx := brokercore.WithRequestMethod(context.Background(), http.MethodGet)
	return srv.CredentialProvider().Inject(ctx, r.vaultID, "api.notion.com", 443, "/v1/pages/abc")
}

// injectedBy returns which sentinel key the injection carries, "" for none.
func (r *rotEnv) injectedBy(srv *Server) string {
	res, _ := r.inject(srv)
	return carried(res)
}

func carried(res *brokercore.InjectResult) string {
	if res == nil {
		return ""
	}
	for _, v := range res.Headers {
		for _, tok := range rotTokens {
			if strings.Contains(v, tok) {
				return tok
			}
		}
	}
	return ""
}

// refusalCode returns the error code the proxy answers an injection error
// with, or "" when the injection was not refused.
func refusalCode(err error) string {
	if err == nil {
		return ""
	}
	w := httptest.NewRecorder()
	brokercore.WriteInjectError(w, err, "api.notion.com", "default", "")
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return body.Error
}

// --- tests ---

func TestProviderRotation_JournalRowWrittenWithReplacement(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		r.fake.answer(rotNew, http.StatusOK, r.pinned)
		if rec := r.paste(rotNew); rec.Code != http.StatusOK {
			t.Fatalf("paste of a replacement matching the pin: %d %s", rec.Code, rec.Body.String())
		}
		if v, val := r.current(); v != 2 || val != rotNew {
			t.Fatalf("current value after the paste: version %d, new value stored %v; want version 2 holding the new key", v, val == rotNew)
		}
		rows := r.rows()
		if len(rows) != 1 {
			t.Fatalf("credential_rotations has %d rows after one replacement; want 1", len(rows))
		}
		row := rows[0]
		if row.key != rotKey || row.oldVersion != 1 || row.newVersion != 2 || row.closed {
			t.Fatalf("journal row = key %q old %d new %d closed %v; want %s, 1, 2, open", row.key, row.oldVersion, row.newVersion, row.closed, rotKey)
		}
		pt, err := store.CredentialValueAAD(r.vaultID, rotKey, 1).Open(row.oldCT, row.oldNonce, r.encKey)
		if err != nil || string(pt) != rotOld {
			t.Fatalf("old_ciphertext does not open to the superseded key under version 1's AAD (err %v)", err)
		}
		if _, err := store.CredentialValueAAD(r.vaultID, rotKey, 2).Open(row.oldCT, row.oldNonce, r.encKey); err == nil {
			t.Fatal("old_ciphertext opens under the new version's AAD")
		}
	})
}

// The journal row is part of the replacement's transaction: if it cannot be
// written, the old value stays.
func TestProviderRotation_NoReplacementWithoutJournalRow(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		r.fake.answer(rotNew, http.StatusOK, r.pinned)
		drop := `DROP TABLE IF EXISTS credential_rotations`
		if tdb.Kind == "postgres" {
			drop += " CASCADE"
		}
		tdb.Exec(t, drop)
		rec := r.paste(rotNew)
		v, val := r.current()
		if val != rotOld || v != 1 {
			t.Fatalf("the key was replaced (now version %d) although no credential_rotations row could be written; paste answered %d", v, rec.Code)
		}
		if rec.Code == http.StatusOK {
			t.Fatal("paste answered 200 although nothing was replaced")
		}
	})
}

func TestProviderRotation_NewKeyMustMatchPin(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		r.fake.answer(rotOld, http.StatusUnauthorized, notion401) // revoked at the provider first
		r.fake.answer(rotWrong, http.StatusOK, r.otherBody)
		r.fake.answer(rotNew, http.StatusOK, r.pinned)

		rec := r.paste(rotWrong)
		if rec.Code/100 == 2 || !strings.Contains(rec.Body.String(), "IDENTITY_MISMATCH") {
			t.Errorf("paste of a key for another workspace answered %d %q; want a refusal naming IDENTITY_MISMATCH", rec.Code, rec.Body.String())
		}
		if r.fake.probes(rotWrong) == 0 {
			t.Error("the pasted key was never probed before the paste was answered")
		}
		if got := r.injectedBy(r.srv); got == rotWrong {
			t.Error("the key whose identity differs from the pin was injected")
		}
		if n := r.liveValues(); n > 2 {
			t.Errorf("%d values of the key held after a refused paste; at most 2", n)
		}

		r.tick() // the superseded key answers 401
		if rec := r.paste(rotNew); rec.Code != http.StatusOK {
			t.Fatalf("paste of the correct key after the refused one: %d %s", rec.Code, rec.Body.String())
		}
		if got := r.injectedBy(r.srv); got != rotNew {
			t.Errorf("after the correct paste the injection carries %q; want the new key", got)
		}
		if n := r.liveValues(); n > 2 {
			t.Errorf("%d values of the key held after the correct paste; at most 2", n)
		}
	})
}

func TestProviderRotation_InjectionRequiresPinnedIdentity(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb) // the control in newRotEnv injects rotOld
		ctx := context.Background()
		c, err := r.st.GetCredential(ctx, r.vaultID, rotKey)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := brokercore.IdentityRecord{
			Binding:         brokercore.VersionBinding(c.ID, c.Version),
			Digest:          r.otherDigest,
			WorkspaceName:   "Other Workspace",
			WorkspaceID:     "ws-11111111-test",
			IntegrationName: "other-integration",
		}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if err := r.st.SetVaultSetting(ctx, r.vaultID, brokercore.IdentitySettingKey(rotKey), rec); err != nil {
			t.Fatal(err)
		}
		res, err := r.inject(r.srv)
		if carried(res) != "" {
			t.Error("a value whose recorded identity differs from the pin was injected")
		}
		if code := refusalCode(err); code != "IDENTITY_MISMATCH" {
			t.Errorf("identity differing from the pin refused with %q; want IDENTITY_MISMATCH", code)
		}

		if err := r.st.DeleteVaultSetting(ctx, r.vaultID, brokercore.IdentitySettingKey(rotKey)); err != nil {
			t.Fatal(err)
		}
		res, err = r.inject(r.srv)
		if carried(res) != "" || err == nil {
			t.Error("a value with no recorded identity was injected while the key has a pin")
		}
	})
}

func TestProviderRotation_OldKeyProbedUntil401ThenDestroyed(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		r.fake.answer(rotNew, http.StatusOK, r.pinned)
		if rec := r.paste(rotNew); rec.Code != http.StatusOK {
			t.Fatalf("paste: %d %s", rec.Code, rec.Body.String())
		}
		before := r.fake.probes(rotOld)
		r.tick()
		if r.fake.probes(rotOld) == before {
			t.Fatal("a pass did not probe the identity endpoint with the superseded key")
		}
		var origCT []byte
		if open := openRows(r.rows()); len(open) != 1 || len(open[0].oldCT) == 0 {
			t.Fatalf("a superseded key that still works lost its open row or its ciphertext (%d open rows)", len(open))
		} else {
			origCT = open[0].oldCT
		}

		for _, c := range []struct {
			status int
			why    string
		}{
			{http.StatusInternalServerError, "500"},
			{http.StatusForbidden, "403"},
			{http.StatusTooManyRequests, "429"},
		} {
			r.fake.answer(rotOld, c.status, `{"object":"error"}`)
			r.tick()
			if open := openRows(r.rows()); len(open) != 1 || len(open[0].oldCT) == 0 {
				t.Errorf("a %s from the identity endpoint closed the rotation; only a 401 proves the key dead", c.why)
			}
		}

		r.fake.answer(rotOld, http.StatusUnauthorized, notion401)
		// Two instances pass at once, as after a crash and restart beside a
		// running one.
		other := r.restart()
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, srv := range []*Server{r.srv, other} {
			tk, ok := any(srv).(rotationTicker)
			if !ok {
				t.Fatal("*Server has no CredentialRotationTick")
			}
			wg.Add(1)
			go func(i int, tk rotationTicker) {
				defer wg.Done()
				errs[i] = tk.CredentialRotationTick(context.Background())
			}(i, tk)
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Errorf("concurrent pass %d: %v", i, err)
			}
		}
		rows := r.rows()
		if len(rows) != 1 || !rows[0].closed {
			t.Fatalf("after a 401 the rotation is not closed exactly once (%d rows, closed %v)", len(rows), len(rows) == 1 && rows[0].closed)
		}
		if len(rows[0].oldCT) != 0 || len(rows[0].oldNonce) != 0 {
			t.Error("the superseded ciphertext was kept after the 401")
		}
		if tdb.RowBytesContain(t, "credential_rotations", origCT) {
			t.Error("the superseded ciphertext is still somewhere in credential_rotations")
		}
		after := r.fake.probes(rotOld)
		r.tick()
		if r.fake.probes(rotOld) != after {
			t.Error("a closed rotation's key was probed again")
		}
		if got := r.injectedBy(r.srv); got != rotNew {
			t.Errorf("after the rotation closed the injection carries %q; want the new key", got)
		}
	})
}

func TestProviderRotation_SuspendedAfter24hUntil401(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		r.fake.answer(rotNew, http.StatusOK, r.pinned) // rotOld keeps answering 200
		if rec := r.paste(rotNew); rec.Code != http.StatusOK {
			t.Fatalf("paste: %d %s", rec.Code, rec.Body.String())
		}
		r.tick()
		if got := r.injectedBy(r.srv); got != rotNew {
			t.Fatalf("inside the 24-hour window the new key is not served (got %q)", got)
		}
		r.backdate(23 * time.Hour)
		r.tick()
		if got := r.injectedBy(r.srv); got != rotNew {
			t.Errorf("suspended at 23 hours (got %q); the grace window is 24 hours", got)
		}

		r.backdate(25 * time.Hour)
		r.tick()
		res, err := r.inject(r.srv)
		if got := carried(res); got != "" {
			t.Errorf("superseded key alive 25 hours after the paste, and the injection still carries %q", got)
		}
		if code := refusalCode(err); code != "CREDENTIAL_ROTATION_UNVERIFIED" {
			t.Errorf("suspended injection refused with %q; want CREDENTIAL_ROTATION_UNVERIFIED", code)
		}

		// Suspension is database state: a restarted process refuses before
		// its first pass.
		restarted := r.restart()
		res, err = r.inject(restarted)
		if got := carried(res); got != "" {
			t.Errorf("after a restart the suspended key is served again (%q)", got)
		}
		if code := refusalCode(err); code != "CREDENTIAL_ROTATION_UNVERIFIED" {
			t.Errorf("after a restart the suspended injection is refused with %q; want CREDENTIAL_ROTATION_UNVERIFIED", code)
		}

		r.fake.answer(rotOld, http.StatusUnauthorized, notion401)
		tickOn(t, restarted)
		for name, srv := range map[string]*Server{"running": r.srv, "restarted": restarted} {
			if got := r.injectedBy(srv); got != rotNew {
				t.Errorf("%s instance: suspension not lifted after the 401 (injection carries %q)", name, got)
			}
		}
	})
}

// The state a crash leaves after the replacement commits and before any
// probe: the new version stored, its identity not recorded, the superseded
// key never probed. It is resumed by the startup pass and by each tick.
func TestProviderRotation_CrashBeforeFirstProbe_ResumedOnStartupAndTick(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		r.fake.answer(rotNew, http.StatusOK, r.pinned)
		if rec := r.paste(rotNew); rec.Code != http.StatusOK {
			t.Fatalf("paste: %d %s", rec.Code, rec.Body.String())
		}
		ctx := context.Background()
		if err := r.st.DeleteVaultSetting(ctx, r.vaultID, brokercore.IdentitySettingKey(rotKey)); err != nil {
			t.Fatal(err)
		}
		if open := openRows(r.rows()); len(open) != 1 {
			t.Fatalf("control: %d open rotations after the paste; want 1", len(open))
		}

		srv := r.restart()
		if got := r.injectedBy(srv); got != "" {
			t.Errorf("restarted before any pass, the unverified new value was injected (%q)", got)
		}
		lp, ok := any(srv).(rotationLooper)
		if !ok {
			t.Fatal("*Server has no RunCredentialRotations(ctx, tick): rotations are not resumed on startup or tick")
		}
		loopCtx, stop := context.WithCancel(ctx)
		ticks := make(chan time.Time)
		done := make(chan struct{})
		go func() { defer close(done); lp.RunCredentialRotations(loopCtx, ticks) }()
		defer func() {
			stop()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("RunCredentialRotations did not return after its context ended")
			}
		}()

		// Startup pass: the old key still works, so the row stays open, but
		// the new value's identity is recorded and it is served.
		waitFor(t, "startup pass recorded the new value's identity", func() bool { return r.injectedBy(srv) == rotNew })
		if r.fake.probes(rotOld) == 0 {
			t.Error("the startup pass did not probe the superseded key")
		}

		// Tick pass: the old key is now dead.
		r.fake.answer(rotOld, http.StatusUnauthorized, notion401)
		select {
		case ticks <- time.Now():
		case <-time.After(10 * time.Second):
			t.Fatal("RunCredentialRotations is not receiving ticks")
		}
		waitFor(t, "tick pass closed the rotation after the 401", func() bool {
			rows := r.rows()
			return len(rows) == 1 && rows[0].closed && len(rows[0].oldCT) == 0
		})
	})
}

func TestProviderRotation_AtMostTwoLiveValues(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		r.fake.answer(rotNew, http.StatusOK, r.pinned)
		r.fake.answer(rotNext, http.StatusOK, r.pinned) // rotOld still answers 200
		if rec := r.paste(rotNew); rec.Code != http.StatusOK {
			t.Fatalf("paste: %d %s", rec.Code, rec.Body.String())
		}
		rec := r.paste(rotNext)
		if rec.Code/100 == 2 {
			t.Errorf("a second replacement was accepted (%d) while the first superseded key is unverified", rec.Code)
		}
		if n := r.liveValues(); n > 2 {
			t.Errorf("%d values of the key held; at most 2", n)
		}
		if _, val := r.current(); val != rotNew {
			t.Error("the current value moved past the open rotation")
		}
		open := openRows(r.rows())
		if len(open) != 1 || open[0].oldVersion != 1 || len(open[0].oldCT) == 0 {
			t.Errorf("the unverified superseded key lost its open row (%d open rows)", len(open))
		}
	})
}

func TestProviderRotation_ConcurrentPastesLeaveOneRotation(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		r.fake.answer(rotNew, http.StatusOK, r.pinned)
		r.fake.answer(rotNext, http.StatusOK, r.pinned)
		codes := make([]int, 2)
		var wg sync.WaitGroup
		for i, tok := range []string{rotNew, rotNext} {
			wg.Add(1)
			go func(i int, tok string) {
				defer wg.Done()
				codes[i] = r.paste(tok).Code
			}(i, tok)
		}
		wg.Wait()
		ok := 0
		var winner string
		for i, tok := range []string{rotNew, rotNext} {
			if codes[i] == http.StatusOK {
				ok++
				winner = tok
			}
		}
		if ok != 1 {
			t.Fatalf("%d of two concurrent replacements succeeded (codes %v); want exactly 1", ok, codes)
		}
		if _, val := r.current(); val != winner {
			t.Error("the stored value is not the paste that was answered 200")
		}
		if open := openRows(r.rows()); len(open) != 1 {
			t.Errorf("%d open rotations after concurrent pastes; want 1", len(open))
		}
		if n := r.liveValues(); n > 2 {
			t.Errorf("%d values of the key held; at most 2", n)
		}
	})
}

func TestProviderRotation_NoKeyValueInLogsOrResponses(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		r := newRotEnv(t, tdb)
		r.fake.answer(rotNew, http.StatusOK, r.pinned)
		r.fake.answer(rotWrong, http.StatusOK, r.otherBody)
		var refusals []string
		note := func(err error) {
			if err == nil {
				return
			}
			w := httptest.NewRecorder()
			brokercore.WriteInjectError(w, err, "api.notion.com", "default", "")
			refusals = append(refusals, err.Error(), w.Body.String())
		}
		checkTable := func(stage string) {
			for _, tok := range rotTokens {
				if tdb.RowBytesContain(t, "credential_rotations", []byte(tok)) {
					t.Errorf("%s: credential_rotations holds a key in plaintext", stage)
				}
				if tdb.RowBytesContain(t, "vault_settings", []byte(tok)) {
					t.Errorf("%s: vault_settings holds a key in plaintext", stage)
				}
			}
		}

		if rec := r.paste(rotNew); rec.Code != http.StatusOK {
			t.Fatalf("paste: %d %s", rec.Code, rec.Body.String())
		}
		checkTable("after the paste")
		r.tick()
		r.backdate(25 * time.Hour)
		r.tick()
		_, err := r.inject(r.srv)
		note(err)
		r.paste(rotWrong) // refused: a rotation is open, and the identity differs
		_ = metadataEntries(t, r.kenv)
		r.fake.answer(rotOld, http.StatusUnauthorized, notion401)
		r.tick()
		checkTable("after the rotation closed")
		r.paste(rotWrong) // refused: identity differs from the pin
		_, err = r.inject(r.srv)
		note(err)

		chs := r.channels()
		chs["injection refusals"] = strings.Join(refusals, "\n")
		if hits := findSentinels(chs, rotTokens); len(hits) > 0 {
			t.Errorf("key values reached output: %v", hits)
		}
	})
}

// Start resumes open rotations: it runs the rotation loop.
func TestProviderRotation_StartRunsRotationLoop(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var start *ast.FuncDecl
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if ok && fd.Name.Name == "Start" && fd.Recv != nil && len(fd.Recv.List) == 1 {
					if star, ok := fd.Recv.List[0].Type.(*ast.StarExpr); ok {
						if id, ok := star.X.(*ast.Ident); ok && id.Name == "Server" {
							start = fd
						}
					}
				}
			}
		}
	}
	if start == nil {
		t.Fatal("(*Server).Start not found")
	}
	calls := false
	ast.Inspect(start.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "RunCredentialRotations" {
				calls = true
			}
		}
		return true
	})
	if !calls {
		t.Error("(*Server).Start does not run RunCredentialRotations, so open rotations are not resumed on startup")
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting: %s", what)
}
