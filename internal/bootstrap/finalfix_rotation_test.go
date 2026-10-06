// Final-review item 3: rotation must not leave old executor tokens running at
// full TTL.
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

func tokenHash(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// Every bootstrap run caps executor tokens older than the newest one to the
// rotation overlap, not only the run that mints. Here a full-TTL token older
// than the delivered one exists (for example left by an earlier run that
// crashed after minting) and the second run has nothing to mint.
func TestFinalFix_EveryRunCapsOlderExecutorTokens(t *testing.T) {
	ctx := context.Background()
	tdb := newSQLiteTestDB(t)
	fx := newFixture(t, tdb.Open(t), docJSON)
	if err := Apply(ctx, fx.opts); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	delivered := fx.tokens.last().token

	agent, err := fx.st.GetAgentByName(ctx, "example-executor")
	if err != nil || agent == nil {
		t.Fatalf("executor agent: %v", err)
	}
	fullTTL := time.Now().Add(720 * time.Hour)
	older, err := fx.st.CreateAgentToken(ctx, agent.ID, &fullTTL)
	if err != nil {
		t.Fatal(err)
	}
	// Make it older than the delivered token.
	tdb.Exec(t, `UPDATE sessions SET created_at = ? WHERE id = ?`,
		time.Now().Add(-48*time.Hour).UTC().Format(time.DateTime), tokenHash(older.ID))

	if err := Apply(ctx, fx.opts); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if fx.tokens.count() != 1 {
		t.Fatalf("precondition: second Apply minted (%d sink writes); this test is about a run that does not", fx.tokens.count())
	}
	sess, err := fx.st.GetSession(ctx, older.ID)
	if err != nil || sess == nil {
		t.Fatalf("older token's session: %v", err)
	}
	if sess.ExpiresAt == nil || sess.ExpiresAt.After(time.Now().Add(RotationOverlap+time.Minute)) {
		t.Errorf("an executor token older than the newest still expires at %v; every run must cap it to the %s overlap", sess.ExpiresAt, RotationOverlap)
	}
	if _, err := brokercore.NewStoreSessionResolver(fx.st).ResolveForProxy(ctx, delivered, "example-integration"); err != nil {
		t.Errorf("the delivered (newest) token was cut off: %v", err)
	}
}

// ambiguousSink stores the token and then reports an error, as a write that
// landed but whose response was lost would.
type ambiguousSink struct {
	*fakeTokenSink
	failOnce bool
}

func (a *ambiguousSink) PutToken(ctx context.Context, agent, token string, exp time.Time) error {
	if err := a.fakeTokenSink.PutToken(ctx, agent, token, exp); err != nil {
		return err
	}
	if a.failOnce {
		a.failOnce = false
		return errors.New("fake sink: request timed out after the write was accepted")
	}
	return nil
}

// If PutToken fails ambiguously, the run must not delete the token, because
// it may be the one now in the sink: the token the sink holds stays valid.
func TestFinalFix_AmbiguousSinkFailureKeepsDeliveredTokenValid(t *testing.T) {
	ctx := context.Background()
	tdb := newSQLiteTestDB(t)
	fx := newFixture(t, tdb.Open(t), docJSON)
	sink := &ambiguousSink{fakeTokenSink: fx.tokens, failOnce: true}
	fx.opts.Tokens = sink

	_ = Apply(ctx, fx.opts) // may report the sink error
	if fx.tokens.count() == 0 {
		t.Fatal("precondition: the fake sink never received a token")
	}
	tok, _, err := sink.GetToken(ctx, "example-executor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := brokercore.NewStoreSessionResolver(fx.st).ResolveForProxy(ctx, tok, "example-integration"); err != nil {
		t.Errorf("the token in the sink was deleted after an ambiguous PutToken failure; the executor is cut off: %v", err)
	}

	// A later run converges on one valid delivered token.
	if err := Apply(ctx, fx.opts); err != nil {
		t.Fatalf("follow-up Apply: %v", err)
	}
	tok, _, _ = sink.GetToken(ctx, "example-executor")
	if _, err := brokercore.NewStoreSessionResolver(fx.st).ResolveForProxy(ctx, tok, "example-integration"); err != nil {
		t.Errorf("after the follow-up run the delivered token does not authenticate: %v", err)
	}

	// Count valid sessions, which kills both wrong fixes: "never cap" leaves
	// an extra long-lived session, and "cap on error" shortens the
	// delivered one. Exactly one session (the delivered token) may stay
	// valid beyond the 15-minute grace window, and at most two are valid.
	a, err := fx.st.GetAgentByName(ctx, "example-executor")
	if err != nil || a == nil {
		t.Fatalf("executor agent: %v", err)
	}
	rows := agentSessions(t, tdb, a.ID)
	if n := countValid(rows, time.Now()); n > 2 {
		t.Errorf("%d executor sessions are valid after the follow-up run; at most two", n)
	}
	long := 0
	for _, r := range rows {
		if r.exp.IsZero() || r.exp.After(time.Now().Add(15*time.Minute)) {
			long++
			if r.id != tokenHash(tok) {
				t.Errorf("a session other than the delivered token stays valid beyond the grace window (expires %v)", r.exp)
			}
		}
	}
	if long != 1 {
		t.Errorf("%d sessions valid beyond now+15m after the follow-up run; want exactly 1 (the delivered token)", long)
	}

	// Known positive for the counter: an extra full-TTL session ("never
	// cap") is seen as a second long-lived session, and capping the
	// delivered token ("cap on error") leaves none.
	extraExp := time.Now().Add(720 * time.Hour)
	if _, err := fx.st.CreateAgentToken(ctx, a.ID, &extraExp); err != nil {
		t.Fatal(err)
	}
	if n := countValid(agentSessions(t, tdb, a.ID), time.Now().Add(15*time.Minute)); n != 2 {
		t.Fatalf("counter self-check: an extra full-TTL session is counted as %d long-lived sessions, want 2", n)
	}
	capper, ok := fx.st.(TokenCapper)
	if !ok {
		t.Fatal("store does not implement TokenCapper")
	}
	if _, err := capper.CapAgentTokenExpiry(ctx, a.ID, "not-a-real-token", time.Now().Add(RotationOverlap)); err != nil {
		t.Fatal(err)
	}
	if n := countValid(agentSessions(t, tdb, a.ID), time.Now().Add(15*time.Minute)); n != 0 {
		t.Fatalf("counter self-check: after capping every session, %d are counted as long-lived, want 0", n)
	}
}

// Policy mode: Validate requires strict_deny on every service, so the vault
// is set to unmatched_host_policy=deny.
func TestFinalFix_ValidateRequiresStrictDenyInPolicyMode(t *testing.T) {
	t.Setenv("AGENT_VAULT_SERVICE_POLICY", "readonly-allowlist")
	doc := &Document{
		Vaults: []string{"example-integration"},
		Services: []ServiceSpec{{
			Vault: "example-integration", Name: "notion-read", Host: "api.notion.com", Path: "/v1/pages/{id}",
			Methods: []string{"GET"}, AuthType: "bearer", CredentialKey: "NOTION_TOKEN", StrictDeny: false,
		}},
		Agents: []AgentSpec{{Name: "example-executor", InstanceRole: "no-access",
			VaultRoles: map[string]string{"example-integration": "proxy"}, ExpiresIn: "720h"}},
	}
	if err := Validate(doc, "example-executor"); err == nil {
		t.Error("Validate accepted a service without strict_deny while the policy mode is active")
	}
	doc.Services[0].StrictDeny = true
	if err := Validate(doc, "example-executor"); err != nil {
		t.Errorf("control: Validate refused strict_deny=true: %v", err)
	}
}
