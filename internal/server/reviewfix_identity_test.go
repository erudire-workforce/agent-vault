//go:build reviewfix

// Review-fix tests for the credential identity record (blocker 1).
// Run with: go test -tags reviewfix ./internal/server/
package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/identity"
	"github.com/Infisical/agent-vault/internal/store"
)

// usersMeFor returns a users/me body whose workspace depends on the bearer,
// so each credential value has its own digest.
func usersMeFor(auth string) string {
	ws := "Workspace " + strings.TrimPrefix(auth, "Bearer ")
	return `{"object":"user","id":"u","name":"example-integration","type":"bot",
 "bot":{"owner":{"type":"workspace","workspace":true},"workspace_name":"` + ws + `","workspace_id":"ws-00000000-test"}}`
}

func digestFor(t *testing.T, token string) string {
	t.Helper()
	d, err := identity.NotionDigest([]byte(usersMeFor("Bearer " + token)))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

type identityRig struct {
	t    *testing.T
	st   *store.SQLStore
	srv  *Server
	vid  string
	key  []byte
	gate chan struct{} // when non-nil, users/me blocks until it is closed
	mu   sync.Mutex
	hits int
	in   chan string // receives the Authorization of every users/me call
}

func newIdentityRig(t *testing.T) *identityRig {
	t.Helper()
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")
	r := &identityRig{t: t, in: make(chan string, 16)}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/users/me" {
			http.NotFound(w, req)
			return
		}
		auth := req.Header.Get("Authorization")
		r.mu.Lock()
		r.hits++
		gate := r.gate
		r.mu.Unlock()
		r.in <- auth
		if gate != nil {
			<-gate
		}
		_, _ = io.WriteString(w, usersMeFor(auth))
	}))
	t.Cleanup(up.Close)
	old := identityProbeBaseURL
	identityProbeBaseURL = up.URL
	t.Cleanup(func() { identityProbeBaseURL = old })

	st, err := store.Open(filepath.Join(t.TempDir(), "av.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	r.st = st
	r.key = make([]byte, 32)
	r.srv = newTestServer(withStore(st), withEncKey(r.key))
	v, err := st.CreateVault(context.Background(), "identity-vault")
	if err != nil {
		t.Fatal(err)
	}
	r.vid = v.ID
	if _, err := st.SetBrokerConfig(context.Background(), v.ID,
		`[{"name":"notion-read","host":"api.notion.com/v1/pages/{id}","methods":["GET"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}]`); err != nil {
		t.Fatal(err)
	}
	return r
}

// set writes val for the row's next version (or version 1 after a delete).
func (r *identityRig) set(val string) {
	r.t.Helper()
	ctx := context.Background()
	next := uint64(1)
	if cur, err := r.st.GetCredential(ctx, r.vid, "NOTION_TOKEN"); err == nil && cur != nil {
		next = cur.Version + 1
	}
	ct, n, err := store.CredentialValueAAD(r.vid, "NOTION_TOKEN", next).Seal([]byte(val), r.key)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.st.SetCredentialVersion(ctx, r.vid, "NOTION_TOKEN", ct, n, next); err != nil {
		r.t.Fatal(err)
	}
}

func (r *identityRig) identity() string {
	r.t.Helper()
	res, err := r.srv.CredentialProvider().Inject(brokercore.WithRequestMethod(context.Background(), "GET"),
		r.vid, "api.notion.com", 443, "/v1/pages/abc")
	if err != nil {
		r.t.Fatal(err)
	}
	return res.CredentialIdentity
}

// Key K holds value A at version 1 with A's identity recorded. K is deleted
// through an approved proposal and recreated with value B, again at version
// 1. Inject must not report A's digest for B.
func TestReviewFix_Identity_ProposalDeleteThenRecreate(t *testing.T) {
	r := newIdentityRig(t)
	ctx := context.Background()
	r.set("SENTINEL-RF-A")
	if err := r.srv.runIdentityProbe(ctx, r.vid, "NOTION_TOKEN"); err != nil {
		t.Fatal(err)
	}
	<-r.in
	digA := digestFor(t, "SENTINEL-RF-A")
	if got := r.identity(); got != digA {
		t.Fatalf("control: identity %q, want A's digest", got)
	}

	sess, err := r.st.CreateScopedSession(ctx, store.CreateScopedSessionParams{VaultID: r.vid, VaultRole: "proxy"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.st.CreateProposal(ctx, r.vid, sess.ID, `[]`, `[{"action":"delete","key":"NOTION_TOKEN"}]`, "delete", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	bc, _ := r.st.GetBrokerConfig(ctx, r.vid)
	if err := r.st.ApplyProposal(ctx, r.vid, p.ID, bc.ServicesJSON, nil, []string{"NOTION_TOKEN"}, nil); err != nil {
		t.Fatal(err)
	}
	r.set("SENTINEL-RF-B") // version 1 again
	if c, _ := r.st.GetCredential(ctx, r.vid, "NOTION_TOKEN"); c == nil || c.Version != 1 {
		t.Fatalf("precondition: recreated row not at version 1: %+v", c)
	}
	if got := r.identity(); got == digA {
		t.Fatal("Inject reports the deleted value A's identity for the recreated value B")
	}
}

// A probe that is in flight while the credential is deleted and recreated
// must not attach its (old) digest to the new row.
func TestReviewFix_Identity_InFlightProbeAfterDeleteAndRecreate(t *testing.T) {
	r := newIdentityRig(t)
	ctx := context.Background()
	r.set("SENTINEL-RF-A")
	gate := make(chan struct{})
	r.mu.Lock()
	r.gate = gate
	r.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- r.srv.runIdentityProbe(ctx, r.vid, "NOTION_TOKEN") }()
	select {
	case <-r.in:
	case <-time.After(5 * time.Second):
		t.Fatal("probe never reached users/me")
	}

	if err := r.st.DeleteCredential(ctx, r.vid, "NOTION_TOKEN"); err != nil {
		t.Fatal(err)
	}
	r.set("SENTINEL-RF-B") // version 1 again, new row
	close(gate)
	<-done

	if got := r.identity(); got == digestFor(t, "SENTINEL-RF-A") {
		t.Fatal("a probe that ran with value A recorded A's digest on the recreated row holding B")
	}
}

// A probe requested while another is running for the same key must be
// re-queued, not dropped as busy: the newer value must end up with its own
// identity.
func TestReviewFix_Identity_BusyProbeRequeuesNext(t *testing.T) {
	r := newIdentityRig(t)
	r.set("SENTINEL-RF-A")
	gate := make(chan struct{})
	r.mu.Lock()
	r.gate = gate
	r.mu.Unlock()
	r.srv.scheduleIdentityProbe(r.vid, "NOTION_TOKEN")
	select {
	case <-r.in:
	case <-time.After(5 * time.Second):
		t.Fatal("first probe never reached users/me")
	}

	r.set("SENTINEL-RF-B") // version 2
	r.srv.scheduleIdentityProbe(r.vid, "NOTION_TOKEN")
	r.mu.Lock()
	r.gate = nil
	r.mu.Unlock()
	close(gate)

	want := digestFor(t, "SENTINEL-RF-B")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if r.identity() == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the probe requested while another was running was dropped: identity for value B never recorded (got %q)", r.identity())
}

// The record must be bound to the credential row's ID as well as its
// version, so no recreated row can match it by version alone.
func TestReviewFix_Identity_RecordBindsRowIDAndVersion(t *testing.T) {
	r := newIdentityRig(t)
	ctx := context.Background()
	r.set("SENTINEL-RF-A")
	if err := r.srv.runIdentityProbe(ctx, r.vid, "NOTION_TOKEN"); err != nil {
		t.Fatal(err)
	}
	c, err := r.st.GetCredential(ctx, r.vid, "NOTION_TOKEN")
	if err != nil || c == nil || c.ID == "" {
		t.Fatalf("credential row: %v", err)
	}
	rec, _ := r.st.GetVaultSetting(ctx, r.vid, brokercore.IdentitySettingKey("NOTION_TOKEN"))
	if !strings.Contains(rec, c.ID) {
		t.Fatalf("identity record %q does not bind the credential row ID %s", rec, c.ID)
	}
}
