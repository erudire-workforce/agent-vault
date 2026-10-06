// Contract of package bootstrap (fork: declarative bootstrap, token
// delivery and rotation).
//
// API:
//
//	type Document struct {
//	    Vaults   []string      `json:"vaults"`
//	    Services []ServiceSpec `json:"services"`
//	    Agents   []AgentSpec   `json:"agents"`
//	}
//	type ServiceSpec struct {
//	    Vault, Name, Host, Path string
//	    Methods       []string `json:"methods"`
//	    AuthType      string   `json:"auth_type"`      // "bearer", ...
//	    CredentialKey string   `json:"credential_key"`
//	    StrictDeny    bool     `json:"strict_deny"`    // vault unmatched_host_policy=deny
//	}
//	type AgentSpec struct {
//	    Name         string            `json:"name"`
//	    InstanceRole string            `json:"instance_role"`
//	    VaultRoles   map[string]string `json:"vault_roles"`
//	    ExpiresIn    string            `json:"expires_in"` // Go duration, e.g. "720h"
//	}
//	type SecretsSource interface{ BootstrapDocument(ctx context.Context) ([]byte, error) }
//	type TokenSink interface {
//	    PutToken(ctx context.Context, agent, token string, expiresAt time.Time) error
//	    GetToken(ctx context.Context, agent string) (token string, expiresAt time.Time, err error)
//	}
//	type CertSink interface{ PutCACert(ctx context.Context, certPEM []byte) error }
//	type Options struct {
//	    Store    store.Store
//	    Source   SecretsSource
//	    Tokens   TokenSink
//	    Certs    CertSink
//	    RootPEM  func() []byte   // MITM CA certificate (public part only)
//	    Executor string          // agent whose token is delivered to Tokens
//	    Now      func() time.Time
//	    Logger   *slog.Logger
//	}
//	const RotateBefore = 7 * 24 * time.Hour
//	const RotationOverlap = 10 * time.Minute
//	func Apply(ctx context.Context, o Options) error
//	func RotateIfDue(ctx context.Context, o Options) (rotated bool, err error)
//	func RunRotationLoop(ctx context.Context, o Options, tick <-chan time.Time)
//
// Compiled-in limits (refused even in an otherwise valid document): executor
// instance role other than "no-access"; any agent instance role "owner" or
// "member"; any vault role other than "proxy" for the executor; a service on
// api.notion.com whose methods include anything but GET (or is unset).
package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/store"
)

type fakeSource struct{ doc []byte }

func (f fakeSource) BootstrapDocument(context.Context) ([]byte, error) { return f.doc, nil }

type sinkWrite struct {
	token          string
	expiresAt      time.Time
	oldStillValid  bool // was the previously delivered token still accepted at write time?
}

type fakeTokenSink struct {
	mu        sync.Mutex
	writes    []sinkWrite
	failNext  int
	readErr   error
	resolver  *brokercore.StoreSessionResolver
	vaultHint string
}

func (f *fakeTokenSink) PutToken(ctx context.Context, _ string, token string, exp time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext > 0 {
		f.failNext--
		return errors.New("fake sink: PutSecretValue unavailable")
	}
	w := sinkWrite{token: token, expiresAt: exp}
	if n := len(f.writes); n > 0 && f.resolver != nil {
		_, err := f.resolver.ResolveForProxy(ctx, f.writes[n-1].token, f.vaultHint)
		w.oldStillValid = err == nil
	}
	f.writes = append(f.writes, w)
	return nil
}

func (f *fakeTokenSink) GetToken(context.Context, string) (string, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return "", time.Time{}, f.readErr
	}
	if len(f.writes) == 0 {
		return "", time.Time{}, errors.New("fake sink: secret not found")
	}
	w := f.writes[len(f.writes)-1]
	return w.token, w.expiresAt, nil
}

func (f *fakeTokenSink) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

func (f *fakeTokenSink) last() sinkWrite {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes[len(f.writes)-1]
}

type fakeCertSink struct {
	mu   sync.Mutex
	puts [][]byte
}

func (f *fakeCertSink) PutCACert(_ context.Context, b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts = append(f.puts, append([]byte(nil), b...))
	return nil
}

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *logBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

const docJSON = `{
  "vaults": ["example-integration"],
  "services": [
    {"vault":"example-integration","name":"notion-read","host":"api.notion.com","path":"/v1/pages/{id}","methods":["GET"],
     "auth_type":"bearer","credential_key":"NOTION_TOKEN","strict_deny":true}
  ],
  "agents": [
    {"name":"example-executor","instance_role":"no-access","vault_roles":{"example-integration":"proxy"},"expires_in":"720h"}
  ]
}`

type fixture struct {
	st     store.Store
	tokens *fakeTokenSink
	certs  *fakeCertSink
	logs   *logBuf
	opts   Options
	now    time.Time
}

func newFixture(t *testing.T, st store.Store, doc string) *fixture {
	t.Helper()
	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	caProv, err := ca.New(dek, ca.Options{Dir: filepath.Join(t.TempDir(), "ca")})
	if err != nil {
		t.Fatal(err)
	}
	fx := &fixture{st: st, certs: &fakeCertSink{}, logs: &logBuf{}, now: time.Now()}
	fx.tokens = &fakeTokenSink{resolver: brokercore.NewStoreSessionResolver(st), vaultHint: "example-integration"}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(fx.logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	fx.opts = Options{
		Store: st, Source: fakeSource{doc: []byte(doc)}, Tokens: fx.tokens, Certs: fx.certs,
		RootPEM: caProv.RootPEM, Executor: "example-executor",
		Now:    func() time.Time { return fx.now },
		Logger: slog.New(slog.NewJSONHandler(fx.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	return fx
}

func snapshot(t *testing.T, st store.Store) string {
	t.Helper()
	ctx := context.Background()
	vs, _ := st.ListVaults(ctx)
	as, _ := st.ListAllAgents(ctx)
	var parts []string
	for _, v := range vs {
		bc, _ := st.GetBrokerConfig(ctx, v.ID)
		svc := ""
		if bc != nil {
			svc = bc.ServicesJSON
		}
		parts = append(parts, "vault:"+v.Name+" services:"+svc)
	}
	for _, a := range as {
		parts = append(parts, "agent:"+a.Name+" role:"+a.Role)
	}
	return strings.Join(parts, "\n")
}

func TestKMSAAD_Bootstrap_ApplyIsIdempotent(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		ctx := context.Background()
		fx := newFixture(t, tdb.Open(t), docJSON)
		if err := Apply(ctx, fx.opts); err != nil {
			t.Fatalf("first Apply: %v", err)
		}
		first := snapshot(t, fx.st)
		if err := Apply(ctx, fx.opts); err != nil {
			t.Fatalf("second Apply: %v", err)
		}
		if second := snapshot(t, fx.st); second != first {
			t.Fatalf("second Apply changed state:\nfirst:\n%s\nsecond:\n%s", first, second)
		}
		if strings.Count(first, "vault:example-integration") != 1 || strings.Count(first, "agent:example-executor") != 1 ||
			strings.Count(first, `"notion-read"`) != 1 {
			t.Fatalf("duplicate or missing vault/service/agent:\n%s", first)
		}
		if fx.tokens.count() != 1 {
			t.Fatalf("token minted %d times over two Applies with a valid delivered token; want 1", fx.tokens.count())
		}
	})
}

func TestKMSAAD_Bootstrap_TokenDeliveredWithExpiry_NotLogged(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		ctx := context.Background()
		fx := newFixture(t, tdb.Open(t), docJSON)
		// Known positive for the scan: a planted sentinel is found.
		fx.opts.Logger.Info("plant", "v", "SENTINEL-AV-TEST-1001")
		if !strings.Contains(fx.logs.String(), "SENTINEL-AV-TEST-1001") {
			t.Fatal("log scanner cannot see the bootstrap logger")
		}
		if err := Apply(ctx, fx.opts); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if fx.tokens.count() != 1 {
			t.Fatalf("token sink writes = %d, want 1", fx.tokens.count())
		}
		w := fx.tokens.last()
		if w.expiresAt.IsZero() || !w.expiresAt.After(fx.now) || w.expiresAt.After(fx.now.Add(721*time.Hour)) {
			t.Fatalf("delivered expiry %v not within (now, now+720h]", w.expiresAt)
		}
		scope, err := brokercore.NewStoreSessionResolver(fx.st).ResolveForProxy(ctx, w.token, "example-integration")
		if err != nil || scope.VaultRole != "proxy" {
			t.Fatalf("delivered token does not authenticate as proxy on example-integration: %+v %v", scope, err)
		}
		if strings.Contains(fx.logs.String(), w.token) {
			t.Fatal("minted executor token appears in logs")
		}
	})
}

func TestKMSAAD_Bootstrap_RotationInsideWindow_SinkBeforeRevoke_Overlap(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		ctx := context.Background()
		fx := newFixture(t, tdb.Open(t), docJSON)
		if err := Apply(ctx, fx.opts); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		old := fx.tokens.last()

		fx.now = old.expiresAt.Add(-8 * 24 * time.Hour) // outside the 7-day window
		if rotated, err := RotateIfDue(ctx, fx.opts); err != nil || rotated {
			t.Fatalf("rotated outside the window: rotated=%v err=%v", rotated, err)
		}
		fx.now = old.expiresAt.Add(-6 * 24 * time.Hour) // inside
		rotatedAt := time.Now()
		if rotated, err := RotateIfDue(ctx, fx.opts); err != nil || !rotated {
			t.Fatalf("no rotation inside the 7-day window: rotated=%v err=%v", rotated, err)
		}
		nw := fx.tokens.last()
		if nw.token == old.token {
			t.Fatal("rotation delivered the same token")
		}
		if !nw.oldStillValid {
			t.Fatal("old session was revoked before the new token reached the sink")
		}
		res := brokercore.NewStoreSessionResolver(fx.st)
		if _, err := res.ResolveForProxy(ctx, old.token, "example-integration"); err != nil {
			t.Fatalf("old token refused immediately after rotation; must survive the 10-minute overlap: %v", err)
		}
		sess, err := fx.st.GetSession(ctx, old.token)
		if err != nil || sess == nil || sess.ExpiresAt == nil {
			t.Fatalf("old session missing or without expiry during overlap: %v", err)
		}
		if d := sess.ExpiresAt.Sub(rotatedAt); d < 9*time.Minute || d > 11*time.Minute {
			t.Fatalf("old session expires %v after rotation; want ~10m overlap then refusal", d)
		}
	})
}

func TestKMSAAD_Bootstrap_RotationRunsFromTimer(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		fx := newFixture(t, tdb.Open(t), docJSON)
		if err := Apply(ctx, fx.opts); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		old := fx.tokens.last()
		fx.now = old.expiresAt.Add(-24 * time.Hour)
		tick := make(chan time.Time)
		done := make(chan struct{})
		go func() { RunRotationLoop(ctx, fx.opts, tick); close(done) }()
		tick <- fx.now
		deadline := time.Now().Add(5 * time.Second)
		for fx.tokens.count() < 2 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		<-done
		if fx.tokens.count() < 2 {
			t.Fatal("a timer tick inside the rotation window did not rotate the token")
		}
	})
}

func TestKMSAAD_Bootstrap_ConcurrentBootstrapsMintOnce(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		if tdb.Kind != "postgres" {
			t.Skip("cross-process LockVault exists only on Postgres (advisory lock); SQLite deployments are single-process")
		}
		ctx := context.Background()
		fxA := newFixture(t, tdb.Open(t), docJSON)
		fxB := newFixture(t, tdb.Open(t), docJSON) // a second "task" with its own pool
		fxB.opts.Tokens = fxA.tokens
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, o := range []Options{fxA.opts, fxB.opts} {
			wg.Add(1)
			go func(i int, o Options) { defer wg.Done(); errs[i] = Apply(ctx, o) }(i, o)
		}
		wg.Wait()
		if errs[0] != nil || errs[1] != nil {
			t.Fatalf("concurrent Apply errors: %v / %v", errs[0], errs[1])
		}
		if n := fxA.tokens.count(); n != 1 {
			t.Fatalf("two concurrent bootstraps minted %d tokens; want exactly 1", n)
		}
	})
}

func TestKMSAAD_Bootstrap_MintsWhenSecretUnreadable(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		ctx := context.Background()
		fx := newFixture(t, tdb.Open(t), docJSON)
		if err := Apply(ctx, fx.opts); err != nil {
			t.Fatal(err)
		}
		fx.tokens.readErr = errors.New("fake sink: AccessDeniedException")
		if err := Apply(ctx, fx.opts); err != nil {
			t.Fatalf("Apply with unreadable secret: %v", err)
		}
		fx.tokens.readErr = nil
		if fx.tokens.count() != 2 {
			t.Fatalf("token writes = %d; an unreadable delivered secret must trigger a re-mint", fx.tokens.count())
		}
	})
}

// Crash between the DB commit (new session) and the sink write: the next
// bootstrap must notice the delivered token is stale and re-mint.
func TestKMSAAD_Bootstrap_ReMintAfterCrashBetweenCommitAndSink(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		ctx := context.Background()
		fx := newFixture(t, tdb.Open(t), docJSON)
		fx.tokens.failNext = 1
		if err := Apply(ctx, fx.opts); err == nil {
			t.Fatal("Apply reported success although the token never reached the sink")
		}
		if err := Apply(ctx, fx.opts); err != nil {
			t.Fatalf("Apply after simulated crash: %v", err)
		}
		if fx.tokens.count() != 1 {
			t.Fatalf("token writes = %d after recovery, want 1", fx.tokens.count())
		}
		if _, err := brokercore.NewStoreSessionResolver(fx.st).ResolveForProxy(ctx, fx.tokens.last().token, "example-integration"); err != nil {
			t.Fatalf("token delivered after recovery does not authenticate: %v", err)
		}
	})
}

func TestKMSAAD_Bootstrap_CompiledInLimitsRefused(t *testing.T) {
	cases := map[string]string{
		"executor vault role member": strings.Replace(docJSON, `"example-integration":"proxy"`, `"example-integration":"member"`, 1),
		"executor vault role admin":  strings.Replace(docJSON, `"example-integration":"proxy"`, `"example-integration":"admin"`, 1),
		"agent instance role owner":  strings.Replace(docJSON, `"instance_role":"no-access"`, `"instance_role":"owner"`, 1),
		"agent instance role member": strings.Replace(docJSON, `"instance_role":"no-access"`, `"instance_role":"member"`, 1),
		"notion PATCH method":        strings.Replace(docJSON, `"methods":["GET"]`, `"methods":["GET","PATCH"]`, 1),
		"notion POST method":         strings.Replace(docJSON, `"methods":["GET"]`, `"methods":["POST"]`, 1),
		"notion methods unset":       strings.Replace(docJSON, `"methods":["GET"],`, ``, 1),
	}
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		for name, doc := range cases {
			t.Run(name, func(t *testing.T) {
				fx := newFixture(t, tdb.fresh(t).Open(t), doc)
				if err := Apply(context.Background(), fx.opts); err == nil {
					t.Fatal("Apply accepted a document that breaks a compiled-in limit")
				}
				if fx.tokens.count() != 0 {
					t.Fatal("a token was minted for a refused document")
				}
				if a, _ := fx.st.GetAgentByName(context.Background(), "example-executor"); a != nil {
					t.Fatal("agent created from a refused document")
				}
			})
		}
	})
}

func TestKMSAAD_Bootstrap_CACertPublished_PrivateKeyNever(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		fx := newFixture(t, tdb.Open(t), docJSON)
		if err := Apply(context.Background(), fx.opts); err != nil {
			t.Fatal(err)
		}
		if len(fx.certs.puts) == 0 {
			t.Fatal("CA certificate was not published")
		}
		for _, p := range fx.certs.puts {
			if !bytes.Equal(p, fx.opts.RootPEM()) {
				t.Error("published bytes differ from the CA root certificate PEM")
			}
			rest := p
			for {
				var blk *pem.Block
				blk, rest = pem.Decode(rest)
				if blk == nil {
					break
				}
				if blk.Type != "CERTIFICATE" {
					t.Errorf("published a %q PEM block", blk.Type)
				}
			}
			if bytes.Contains(p, []byte("PRIVATE KEY")) {
				t.Error("CA private key published")
			}
		}
		for _, w := range fx.tokens.writes {
			if strings.Contains(w.token, "PRIVATE KEY") {
				t.Error("private key material written to the token sink")
			}
		}
		if strings.Contains(fx.logs.String(), "PRIVATE KEY") {
			t.Error("private key material in logs")
		}
	})
}
