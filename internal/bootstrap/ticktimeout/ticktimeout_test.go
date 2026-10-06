// Non-blocking review item: each rotation-loop tick runs under its own
// timeout, so a hung token sink cannot hold the bootstrap lock forever.
//
// API: bootstrap.RotationTickTimeout, a package variable (time.Duration)
// bounding one tick.
package ticktimeout_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/bootstrap"
	"github.com/Infisical/agent-vault/internal/store"
)

const doc = `{"vaults":["example-integration"],
 "services":[{"vault":"example-integration","name":"notion-read","host":"api.notion.com","path":"/v1/pages/{id}","methods":["GET"],
   "auth_type":"bearer","credential_key":"NOTION_TOKEN","strict_deny":true}],
 "agents":[{"name":"example-executor","instance_role":"no-access","vault_roles":{"example-integration":"proxy"},"expires_in":"720h"}]}`

type source struct{}

func (source) BootstrapDocument(context.Context) ([]byte, error) { return []byte(doc), nil }

// sink delivers normally until hang is set; then PutToken blocks until its
// context ends (as the AWS SDK does), and never on its own.
type sink struct {
	mu   sync.Mutex
	tok  string
	exp  time.Time
	hang bool
}

func (s *sink) PutToken(ctx context.Context, _ string, token string, exp time.Time) error {
	s.mu.Lock()
	hang := s.hang
	s.mu.Unlock()
	if hang {
		<-ctx.Done()
		return ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tok, s.exp = token, exp
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

func TestReviewFix_RotationTickHasTimeout(t *testing.T) {
	old := bootstrap.RotationTickTimeout
	bootstrap.RotationTickTimeout = 300 * time.Millisecond
	t.Cleanup(func() { bootstrap.RotationTickTimeout = old })

	st, err := store.Open(filepath.Join(t.TempDir(), "av.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sk := &sink{}
	now := time.Now()
	var nowMu sync.Mutex
	o := bootstrap.Options{
		Store: st, Source: source{}, Tokens: sk, Executor: "example-executor",
		Now: func() time.Time { nowMu.Lock(); defer nowMu.Unlock(); return now },
	}
	if err := bootstrap.Apply(context.Background(), o); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	_, exp, _ := sk.GetToken(context.Background(), "")
	nowMu.Lock()
	now = exp.Add(-24 * time.Hour) // inside the rotation window
	nowMu.Unlock()
	sk.mu.Lock()
	sk.hang = true
	sk.mu.Unlock()

	loopCtx, stop := context.WithCancel(context.Background())
	defer stop()
	tick := make(chan time.Time, 1)
	go bootstrap.RunRotationLoop(loopCtx, o, tick)
	tick <- now

	time.Sleep(100 * time.Millisecond) // let the tick take the lock and hang
	sk.mu.Lock()
	sk.hang = false
	sk.mu.Unlock()

	done := make(chan error, 1)
	go func() { _, err := bootstrap.RotateIfDue(context.Background(), o); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RotateIfDue after the hung tick: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a hung token sink kept the bootstrap lock: a second rotation could not run 3s after a 300ms tick timeout")
	}
}
