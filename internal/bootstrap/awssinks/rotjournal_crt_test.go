// Fork change 17, item 4: PutSecretValue carries the new session's ID as
// its ClientRequestToken, so a retry of the same write is idempotent and a
// later mint never collides with an earlier one. The session ID is the
// stored, non-secret ID (sha256 hex of the raw token, as sessions.id); the
// raw token itself must never be the request token, because request
// parameters are logged by CloudTrail.
package awssinks_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/Infisical/agent-vault/internal/bootstrap"
	"github.com/Infisical/agent-vault/internal/bootstrap/awssinks"
	"github.com/Infisical/agent-vault/internal/store"
)

const crtDoc = `{
  "vaults": ["example-integration"],
  "services": [
    {"vault":"example-integration","name":"notion-read","host":"api.notion.com","path":"/v1/pages/{id}","methods":["GET"],
     "auth_type":"bearer","credential_key":"NOTION_TOKEN","strict_deny":true}
  ],
  "agents": [
    {"name":"example-executor","instance_role":"no-access","vault_roles":{"example-integration":"proxy"},"expires_in":"720h"}
  ]
}`

type crtSource struct{}

func (crtSource) BootstrapDocument(context.Context) ([]byte, error) { return []byte(crtDoc), nil }

type putRecord struct {
	crt    string
	secret string
}

type recordingSecrets struct {
	mu     sync.Mutex
	values map[string]string
	puts   []putRecord
}

func (r *recordingSecrets) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.values[aws.ToString(in.SecretId)]
	if !ok {
		return nil, errors.New("ResourceNotFoundException")
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(v)}, nil
}

func (r *recordingSecrets) PutSecretValue(_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values[aws.ToString(in.SecretId)] = aws.ToString(in.SecretString)
	r.puts = append(r.puts, putRecord{crt: aws.ToString(in.ClientRequestToken), secret: aws.ToString(in.SecretString)})
	return &secretsmanager.PutSecretValueOutput{}, nil
}

func sessionID(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func TestRotJournal_PutSecretValueUsesNewSessionIDAsClientRequestToken(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "av.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rec := &recordingSecrets{values: map[string]string{}}
	now := time.Now()
	o := bootstrap.Options{
		Store: st, Source: crtSource{},
		Tokens:   awssinks.TokenSink{Client: rec, SecretID: "example/executor-token"},
		Executor: "example-executor",
		Now:      func() time.Time { return now },
	}
	if err := bootstrap.Apply(ctx, o); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Second mint: move the clock inside the rotation window.
	var first struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	rec.mu.Lock()
	if len(rec.puts) == 0 {
		rec.mu.Unlock()
		t.Fatal("precondition: no PutSecretValue on first boot")
	}
	_ = json.Unmarshal([]byte(rec.puts[len(rec.puts)-1].secret), &first)
	rec.mu.Unlock()
	exp, err := time.Parse(time.RFC3339, first.ExpiresAt)
	if err != nil {
		t.Fatalf("delivered secret has no expires_at: %v", err)
	}
	now = exp.Add(-bootstrap.RotateBefore + 24*time.Hour)
	if _, err := bootstrap.RotateIfDue(ctx, o); err != nil {
		t.Fatalf("RotateIfDue: %v", err)
	}

	rec.mu.Lock()
	puts := append([]putRecord(nil), rec.puts...)
	rec.mu.Unlock()
	if len(puts) < 2 {
		t.Fatalf("precondition: want two PutSecretValue calls (first boot and rotation), got %d", len(puts))
	}
	seen := map[string]bool{}
	for i, p := range puts {
		var s struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal([]byte(p.secret), &s)
		if p.crt == "" {
			t.Errorf("PutSecretValue %d has no ClientRequestToken", i+1)
			continue
		}
		if s.Token != "" && strings.Contains(p.crt, s.Token) {
			t.Errorf("PutSecretValue %d uses the raw token as its ClientRequestToken", i+1)
		}
		if want := sessionID(s.Token); p.crt != want {
			t.Errorf("PutSecretValue %d ClientRequestToken = %q, want the new session's ID %q", i+1, p.crt, want)
		}
		seen[p.crt] = true
	}
	if len(seen) < 2 {
		t.Error("two different mints shared one ClientRequestToken")
	}
}
