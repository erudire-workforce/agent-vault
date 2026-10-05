//go:build kmsaad

// Shared harness for the server-level kmsaad tests: a real store (Postgres
// and SQLite via forEachBackend), a real owner session, and every log
// channel the server can write to captured in memory.
package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/requestlog"
	"github.com/Infisical/agent-vault/internal/store"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type captureSink struct {
	mu   sync.Mutex
	recs []requestlog.Record
}

func (c *captureSink) Record(_ context.Context, r requestlog.Record) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, r)
}

func (c *captureSink) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, _ := json.Marshal(c.recs)
	return string(b)
}

type kenv struct {
	t          *testing.T
	tdb        testDB
	st         store.Store
	srv        *Server
	encKey     []byte
	ownerID    string
	ownerToken string
	vaultID    string

	serverLog *syncBuffer // srv.logger
	slogDef   *syncBuffer // slog.Default()
	stdLog    *syncBuffer // log.Printf
	stderr    *os.File    // os.Stderr redirect target
	sink      *captureSink
	responses *syncBuffer // every response body and Location header seen by do()
}

func newKEnv(t *testing.T, tdb testDB) *kenv {
	t.Helper()
	// Must be set before New(): it decides the OAuth token client's SSRF guard.
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")
	ctx := context.Background()
	st := tdb.Open(t)
	v, err := st.GetVault(ctx, store.DefaultVault)
	if err != nil || v == nil {
		t.Fatalf("default vault: %v", err)
	}
	u, err := st.RegisterFirstUser(ctx, "owner@example.test", []byte("hash"), []byte("salt"), v.ID, 1, 1024, 1)
	if err != nil {
		t.Fatalf("RegisterFirstUser: %v", err)
	}
	sess, err := st.CreateUserSession(ctx, store.CreateUserSessionParams{UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour), IdleTTL: time.Hour})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	e := &kenv{
		t: t, tdb: tdb, st: st, ownerID: u.ID, ownerToken: sess.ID, vaultID: v.ID,
		serverLog: &syncBuffer{}, slogDef: &syncBuffer{}, stdLog: &syncBuffer{}, sink: &captureSink{}, responses: &syncBuffer{},
	}
	e.encKey = make([]byte, 32)
	_, _ = rand.Read(e.encKey)
	logger := slog.New(slog.NewJSONHandler(e.serverLog, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e.srv = New("127.0.0.1:0", st, e.encKey, nil, true, "http://127.0.0.1:14321", logger)
	e.srv.AttachLogSink(e.sink)

	oldDefault := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(e.slogDef, &slog.HandlerOptions{Level: slog.LevelDebug})))
	oldLogOut := log.Writer()
	log.SetOutput(e.stdLog)
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = f
	e.stderr = f
	t.Cleanup(func() {
		slog.SetDefault(oldDefault)
		log.SetOutput(oldLogOut)
		os.Stderr = oldStderr
		_ = f.Close()
	})
	return e
}

func (e *kenv) do(method, path, body, token string, hdr ...string) *httptest.ResponseRecorder {
	e.t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.srv.httpServer.Handler.ServeHTTP(rec, req)
	_, _ = e.responses.Write([]byte(rec.Header().Get("Location") + "\n" + rec.Body.String() + "\n"))
	return rec
}

func (e *kenv) setCreds(vault string, kv map[string]string) {
	e.t.Helper()
	b, _ := json.Marshal(map[string]any{"vault": vault, "credentials": kv})
	if rec := e.do(http.MethodPost, "/v1/credentials", string(b), e.ownerToken); rec.Code != http.StatusOK {
		e.t.Fatalf("POST /v1/credentials: %d %s", rec.Code, rec.Body.String())
	}
}

// reveal returns (status, value) of GET /v1/credentials?reveal=true&key=.
func (e *kenv) reveal(vault, key string) (int, string) {
	e.t.Helper()
	rec := e.do(http.MethodGet, "/v1/credentials?vault="+vault+"&reveal=true&key="+key, "", e.ownerToken)
	if rec.Code != http.StatusOK {
		return rec.Code, ""
	}
	var resp credentialsListResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Credentials) != 1 {
		return rec.Code, ""
	}
	return rec.Code, resp.Credentials[0].Value
}

func (e *kenv) vaultIDByName(name string) string {
	e.t.Helper()
	v, err := e.st.GetVault(context.Background(), name)
	if err != nil || v == nil {
		e.t.Fatalf("vault %q: %v", name, err)
	}
	return v.ID
}

// channels returns every captured output channel by name.
func (e *kenv) channels() map[string]string {
	_ = e.stderr.Sync()
	se, _ := os.ReadFile(e.stderr.Name())
	return map[string]string{
		"server logger":     e.serverLog.String(),
		"slog default":      e.slogDef.String(),
		"std log":           e.stdLog.String(),
		"stderr":            string(se),
		"request log sink":  e.sink.String(),
		"http responses":    e.responses.String(),
	}
}

// findSentinels returns "channel: sentinel" for every sentinel present.
func findSentinels(chs map[string]string, sentinels []string, skip ...string) []string {
	var hits []string
	for name, text := range chs {
		skipped := false
		for _, s := range skip {
			if s == name {
				skipped = true
			}
		}
		if skipped {
			continue
		}
		for _, s := range sentinels {
			if strings.Contains(text, s) {
				hits = append(hits, name+": "+s)
			}
		}
	}
	return hits
}
