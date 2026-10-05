//go:build kmsaad

// Fork policy tests on a real store, through the HTTP API (and, for whoami,
// through a real MITM proxy listener). Several of these already pass at
// v0.40.0; they are regression guards and are listed as such in
// internal/crypto/FAILURE_MODES_KMS_AAD.md.
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/requestlog"
	"github.com/Infisical/agent-vault/internal/store"
)

func scopedParams(vaultID string) store.CreateScopedSessionParams {
	exp := time.Now().Add(time.Hour)
	return store.CreateScopedSessionParams{VaultID: vaultID, VaultRole: "proxy", ExpiresAt: &exp}
}

// executor creates the agent shape the fork uses: instance role no-access,
// vault role proxy on default, finite expiry.
func (e *kenv) executor(name string, exp *time.Time) string {
	e.t.Helper()
	_, sess, err := e.st.CreateAgentWithGrantsAndToken(context.Background(), name, e.ownerID, "no-access",
		[]store.AgentVaultGrantSpec{{VaultID: e.vaultID, Role: "proxy"}}, exp)
	if err != nil {
		e.t.Fatalf("CreateAgentWithGrantsAndToken: %v", err)
	}
	return sess.ID
}

// ---- Registration -------------------------------------------------------

func TestKMSAAD_RegisterRefusedOnceAUserExists(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := newKEnv(t, tdb)
		rec := e.do(http.MethodPost, "/v1/auth/register", `{"email":"intruder@example.test","password":"SENTINEL-AV-TEST-0801-pw"}`, "")
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST /v1/auth/register with an existing owner = %d, want 403: %s", rec.Code, rec.Body.String())
		}
		if u, _ := e.st.GetUserByEmail(context.Background(), "intruder@example.test"); u != nil {
			t.Errorf("a user row was created by open registration (active=%v)", u.IsActive)
		}
	})
}

// ---- Executor token privileges -----------------------------------------

func TestKMSAAD_ExecutorTokenPrivilegeChecks(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := newKEnv(t, tdb)
		e.setCreds("default", map[string]string{"SOME_KEY": "SENTINEL-AV-TEST-0811"})
		exp := time.Now().Add(24 * time.Hour)
		tok := e.executor("exec-bot", &exp)
		cases := []struct{ method, path, body string }{
			{http.MethodGet, "/v1/credentials?vault=default&reveal=true", ""},
			{http.MethodGet, "/v1/credentials?vault=default&reveal=true&key=SOME_KEY", ""},
			{http.MethodPatch, "/v1/vaults/default/settings", `{"unmatched_host_policy":"passthrough"}`},
			{http.MethodPost, "/v1/vaults/default/services", `{"services":[{"name":"x","host":"x.example.test","auth":{"type":"bearer","token":"SOME_KEY"}}]}`},
			{http.MethodPost, "/v1/vaults", `{"name":"exec-made-vault"}`},
			{http.MethodPost, "/v1/agents", `{"name":"exec-made-agent","vaults":[{"vault_name":"default","vault_role":"admin"}]}`},
		}
		for _, c := range cases {
			rec := e.do(c.method, c.path, c.body, tok, "X-Vault", "default")
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s with executor token = %d, want 403: %s", c.method, c.path, rec.Code, strings.TrimSpace(rec.Body.String()))
			}
			if strings.Contains(rec.Body.String(), "SENTINEL-AV-TEST-0811") {
				t.Errorf("%s %s leaked a credential value to the executor", c.method, c.path)
			}
		}
	})
}

// ---- Token expiry -------------------------------------------------------

func TestKMSAAD_RequireTokenExpiry_MintingRefusesNilExpiry(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		t.Setenv("AGENT_VAULT_REQUIRE_TOKEN_EXPIRY", "1")
		e := newKEnv(t, tdb)
		rec := e.do(http.MethodPost, "/v1/agents", `{"name":"exec-noexp","vaults":[{"vault_name":"default","vault_role":"proxy"}]}`, e.ownerToken)
		if rec.Code/100 == 2 {
			t.Errorf("POST /v1/agents minted a token with no expiry under AGENT_VAULT_REQUIRE_TOKEN_EXPIRY=1 (status %d)", rec.Code)
		}
		if a, _ := e.st.GetAgentByName(context.Background(), "exec-noexp"); a != nil {
			t.Errorf("agent row created although minting must be refused")
		}

		exp := time.Now().Add(time.Hour)
		e.executor("exec-rot", &exp)
		rec = e.do(http.MethodPost, "/v1/agents/exec-rot/rotate", `{}`, e.ownerToken)
		if rec.Code/100 == 2 {
			t.Errorf("POST /v1/agents/{name}/rotate minted a token with no expiry under AGENT_VAULT_REQUIRE_TOKEN_EXPIRY=1 (status %d)", rec.Code)
		}
	})
}

func TestKMSAAD_RequireTokenExpiry_AuthRefusesExistingNoExpiryToken(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := newKEnv(t, tdb)
		tok := e.executor("legacy-noexp", nil) // minted before the setting was turned on
		if rec := e.do(http.MethodGet, "/v1/vaults", "", tok); rec.Code != http.StatusOK {
			t.Fatalf("control: no-expiry token accepted before the setting: %d", rec.Code)
		}
		t.Setenv("AGENT_VAULT_REQUIRE_TOKEN_EXPIRY", "1")
		if rec := e.do(http.MethodGet, "/v1/vaults", "", tok); rec.Code != http.StatusUnauthorized {
			t.Errorf("API accepted a token with no expiry under AGENT_VAULT_REQUIRE_TOKEN_EXPIRY=1 (status %d)", rec.Code)
		}
		if scope, err := e.srv.SessionResolver().ResolveForProxy(context.Background(), tok, "default"); err == nil {
			t.Errorf("proxy accepted a token with no expiry under AGENT_VAULT_REQUIRE_TOKEN_EXPIRY=1 (scope %+v)", scope)
		}
	})
}

// ---- External credential store switching (infisical sync.go:226) ---------

func TestKMSAAD_CredentialStoreSwitchingDisabled(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := newKEnv(t, tdb)
		for _, body := range []string{`{"kind":"builtin"}`, `{"kind":"infisical","config":{},"poll_interval_seconds":60}`} {
			rec := e.do(http.MethodPatch, "/v1/vaults/default/credential-store", body, e.ownerToken)
			if rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
				t.Errorf("PATCH /v1/vaults/default/credential-store %s as owner = %d, want 403 or 404", body, rec.Code)
			}
		}
	})
}

// ---- whoami on the proxy port -------------------------------------------

func startProxy(t *testing.T, e *kenv) string {
	t.Helper()
	caProv, err := ca.New(e.encKey, ca.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	p := mitm.New("127.0.0.1:0", mitm.Options{
		CA: caProv, Sessions: e.srv.SessionResolver(), Credentials: e.srv.CredentialProvider(),
		BaseURL: e.srv.BaseURL(), Logger: slog.New(slog.DiscardHandler), RateLimit: e.srv.RateLimit(), LogSink: e.srv.LogSink(),
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = p.Serve(l) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	})
	return "http://" + l.Addr().String()
}

func TestKMSAAD_ProxyWhoami(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := newKEnv(t, tdb)
		e.setCreds("default", map[string]string{"SOME_KEY": "SENTINEL-AV-TEST-0821"})
		exp := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
		tok := e.executor("exec-whoami", &exp)
		proxy := startProxy(t, e)

		get := func(hdr map[string]string) (int, []byte) {
			req, _ := http.NewRequest(http.MethodGet, proxy+"/v1/whoami", nil)
			for k, v := range hdr {
				req.Header.Set(k, v)
			}
			resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
			if err != nil {
				t.Fatalf("GET proxy /v1/whoami: %v", err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, b
		}

		code, body := get(map[string]string{"Proxy-Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(tok+":"))})
		if code != http.StatusOK {
			t.Fatalf("proxy-port whoami with a valid proxy token = %d: %s", code, body)
		}
		if strings.Contains(string(body), "SENTINEL-AV-TEST-0821") || strings.Contains(string(body), tok) {
			t.Fatal("whoami returned a credential value or the token itself")
		}
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("whoami body is not JSON: %s", body)
		}
		keys := make([]string, 0, len(got))
		for k := range got {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if strings.Join(keys, ",") != "expires_at,instance_role,vaults" {
			t.Errorf("whoami keys = %v, want exactly [expires_at instance_role vaults]", keys)
		}
		if got["instance_role"] != "no-access" {
			t.Errorf("instance_role = %v, want no-access", got["instance_role"])
		}
		vaults, _ := json.Marshal(got["vaults"])
		if string(vaults) != `[{"role":"proxy","vault":"default"}]` {
			t.Errorf("vaults = %s, want [{\"role\":\"proxy\",\"vault\":\"default\"}]", vaults)
		}
		if s, _ := got["expires_at"].(string); s != exp.Format(time.RFC3339) {
			t.Errorf("expires_at = %v, want %s", got["expires_at"], exp.Format(time.RFC3339))
		}

		if code, _ := get(nil); code != http.StatusProxyAuthRequired && code != http.StatusUnauthorized {
			t.Errorf("proxy-port whoami without a token = %d, want 407 or 401", code)
		}
		rec := e.do(http.MethodGet, "/v1/whoami", "", "")
		if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "instance_role") {
			t.Errorf("whoami is reachable on the API port without auth")
		}
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusNotFound {
			t.Errorf("API-port /v1/whoami without auth = %d, want 401 or 404", rec.Code)
		}
	})
}

// ---- No secret in logs --------------------------------------------------

// Known positive: the scanner must see a sentinel planted in each channel,
// otherwise its silence in the tests below proves nothing.
func TestKMSAAD_LogScanner_KnownPositive(t *testing.T) {
	e := newKEnv(t, newSQLiteTestDB(t))
	planted := map[string]string{
		"server logger":    "SENTINEL-AV-TEST-0901-srv",
		"slog default":     "SENTINEL-AV-TEST-0902-slog",
		"std log":          "SENTINEL-AV-TEST-0903-std",
		"stderr":           "SENTINEL-AV-TEST-0904-stderr",
		"request log sink": "SENTINEL-AV-TEST-0905-sink",
		"http responses":   "SENTINEL-AV-TEST-0906-resp",
	}
	e.srv.logger.Info("plant", "v", planted["server logger"])
	slog.Info("plant", "v", planted["slog default"])
	log.Printf("plant %s", planted["std log"])
	fmt.Fprintln(os.Stderr, "plant", planted["stderr"])
	e.sink.Record(context.Background(), requestlog.Record{Path: "/" + planted["request log sink"]})
	e.do(http.MethodGet, "/v1/credentials?vault="+planted["http responses"], "", e.ownerToken)

	var all []string
	for _, s := range planted {
		all = append(all, s)
	}
	hits := findSentinels(e.channels(), all)
	for ch, s := range planted {
		want := ch + ": " + s
		found := false
		for _, h := range hits {
			if h == want {
				found = true
			}
		}
		if !found {
			t.Errorf("scanner missed a sentinel planted in %q", ch)
		}
	}
}

func TestKMSAAD_NoSecretInLogs_CredentialCreateUpdate(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := newKEnv(t, tdb)
		secrets := []string{"SENTINEL-AV-TEST-0911-create", "SENTINEL-AV-TEST-0912-update", "SENTINEL-AV-TEST-0913-badkey",
			"SENTINEL-AV-TEST-0914-oauth-access", "SENTINEL-AV-TEST-0915-oauth-refresh"}
		e.setCreds("default", map[string]string{"LOGGED_KEY": secrets[0]})
		e.setCreds("default", map[string]string{"LOGGED_KEY": secrets[1]})
		e.do(http.MethodPost, "/v1/credentials", `{"vault":"default","credentials":{"bad key":"`+secrets[2]+`"}}`, e.ownerToken)
		e.do(http.MethodPost, "/v1/credentials", `{"vault":"default","credentials":{"X":"`+secrets[2]+`"`, e.ownerToken) // malformed JSON
		e.do(http.MethodPost, "/v1/credentials/oauth/tokens", `{"vault":"default","key":"LOGGED_OAUTH","access_token":"`+secrets[3]+`","refresh_token":"`+secrets[4]+`","token_url":"manual"}`, e.ownerToken)
		if hits := findSentinels(e.channels(), secrets); len(hits) > 0 {
			t.Errorf("credential request bodies leaked: %v", hits)
		}
	})
}

// oauthConnect starts a connect flow and returns the raw state value.
func (e *kenv) oauthConnect(tokenURL, key, clientSecret string) string {
	e.t.Helper()
	body := fmt.Sprintf(`{"vault":"default","key":"%s","authorization_url":"https://auth.example.test/authorize","token_url":"%s","client_id":"cid","client_secret":"%s","scopes":"read"}`,
		key, tokenURL, clientSecret)
	rec := e.do(http.MethodPost, "/v1/credentials/oauth/connect", body, e.ownerToken)
	if rec.Code != http.StatusOK {
		e.t.Fatalf("oauth connect: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	u, err := url.Parse(resp["authorization_url"])
	if err != nil {
		e.t.Fatal(err)
	}
	return u.Query().Get("state")
}

func TestKMSAAD_NoSecretInLogs_OAuthCallback(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		for _, failing := range []bool{false, true} {
			name := "token-endpoint-ok"
			if failing {
				name = "token-endpoint-error-echoes-request"
			}
			t.Run(name, func(t *testing.T) {
				e := newKEnv(t, tdb.fresh(t))
				code := "SENTINEL-AV-TEST-0921-code"
				cs := "SENTINEL-AV-TEST-0922-client-secret"
				access := "SENTINEL-AV-TEST-0923-access"
				refresh := "SENTINEL-AV-TEST-0924-refresh"
				tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_ = r.ParseForm()
					w.Header().Set("Content-Type", "application/json")
					if failing {
						// Providers do echo request fields in error bodies.
						w.WriteHeader(http.StatusBadRequest)
						fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"code %s with client_secret %s rejected"}`, r.Form.Get("code"), r.Form.Get("client_secret"))
						return
					}
					fmt.Fprintf(w, `{"access_token":"%s","refresh_token":"%s","expires_in":3600,"token_type":"bearer"}`, access, refresh)
				}))
				defer tokenSrv.Close()

				state := e.oauthConnect(tokenSrv.URL, "LOGGED_OAUTH", cs)
				rec := e.do(http.MethodGet, "/v1/oauth/callback?code="+code+"&state="+url.QueryEscape(state), "", "")
				if rec.Code != http.StatusFound {
					t.Fatalf("callback status %d", rec.Code)
				}
				if loc := rec.Header().Get("Location"); strings.Contains(loc, "SENTINEL") {
					t.Errorf("callback redirect Location carries secret material (lands in browser history and access logs): %s", loc)
				}
				if hits := findSentinels(e.channels(), []string{code, cs, access, refresh}, "http responses"); len(hits) > 0 {
					t.Errorf("OAuth callback leaked into logs: %v", hits)
				}
			})
		}
	})
}
