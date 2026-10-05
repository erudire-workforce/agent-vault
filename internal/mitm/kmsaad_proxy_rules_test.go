// Runtime tests through the real proxy listener for:
//   - per-method service rules ("methods" on broker.Service, deny by default
//     when set, enforced as a hard 403 rather than falling through to the
//     unmatched-host passthrough);
//   - the opt-in single-segment "{name}" path placeholder;
//   - X-Agent-Vault-* response header hygiene.
//
// Services are given as JSON exactly as they are stored in broker_configs, so
// the file compiles against v0.40.0 (the unknown "methods" key is silently
// ignored there, which is the defect).
package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
)

// jsonCredStore is a brokercore.CredentialStore backed by a raw services
// JSON string and credentials sealed with row-bound AAD at version 0.
type jsonCredStore struct {
	services string
	key      []byte
	creds    map[string]*store.Credential
	policy   brokercore.UnmatchedHostPolicy
}

func (s *jsonCredStore) GetBrokerConfig(_ context.Context, vaultID string) (*store.BrokerConfig, error) {
	return &store.BrokerConfig{VaultID: vaultID, ServicesJSON: s.services}, nil
}
func (s *jsonCredStore) GetCredential(_ context.Context, vaultID, key string) (*store.Credential, error) {
	c, ok := s.creds[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return c, nil
}
func (s *jsonCredStore) UnmatchedHostPolicy(context.Context, string) (brokercore.UnmatchedHostPolicy, error) {
	return s.policy, nil
}

// recordingUpstream records method+path and the Authorization it received.
type recordingUpstream struct {
	mu   sync.Mutex
	seen []string
	srv  *httptest.Server
}

func newRecordingUpstream(t *testing.T) *recordingUpstream {
	t.Helper()
	u := &recordingUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.seen = append(u.seen, r.Method+" "+r.URL.Path+" auth="+r.Header.Get("Authorization"))
		u.mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *recordingUpstream) sawMethod(m string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, s := range u.seen {
		if strings.HasPrefix(s, m+" ") {
			return true
		}
	}
	return false
}

func (u *recordingUpstream) last() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.seen) == 0 {
		return ""
	}
	return u.seen[len(u.seen)-1]
}

const notionTokenValue = "SENTINEL-AV-TEST-0601-notion"

func notionProxy(t *testing.T, servicesJSON string, policy brokercore.UnmatchedHostPolicy) (*recordingUpstream, *http.Client) {
	t.Helper()
	up := newRecordingUpstream(t)
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(up.srv.URL, "http://"))
	k := make([]byte, 32)
	ct, n, err := store.CredentialValueAAD("v1", "NOTION_TOKEN", 0).Seal([]byte(notionTokenValue), k)
	if err != nil {
		t.Fatal(err)
	}
	cs := &jsonCredStore{
		services: strings.ReplaceAll(servicesJSON, "UPSTREAM_HOST", host),
		key:      k,
		creds:    map[string]*store.Credential{"NOTION_TOKEN": {Key: "NOTION_TOKEN", Type: "static", Ciphertext: ct, Nonce: n}},
		policy:   policy,
	}
	cp := brokercore.NewStoreCredentialProvider(cs, k)
	sr := validTokenResolver("av_sess_exec", &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	proxyURL, roots, _ := setupProxy(t, sr, cp)
	return up, newTrustingClient(proxyURL, url.User("av_sess_exec"), roots)
}

func send(t *testing.T, c *http.Client, method, u string) int {
	t.Helper()
	req, err := http.NewRequest(method, u, strings.NewReader(`{"properties":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

const notionReadOnly = `[{"name":"notion-read","host":"UPSTREAM_HOST","path":"/v1/pages/*","methods":["GET"],
  "auth":{"type":"bearer","token":"NOTION_TOKEN"}}]`

// Write hold: GET allowed with the credential, PATCH refused and never sent.
func TestKMSAAD_WriteHold_PatchPagesRefused_GetAllowed(t *testing.T) {
	for _, policy := range []brokercore.UnmatchedHostPolicy{brokercore.PolicyDeny, brokercore.PolicyPassthrough} {
		t.Run(string(policy), func(t *testing.T) {
			up, c := notionProxy(t, notionReadOnly, policy)

			if code := send(t, c, http.MethodGet, up.srv.URL+"/v1/pages/abc123"); code != http.StatusOK {
				t.Fatalf("control: GET /v1/pages/{id} = %d, want 200", code)
			}
			if !strings.Contains(up.last(), "auth=Bearer "+notionTokenValue) {
				t.Fatalf("control: GET was not given the credential: %q", up.last())
			}

			code := send(t, c, http.MethodPatch, up.srv.URL+"/v1/pages/abc123")
			if up.sawMethod(http.MethodPatch) {
				t.Errorf("PATCH /v1/pages/{id} reached the upstream (%q) although the service allows only GET", up.last())
			}
			if code != http.StatusForbidden {
				t.Errorf("PATCH /v1/pages/{id} through the proxy = %d, want 403", code)
			}
		})
	}
}

// "methods" set but empty or with an unknown verb must deny everything, not
// fail open.
func TestKMSAAD_WriteHold_EmptyMethodsDeniesAll(t *testing.T) {
	up, c := notionProxy(t, `[{"name":"n","host":"UPSTREAM_HOST","path":"/v1/pages/*","methods":[],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}]`, brokercore.PolicyDeny)
	if code := send(t, c, http.MethodGet, up.srv.URL+"/v1/pages/abc"); code != http.StatusForbidden || up.sawMethod(http.MethodGet) {
		t.Errorf("GET with methods=[] = %d (upstream saw GET: %v); an explicitly empty allowlist must deny", code, up.sawMethod(http.MethodGet))
	}
}

// sendRaw sends a GET whose path is used exactly as written (no client-side
// cleaning or re-escaping) and reports the status and whether the upstream
// received a new request carrying the credential.
func sendRaw(t *testing.T, c *http.Client, up *recordingUpstream, rawPath string) (int, bool) {
	t.Helper()
	before := up.last()
	u, err := url.Parse(up.srv.URL + rawPath)
	if err != nil {
		t.Fatalf("parse %s: %v", rawPath, err)
	}
	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	req.URL = u
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawPath, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	got := up.last()
	return resp.StatusCode, got != before && strings.Contains(got, "auth=Bearer "+notionTokenValue)
}

// assertOneSegment checks that every path in escapes is refused (403, or 400
// from path normalization) and never forwarded with the credential.
func assertOneSegment(t *testing.T, c *http.Client, up *recordingUpstream, pattern string, escapes []string) {
	t.Helper()
	for _, p := range escapes {
		code, forwarded := sendRaw(t, c, up, p)
		if forwarded {
			t.Errorf("%s matched %s and forwarded it with the credential (%q)", pattern, p, up.last())
		}
		if code != http.StatusForbidden && code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 403 (or 400 from normalization) under deny policy", p, code)
		}
	}
}

// The opt-in "{name}" placeholder matches exactly one path segment:
// /v1/pages/{id} must not cover deeper paths, whether the extra segment is a
// plain "/", an encoded "%2F", a ".." traversal or an empty "//" segment.
// ("*" keeps its upstream greedy meaning; see broker_test.go.)
func TestKMSAAD_Wildcard_SingleSegmentOnly(t *testing.T) {
	up, c := notionProxy(t, `[{"name":"n","host":"UPSTREAM_HOST","path":"/v1/pages/{id}","auth":{"type":"bearer","token":"NOTION_TOKEN"}}]`, brokercore.PolicyDeny)
	if code := send(t, c, http.MethodGet, up.srv.URL+"/v1/pages/abc"); code != http.StatusOK {
		t.Fatalf("control: GET /v1/pages/abc = %d", code)
	}
	assertOneSegment(t, c, up, "/v1/pages/{id}", []string{
		"/v1/pages/abc/children/secret",
		"/v1/pages/abc%2Fchildren",
		"/v1/pages/abc%2fchildren",
		"/v1/pages/abc/../../users/me",
		"/v1/pages/%2e%2e",
		"/v1/pages//abc",
		"/v1/pages/abc//children",
		"/v1/pages/",
	})
}

func TestKMSAAD_Wildcard_MiddleSegment(t *testing.T) {
	up, c := notionProxy(t, `[{"name":"n","host":"UPSTREAM_HOST","path":"/v1/blocks/{id}/children","auth":{"type":"bearer","token":"NOTION_TOKEN"}}]`, brokercore.PolicyDeny)
	if code := send(t, c, http.MethodGet, up.srv.URL+"/v1/blocks/abc/children"); code != http.StatusOK {
		t.Fatalf("control: GET /v1/blocks/abc/children = %d", code)
	}
	assertOneSegment(t, c, up, "/v1/blocks/{id}/children", []string{
		"/v1/blocks/a/b/children",
		"/v1/blocks/a%2Fb/children",
		"/v1/blocks/a/../b/children",
		"/v1/blocks/../children",
		"/v1/blocks//children",
		"/v1/blocks/a//children",
	})
}

// Upstream-supplied X-Agent-Vault-* headers must never reach the client; the proxy
// sets exactly one X-Agent-Vault-Credential-Identity of its own.
func TestKMSAAD_HeaderHygiene_SpoofedIdentityStripped(t *testing.T) {
	check := func(t *testing.T, h http.Header) {
		t.Helper()
		vals := h.Values("X-Agent-Vault-Credential-Identity")
		if len(vals) != 1 {
			t.Errorf("X-Agent-Vault-Credential-Identity has %d values %q, want exactly 1", len(vals), vals)
		}
		for _, v := range vals {
			if strings.Contains(v, "spoofed") {
				t.Errorf("upstream-spoofed X-Agent-Vault-Credential-Identity reached the client: %q", v)
			}
			if strings.Contains(v, "injected-secret") {
				t.Errorf("identity header carries the credential value: %q", v)
			}
		}
		if h.Get("X-Agent-Vault-Upstream-Extra") != "" {
			t.Errorf("upstream X-Agent-Vault-Upstream-Extra reached the client")
		}
	}
	spoof := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("X-Agent-Vault-Credential-Identity", "spoofed-by-upstream")
		w.Header().Add("X-Agent-Vault-Credential-Identity", "spoofed-twice")
		w.Header().Set("x-agent-vault-upstream-extra", "spoofed-extra")
		_, _ = io.WriteString(w, "ok")
	}

	t.Run("plain-http-forward", func(t *testing.T) {
		up := httptest.NewServer(http.HandlerFunc(spoof))
		defer up.Close()
		host, _, _ := net.SplitHostPort(strings.TrimPrefix(up.URL, "http://"))
		cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{host: {result: &brokercore.InjectResult{
			Headers: map[string]string{"Authorization": "Bearer injected-secret"}, MatchedName: "svc", CredentialKeys: []string{"SVC_KEY"},
		}}}}
		sr := validTokenResolver("av_sess_ok", &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
		proxyURL, roots, _ := setupProxy(t, sr, cp)
		resp, err := newTrustingClient(proxyURL, url.User("av_sess_ok"), roots).Get(up.URL + "/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		check(t, resp.Header)
	})

	t.Run("https-mitm", func(t *testing.T) {
		up := httptest.NewTLSServer(http.HandlerFunc(spoof))
		defer up.Close()
		host, _, _ := net.SplitHostPort(strings.TrimPrefix(up.URL, "https://"))
		cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{host: {result: &brokercore.InjectResult{
			Headers: map[string]string{"Authorization": "Bearer injected-secret"}, MatchedName: "svc", CredentialKeys: []string{"SVC_KEY"},
		}}}}
		sr := validTokenResolver("av_sess_ok", &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
		proxyURL, roots, p := setupProxy(t, sr, cp)
		upRoots := x509.NewCertPool()
		upRoots.AddCert(up.Certificate())
		p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upRoots}
		resp, err := newTrustingClient(proxyURL, url.User("av_sess_ok"), roots).Get(up.URL + "/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		check(t, resp.Header)
	})
}
