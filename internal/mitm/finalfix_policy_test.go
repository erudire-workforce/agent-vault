// Final-review blockers 1 and 2, through the real proxy listener in
// service-policy mode. Run with: go test -tags finalfix ./internal/mitm/
//
// The proxy's upstream dialler is redirected to local test servers, so the
// requests name the real provider host while nothing leaves the machine.
// Every dial and every Authorization the upstreams receive is recorded.
package mitm

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/servicepolicy"
	"github.com/Infisical/agent-vault/internal/store"
)

const policyBearer = "SENTINEL-FF-0101-bearer"

type policyRig struct {
	client *http.Client
	mu     sync.Mutex
	dials  []string // host:port the proxy tried to reach
	auths  []string // Authorization headers the upstreams received
}

func (r *policyRig) record(dst *[]string, v string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	*dst = append(*dst, v)
}

func (r *policyRig) snapshot() (dials, auths []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.dials...), append([]string(nil), r.auths...)
}

func (r *policyRig) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dials, r.auths = nil, nil
}

func newPolicyRig(t *testing.T, unmatched brokercore.UnmatchedHostPolicy) *policyRig {
	t.Helper()
	t.Setenv(servicepolicy.EnvMode, servicepolicy.ModeReadonlyAllowlist)
	rig := &policyRig{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.record(&rig.auths, r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, "ok")
	})
	tlsUp := httptest.NewTLSServer(handler)
	t.Cleanup(tlsUp.Close)
	plainUp := httptest.NewServer(handler)
	t.Cleanup(plainUp.Close)

	k := make([]byte, 32)
	ct, n, err := store.CredentialValueAAD("v1", "NOTION_TOKEN", 0).Seal([]byte(policyBearer), k)
	if err != nil {
		t.Fatal(err)
	}
	cs := &jsonCredStore{
		services: `[{"name":"notion-pages","host":"api.notion.com","path":"/v1/pages/{id}","methods":["GET"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}]`,
		key:      k,
		creds:    map[string]*store.Credential{"NOTION_TOKEN": {Key: "NOTION_TOKEN", Type: "static", Ciphertext: ct, Nonce: n}},
		policy:   unmatched,
	}
	sr := validTokenResolver("av_sess_exec", &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	proxyURL, roots, p := setupProxy(t, sr, brokercore.NewStoreCredentialProvider(cs, k))

	tlsAddr := strings.TrimPrefix(tlsUp.URL, "https://")
	plainAddr := strings.TrimPrefix(plainUp.URL, "http://")
	var d net.Dialer
	p.upstream.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		rig.record(&rig.dials, addr)
		target := tlsAddr
		if strings.HasSuffix(addr, ":80") {
			target = plainAddr
		}
		return d.DialContext(ctx, network, target)
	}
	p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec // local test upstream

	rig.client = newTrustingClient(proxyURL, url.User("av_sess_exec"), roots)
	return rig
}

func (r *policyRig) do(t *testing.T, method, u string) int {
	t.Helper()
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		// A refused CONNECT surfaces as a client error carrying the status.
		if strings.Contains(err.Error(), "Forbidden") {
			return http.StatusForbidden
		}
		t.Fatalf("%s %s: %v", method, u, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// Blocker 1: in policy mode the credential is only ever sent over TLS to
// port 443. Plain http:// and any other port get 403 with no upstream
// contact and no credential sent.
func TestFinalFix_PolicyMode_CredentialOnlyOverTLSOn443(t *testing.T) {
	rig := newPolicyRig(t, brokercore.PolicyDeny)

	if code := rig.do(t, http.MethodGet, "https://api.notion.com/v1/pages/abc"); code != http.StatusOK {
		t.Fatalf("control: GET https://api.notion.com/v1/pages/abc = %d, want 200", code)
	}
	if _, auths := rig.snapshot(); len(auths) != 1 || auths[0] != "Bearer "+policyBearer {
		t.Fatalf("control: upstream saw %v, want the injected bearer once", auths)
	}

	for _, u := range []string{
		"http://api.notion.com/v1/pages/abc",
		"http://api.notion.com/v1/users/me",
		"https://api.notion.com:8443/v1/pages/abc",
		"http://api.notion.com:443/v1/pages/abc",
	} {
		rig.reset()
		code := rig.do(t, http.MethodGet, u)
		dials, auths := rig.snapshot()
		if code != http.StatusForbidden {
			t.Errorf("GET %s in policy mode = %d, want 403", u, code)
		}
		if len(dials) != 0 {
			t.Errorf("GET %s in policy mode dialled %v; the upstream must not be contacted", u, dials)
		}
		for _, a := range auths {
			if strings.Contains(a, policyBearer) {
				t.Errorf("GET %s in policy mode sent the credential (%q) off TLS-on-443", u, a)
			}
		}
	}
}

// Blocker 2: in policy mode an unmatched request gets 403 whatever the
// vault's unmatched_host_policy says, and is never forwarded.
func TestFinalFix_PolicyMode_UnmatchedRequestsRefused(t *testing.T) {
	for _, pol := range []brokercore.UnmatchedHostPolicy{"", brokercore.PolicyPassthrough, brokercore.PolicyDeny} {
		name := string(pol)
		if name == "" {
			name = "absent"
		}
		t.Run(name, func(t *testing.T) {
			rig := newPolicyRig(t, pol)
			for _, c := range []struct{ method, url string }{
				{http.MethodPost, "https://api.notion.com/v1/search"},
				{http.MethodGet, "https://api.notion.com/v1/users"},
				{http.MethodGet, "https://example.com/"},
			} {
				rig.reset()
				code := rig.do(t, c.method, c.url)
				_, auths := rig.snapshot()
				if code != http.StatusForbidden {
					t.Errorf("%s %s (unmatched_host_policy=%s) = %d, want 403", c.method, c.url, name, code)
				}
				if len(auths) != 0 {
					t.Errorf("%s %s (unmatched_host_policy=%s) reached the upstream", c.method, c.url, name)
				}
			}
		})
	}
}
