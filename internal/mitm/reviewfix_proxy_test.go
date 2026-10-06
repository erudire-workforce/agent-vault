//go:build reviewfix

// Review-fix proxy tests. Run with: go test -tags reviewfix ./internal/mitm/
// Remove the build tag in the change that makes the WebSocket policy-mode
// refusal and the documentation paragraph pass.
package mitm

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/servicepolicy"
	"github.com/Infisical/agent-vault/internal/store"
)

const wsBearer = "SENTINEL-RF-0401-ws-bearer"

// wsUpstream answers every upgrade with 101 and immediately sends a text
// frame that echoes the Authorization header it received. hits counts the
// upgrade requests that reached it.
type wsUpstream struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits int
	auth string
}

func (u *wsUpstream) seen() (int, string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits, u.auth
}

func wsEchoUpstream(t *testing.T) *wsUpstream {
	t.Helper()
	u := &wsUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hits++
		u.auth = r.Header.Get("Authorization")
		u.mu.Unlock()
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			websocketAccept(r.Header.Get("Sec-WebSocket-Key")))
		_ = buf.Flush()
		_ = writeWebSocketTextFrame(conn, "hello "+r.Header.Get("Authorization"), false)
		time.Sleep(200 * time.Millisecond)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

// wsHandshake sends an upgrade through the plain-HTTP forward proxy and
// returns the status and, on 101, the first frame.
func wsHandshake(t *testing.T, cp brokercore.CredentialProvider, up *wsUpstream) (int, string) {
	t.Helper()
	sr := validTokenResolver("av_sess_ok", &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	proxyURL, _, _ := setupProxy(t, sr, cp)
	conn := dialProxy(t, proxyURL)
	defer conn.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(up.srv.URL, "http://"))
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	fmt.Fprintf(conn, "GET %s/ws HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		up.srv.URL, host, base64.StdEncoding.EncodeToString([]byte("av_sess_ok:")), key)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return resp.StatusCode, ""
	}
	frame, _ := readWebSocketTextFrame(br)
	return resp.StatusCode, frame
}

func wsProvider(kind, host string) brokercore.CredentialProvider {
	if kind == "passthrough" {
		return &fakeCredProvider{byHost: map[string]fakeInjectResult{host: {result: &brokercore.InjectResult{Passthrough: true}}}}
	}
	return &fakeCredProvider{byHost: map[string]fakeInjectResult{host: {result: &brokercore.InjectResult{
		Headers: map[string]string{"Authorization": "Bearer " + wsBearer}, MatchedName: "svc", CredentialKeys: []string{"WS_KEY"},
	}}}}
}

// Blocker 4 (decision: refuse only in policy mode). With the service-policy
// mode active, every Upgrade gets 403 and never 101, whether or not a
// credential would be injected, and the upstream is never contacted.
func TestReviewFix_WebSocketRefusedInPolicyMode(t *testing.T) {
	t.Setenv(servicepolicy.EnvMode, servicepolicy.ModeReadonlyAllowlist)
	for _, kind := range []string{"credential injected", "passthrough"} {
		t.Run(kind, func(t *testing.T) {
			up := wsEchoUpstream(t)
			host, _, _ := net.SplitHostPort(strings.TrimPrefix(up.srv.URL, "http://"))
			code, frame := wsHandshake(t, wsProvider(kind, host), up)
			if code != http.StatusForbidden {
				t.Errorf("upgrade in policy mode returned %d (first frame %q), want 403", code, frame)
			}
			if hits, _ := up.seen(); hits != 0 {
				t.Errorf("upgrade in policy mode reached the upstream %d time(s)", hits)
			}
		})
	}
}

// With the policy mode off, upstream WebSocket credential injection is
// unchanged. Frames are not echo-scrubbed in that mode, which the docs must
// say (TestReviewFix_WebSocketLimitationDocumented); no scrubbing is
// asserted here.
func TestReviewFix_WebSocketUnchangedWithoutPolicyMode(t *testing.T) {
	t.Setenv(servicepolicy.EnvMode, "")
	up := wsEchoUpstream(t)
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(up.srv.URL, "http://"))
	if code, _ := wsHandshake(t, wsProvider("credential injected", host), up); code != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade with the policy mode off returned %d, want 101 (upstream behaviour)", code)
	}
	if _, auth := up.seen(); auth != "Bearer "+wsBearer {
		t.Errorf("upstream saw Authorization %q, want the injected credential", auth)
	}
}

// The fork's documentation states that WebSocket frames are not
// echo-scrubbed when the service-policy mode is off: some paragraph in
// README.md, SECURITY.md or docs/ names WebSocket, scrubbing and the mode.
func TestReviewFix_WebSocketLimitationDocumented(t *testing.T) {
	root := filepath.Join("..", "..")
	files := []string{filepath.Join(root, "README.md"), filepath.Join(root, "SECURITY.md")}
	_ = filepath.WalkDir(filepath.Join(root, "docs"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && (strings.HasSuffix(p, ".md") || strings.HasSuffix(p, ".mdx")) {
			files = append(files, p)
		}
		return nil
	})
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, para := range strings.Split(string(b), "\n\n") {
			low := strings.ToLower(para)
			if strings.Contains(low, "websocket") && strings.Contains(low, "scrub") && strings.Contains(para, servicepolicy.EnvMode) {
				return
			}
		}
	}
	t.Errorf("no paragraph in README.md, SECURITY.md or docs/ says WebSocket frames are not echo-scrubbed when %s is off", servicepolicy.EnvMode)
}

// headerUpstream records every request's headers.
type headerUpstream struct {
	mu   sync.Mutex
	srv  *httptest.Server
	seen []http.Header
}

func methodRulesProxy(t *testing.T) (*headerUpstream, *http.Client) {
	t.Helper()
	up := &headerUpstream{}
	up.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up.mu.Lock()
		up.seen = append(up.seen, r.Header.Clone())
		up.mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(up.srv.Close)
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(up.srv.URL, "http://"))
	k := make([]byte, 32)
	ct, n, err := store.CredentialValueAAD("v1", "NOTION_TOKEN", 0).Seal([]byte(notionTokenValue), k)
	if err != nil {
		t.Fatal(err)
	}
	cs := &jsonCredStore{
		services: `[{"name":"pages","host":"` + host + `","path":"/v1/pages/{id}","methods":["GET"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}]`,
		key:      k,
		creds:    map[string]*store.Credential{"NOTION_TOKEN": {Key: "NOTION_TOKEN", Type: "static", Ciphertext: ct, Nonce: n}},
		policy:   brokercore.PolicyDeny,
	}
	sr := validTokenResolver("av_sess_exec", &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	proxyURL, roots, _ := setupProxy(t, sr, brokercore.NewStoreCredentialProvider(cs, k))
	return up, newTrustingClient(proxyURL, url.User("av_sess_exec"), roots)
}

// Non-blocking: when Methods is set, method-override headers are stripped
// so an upstream that honours them cannot turn an allowed GET into a write.
func TestReviewFix_MethodOverrideHeadersStripped(t *testing.T) {
	up, c := methodRulesProxy(t)
	req, _ := http.NewRequest(http.MethodGet, up.srv.URL+"/v1/pages/abc", nil)
	req.Header.Set("X-HTTP-Method-Override", "PATCH")
	req.Header.Set("X-HTTP-Method", "DELETE")
	req.Header.Set("X-Method-Override", "POST")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.seen) == 0 {
		t.Fatalf("control: GET /v1/pages/abc not forwarded (status %d)", resp.StatusCode)
	}
	for _, h := range []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"} {
		if v := up.seen[0].Get(h); v != "" {
			t.Errorf("%s: %q reached the upstream on a methods-restricted service", h, v)
		}
	}
}

func encodedUpstream(t *testing.T, encode func(w http.ResponseWriter, body []byte)) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")
		encode(w, []byte(`{"error":"bad token `+tok+`"}`))
	}))
	t.Cleanup(s.Close)
	return s
}

// Non-blocking: an upstream that gzips regardless of Accept-Encoding still
// gets scrubbed (decoded, scrubbed, relayed), not relayed encoded.
func TestReviewFix_EchoScrub_GzipResponse(t *testing.T) {
	up := encodedUpstream(t, func(w http.ResponseWriter, body []byte) {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		_, _ = zw.Write(body)
		_ = zw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(b.Bytes())
	})
	rig := newRig(t, &seqCredProvider{results: []*brokercore.InjectResult{credResult("svc", "ECHO_KEY", "SENTINEL-RF-0501-gzip")}})
	req, _ := http.NewRequest(http.MethodGet, up.URL+"/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := rig.client.Transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	body := raw
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err == nil {
			body, _ = io.ReadAll(zr)
		}
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gzip response status %d (%s); want it decoded and scrubbed, not refused", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "SENTINEL-RF-0501-gzip") {
		t.Error("gzip-encoded echo of the injected credential reached the client")
	}
	if !strings.Contains(string(body), "[REDACTED]") {
		t.Errorf("gzip body not scrubbed: %q", body)
	}
}

// Non-blocking: JSON encoders that escape '/' as "\/" must not hide an echo.
func TestReviewFix_EchoScrub_JSONSlashEscape(t *testing.T) {
	secret := "SENTINEL-RF-0502/with/slashes"
	up := encodedUpstream(t, func(w http.ResponseWriter, body []byte) {
		_, _ = w.Write([]byte(strings.ReplaceAll(string(body), "/", `\/`)))
	})
	rig := newRig(t, &seqCredProvider{results: []*brokercore.InjectResult{credResult("svc", "ECHO_KEY", secret)}})
	_, body := rig.get(t, up.URL+"/x")
	if strings.Contains(string(body), strings.ReplaceAll(secret, "/", `\/`)) {
		t.Errorf(`JSON "\/"-escaped echo of the injected credential reached the client: %s`, body)
	}
}

// Non-blocking: a brotli response cannot be inspected and is refused (502),
// never relayed.
func TestReviewFix_EchoScrub_BrotliRefused(t *testing.T) {
	up := encodedUpstream(t, func(w http.ResponseWriter, body []byte) {
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write(body) // not real brotli; the proxy must not relay it either way
	})
	rig := newRig(t, &seqCredProvider{results: []*brokercore.InjectResult{credResult("svc", "ECHO_KEY", "SENTINEL-RF-0503-br")}})
	got, body := rig.get(t, up.URL+"/x")
	if got.StatusCode != http.StatusBadGateway {
		t.Errorf("brotli response status %d, want 502", got.StatusCode)
	}
	if strings.Contains(string(body), "SENTINEL-RF-0503-br") {
		t.Error("brotli-labelled body relayed with the credential")
	}
}
