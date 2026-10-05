//go:build reviewfix

// Review-fix proxy tests. Run with: go test -tags reviewfix ./internal/mitm/
package mitm

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/servicepolicy"
	"github.com/Infisical/agent-vault/internal/store"
)

const wsBearer = "SENTINEL-RF-0401-ws-bearer"

// wsEchoUpstream answers every upgrade with 101 and immediately sends a text
// frame that echoes the Authorization header it received.
func wsEchoUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	t.Cleanup(s.Close)
	return s
}

// wsHandshake sends an upgrade through the plain-HTTP forward proxy and
// returns the status and, on 101, the first frame.
func wsHandshake(t *testing.T, cp brokercore.CredentialProvider, up *httptest.Server) (int, string) {
	t.Helper()
	sr := validTokenResolver("av_sess_ok", &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	proxyURL, _, _ := setupProxy(t, sr, cp)
	conn := dialProxy(t, proxyURL)
	defer conn.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(up.URL, "http://"))
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	fmt.Fprintf(conn, "GET %s/ws HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		up.URL, host, base64.StdEncoding.EncodeToString([]byte("av_sess_ok:")), key)
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

// Blocker 4: when the scrubber holds a credential, an Upgrade is refused;
// frames are not scrubbed, so a 101 would relay the echoed bearer.
func TestReviewFix_WebSocketRefusedWhenCredentialInjected(t *testing.T) {
	up := wsEchoUpstream(t)
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(up.URL, "http://"))
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{host: {result: &brokercore.InjectResult{
		Headers: map[string]string{"Authorization": "Bearer " + wsBearer}, MatchedName: "svc", CredentialKeys: []string{"WS_KEY"},
	}}}}
	code, frame := wsHandshake(t, cp, up)
	if code == http.StatusSwitchingProtocols {
		t.Errorf("upgrade with an injected credential returned 101; first frame %q", frame)
	}
	if strings.Contains(frame, wsBearer) {
		t.Errorf("injected bearer reached the client unscrubbed in a WebSocket frame")
	}
}

// Blocker 4: in policy mode every Upgrade is refused, even with no
// credential injected.
func TestReviewFix_WebSocketRefusedInPolicyMode(t *testing.T) {
	t.Setenv(servicepolicy.EnvMode, servicepolicy.ModeReadonlyAllowlist)
	up := wsEchoUpstream(t)
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(up.URL, "http://"))
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{host: {result: &brokercore.InjectResult{Passthrough: true}}}}
	if code, _ := wsHandshake(t, cp, up); code == http.StatusSwitchingProtocols {
		t.Error("upgrade returned 101 while the policy mode is active")
	}
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
