//go:build kmsaad

// Runtime tests through the real proxy listener for:
//   - X-Agent-Vault-Credential-Identity on the OAuth 401 retry path
//     (forward.go:350-371) describing the credential used on the final attempt;
//   - path normalization: the single-segment "*" match runs on the same
//     normalized path that is forwarded (%2F, "..", "//");
//   - response echo scrubbing: every raw, base64, base64url and
//     percent-encoded occurrence of the injected credential is replaced with
//     [REDACTED] in response headers, body, logs and the request log,
//     including on the 401 retry path.
package mitm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// seqCredProvider returns its results in order (the last one repeats), so
// the first Inject and the 401-retry Inject can differ.
type seqCredProvider struct {
	mu      sync.Mutex
	results []*brokercore.InjectResult
	n       int
}

func (s *seqCredProvider) Inject(context.Context, string, string, int, string) (*brokercore.InjectResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.n
	if i >= len(s.results) {
		i = len(s.results) - 1
	}
	s.n++
	r := *s.results[i]
	return &r, nil
}

func credResult(name, key, token string) *brokercore.InjectResult {
	return &brokercore.InjectResult{
		Headers:        map[string]string{"Authorization": "Bearer " + token},
		MatchedName:    name,
		CredentialKeys: []string{key},
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *lockedBuf) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type proxyRig struct {
	client *http.Client
	sink   *recordingSink
	logs   *lockedBuf
}

func newRig(t *testing.T, cp brokercore.CredentialProvider) *proxyRig {
	t.Helper()
	rig := &proxyRig{sink: &recordingSink{}, logs: &lockedBuf{}}
	sr := validTokenResolver("av_sess_ok", &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	proxyURL, roots, _ := setupProxy(t, sr, cp, func(o *Options) {
		o.LogSink = rig.sink
		o.Logger = slog.New(slog.NewJSONHandler(rig.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	rig.client = newTrustingClient(proxyURL, url.User("av_sess_ok"), roots)
	return rig
}

func (r *proxyRig) get(t *testing.T, u string) (*http.Response, []byte) {
	t.Helper()
	resp, err := r.client.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

const identityHeader = "X-Agent-Vault-Credential-Identity"

// ---- identity header on the 401 retry path ------------------------------

func TestKMSAAD_RetryPath_IdentityDescribesFinalCredential(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer token-first-attempt" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer up.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(up.URL, "http://"))
	_ = host
	first := credResult("svc-first", "KEY_FIRST", "token-first-attempt")
	final := credResult("svc-final", "KEY_FINAL", "token-final-attempt")

	idFor := func(r *brokercore.InjectResult) string {
		rig := newRig(t, &seqCredProvider{results: []*brokercore.InjectResult{r}})
		resp, _ := rig.get(t, up.URL+"/x")
		return resp.Header.Get(identityHeader)
	}
	idFirst, idFinal := idFor(first), idFor(final)
	if idFinal == "" {
		t.Fatalf("no %s on a plain proxied response", identityHeader)
	}
	if idFirst == idFinal {
		t.Fatalf("identity header does not distinguish two different credentials (%q); the test cannot tell attempts apart", idFirst)
	}

	rig := newRig(t, &seqCredProvider{results: []*brokercore.InjectResult{first, final}})
	resp, _ := rig.get(t, up.URL+"/x")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("retry did not succeed: %d", resp.StatusCode)
	}
	vals := resp.Header.Values(identityHeader)
	if len(vals) != 1 || vals[0] != idFinal {
		t.Fatalf("after a 401 retry %s = %q, want exactly [%q] (the credential used on the final attempt)", identityHeader, vals, idFinal)
	}
}

// ---- path normalization ---------------------------------------------------

func TestKMSAAD_PathNormalization_MatchesWhatIsForwarded(t *testing.T) {
	up, c := notionProxy(t, notionReadOnly, brokercore.PolicyDeny) // /v1/pages/* GET only
	if code := send(t, c, http.MethodGet, up.srv.URL+"/v1/pages/abc"); code != http.StatusOK {
		t.Fatalf("control: GET /v1/pages/abc = %d", code)
	}
	for name, raw := range map[string]string{
		"encoded slash %2F":       "/v1/pages/abc%2Fchildren",
		"encoded slash %2f lower": "/v1/pages/abc%2fchildren",
		"dot-dot escape":          "/v1/pages/abc/../../users/me",
		"encoded dot-dot":         "/v1/pages/%2e%2e/users",
		"double slash":            "/v1/pages//abc",
		"double slash prefix":     "/v1/pages/abc//children",
	} {
		before := up.last()
		u, err := url.Parse(up.srv.URL + raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
		req.URL = u
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resp.Body.Close()
		got := up.last()
		forwarded := got != before && strings.Contains(got, "auth=Bearer "+notionTokenValue)
		if forwarded {
			t.Errorf("%s (%s): forwarded with the credential as %q; the single-segment match must run on the normalized path", name, raw, got)
		}
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s (%s): status %d, want 403 or 400", name, raw, resp.StatusCode)
		}
	}
}

// ---- response echo scrubbing ---------------------------------------------

// A secret whose encodings differ: base64 vs base64url, and characters that
// percent-encoding changes.
const echoSecret = "SENTINEL-AV-TEST-1401~?&=/+ tok>>>?"

func secretForms(s string) map[string]string {
	return map[string]string{
		"raw":            s,
		"base64":         base64.StdEncoding.EncodeToString([]byte(s)),
		"base64 raw":     base64.RawStdEncoding.EncodeToString([]byte(s)),
		"base64url":      base64.URLEncoding.EncodeToString([]byte(s)),
		"base64url raw":  base64.RawURLEncoding.EncodeToString([]byte(s)),
		"query-escaped":  url.QueryEscape(s),
		"path-escaped":   url.PathEscape(s),
		"bearer base64":  base64.StdEncoding.EncodeToString([]byte("Bearer " + s)),
	}
}

func echoUpstream(t *testing.T, rejectToken string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		tok := strings.TrimPrefix(auth, "Bearer ")
		f := secretForms(tok)
		w.Header().Set("X-Echo-Raw", f["raw"])
		w.Header().Set("X-Echo-B64", f["base64"])
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", token="`+f["base64url"]+`"`)
		w.Header().Set("Content-Type", "application/json")
		if rejectToken != "" && tok == rejectToken {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "invalid token " + f["raw"], "b64": f["base64"], "b64_raw": f["base64 raw"],
			"b64url": f["base64url"], "b64url_raw": f["base64url raw"], "q": f["query-escaped"],
			"p": f["path-escaped"], "basic": f["bearer base64"], "auth_header_echo": auth,
		})
	}))
	t.Cleanup(s.Close)
	return s
}

func assertScrubbed(t *testing.T, where string, resp *http.Response, body []byte, rig *proxyRig, secrets ...string) {
	t.Helper()
	var hdr strings.Builder
	for k, vv := range resp.Header {
		fmt.Fprintf(&hdr, "%s: %s\n", k, strings.Join(vv, ", "))
	}
	recs, _ := json.Marshal(rig.sink.snapshot())
	channels := map[string]string{
		"response headers": hdr.String(),
		"response body":    string(body),
		"request log":      string(recs),
		"proxy logs":       rig.logs.String(),
	}
	for _, s := range secrets {
		for form, v := range secretForms(s) {
			for ch, text := range channels {
				if strings.Contains(text, v) {
					t.Errorf("%s: %s form of the injected credential present in %s", where, form, ch)
				}
			}
		}
	}
	if !strings.Contains(string(body), "[REDACTED]") || !strings.Contains(hdr.String(), "[REDACTED]") {
		t.Errorf("%s: echoed credential not replaced with [REDACTED] (body=%v headers=%v)", where,
			strings.Contains(string(body), "[REDACTED]"), strings.Contains(hdr.String(), "[REDACTED]"))
	}
}

func TestKMSAAD_EchoScrub_ResponseHeadersBodyAndLogs(t *testing.T) {
	up := echoUpstream(t, "")
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(up.URL, "http://"))
	_ = host
	rig := newRig(t, &seqCredProvider{results: []*brokercore.InjectResult{credResult("svc", "ECHO_KEY", echoSecret)}})
	resp, body := rig.get(t, up.URL+"/v1/echo")
	assertScrubbed(t, "single attempt", resp, body, rig, echoSecret)
}

func TestKMSAAD_EchoScrub_RetryPath(t *testing.T) {
	firstTok := "SENTINEL-AV-TEST-1402-first?/+"
	up := echoUpstream(t, firstTok)
	rig := newRig(t, &seqCredProvider{results: []*brokercore.InjectResult{
		credResult("svc", "ECHO_KEY", firstTok), credResult("svc", "ECHO_KEY", echoSecret),
	}})
	resp, body := rig.get(t, up.URL+"/v1/echo")
	assertScrubbed(t, "401 retry", resp, body, rig, echoSecret, firstTok)
}
