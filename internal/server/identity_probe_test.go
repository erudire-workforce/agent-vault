package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
)

const probeUsersMe = `{"object":"user","id":"u","name":"example-integration","type":"bot",
 "bot":{"owner":{"type":"workspace","workspace":true},"workspace_name":"Example Workspace","workspace_id":"ws-00000000-test"}}`

const probeGolden = "2ef5eef3617ec9f7d8894b36a385469ea039caaf97e100179cb1e70c091edfe1"

// The probe runs GET /v1/users/me with the credential exactly as the proxy
// injects it, records the digest bound to that stored value, and the proxy
// result carries it only while the value is unchanged.
func TestIdentityProbeRecordsDigestBoundToStoredValue(t *testing.T) {
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")
	var body atomic.Value
	body.Store(probeUsersMe)
	var sawAuth atomic.Value
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/users/me" || r.Header.Get("Notion-Version") == "" {
			http.NotFound(w, r)
			return
		}
		sawAuth.Store(r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, body.Load().(string))
	}))
	defer up.Close()
	old := identityProbeBaseURL
	identityProbeBaseURL = up.URL
	defer func() { identityProbeBaseURL = old }()

	st, err := store.Open(filepath.Join(t.TempDir(), "av.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key := make([]byte, 32)
	srv := newTestServer(withStore(st), withEncKey(key))
	ctx := context.Background()
	v, err := st.CreateVault(ctx, "notion-vault")
	if err != nil {
		t.Fatal(err)
	}
	// The service allows only page reads; the probe must still reach
	// users/me through the injection path.
	if _, err := st.SetBrokerConfig(ctx, v.ID, `[{"name":"notion-read","host":"api.notion.com/v1/pages/{id}","methods":["GET"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}]`); err != nil {
		t.Fatal(err)
	}
	setCred := func(val string) {
		// Seal for the row's next version, as the credential handlers do.
		next := uint64(1)
		if cur, err := st.GetCredential(ctx, v.ID, "NOTION_TOKEN"); err == nil && cur != nil {
			next = cur.Version + 1
		}
		ct, n, err := store.CredentialValueAAD(v.ID, "NOTION_TOKEN", next).Seal([]byte(val), key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.SetCredentialVersion(ctx, v.ID, "NOTION_TOKEN", ct, n, next); err != nil {
			t.Fatal(err)
		}
	}
	inject := func() *brokercore.InjectResult {
		res, err := srv.CredentialProvider().Inject(brokercore.WithRequestMethod(ctx, "GET"), v.ID, "api.notion.com", 443, "/v1/pages/abc")
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	setCred("SENTINEL-PROBE-0001")
	if err := srv.runIdentityProbe(ctx, v.ID, "NOTION_TOKEN"); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if got := sawAuth.Load(); got != "Bearer SENTINEL-PROBE-0001" {
		t.Fatalf("probe sent Authorization %v, want the injected bearer", got)
	}
	if got := inject().CredentialIdentity; got != probeGolden {
		t.Fatalf("CredentialIdentity = %q, want golden %s", got, probeGolden)
	}
	rec, _ := st.GetVaultSetting(ctx, v.ID, brokercore.IdentitySettingKey("NOTION_TOKEN"))
	if strings.Contains(rec, "SENTINEL") {
		t.Fatal("identity record carries the credential")
	}

	// A new stored value invalidates the record until the probe re-runs.
	setCred("SENTINEL-PROBE-0002")
	if got := inject().CredentialIdentity; got != "" {
		t.Fatalf("identity %q still reported for a changed credential", got)
	}

	// A response missing a required field is refused and clears the record.
	body.Store(strings.Replace(probeUsersMe, `"workspace_id":"ws-00000000-test"`, `"workspace_id":""`, 1))
	if err := srv.runIdentityProbe(ctx, v.ID, "NOTION_TOKEN"); err == nil {
		t.Fatal("probe recorded an identity from an incomplete response")
	}
	if rec, _ := st.GetVaultSetting(ctx, v.ID, brokercore.IdentitySettingKey("NOTION_TOKEN")); rec != "" {
		t.Fatalf("stale identity record kept: %q", rec)
	}
}
