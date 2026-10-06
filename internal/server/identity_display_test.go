// Fork change 6 (ADR 0010 r35): the identity probe records four values
// beside the credential's version, workspace_name, workspace_id,
// integration_name and digest, and credential metadata returns all four as
// identity.workspace_name, identity.workspace_id, identity.integration_name
// and identity.digest. None of them may ever carry the credential value. A
// Notion /v1/users/me response missing any field records no identity.
//
// Fork change 7: at injection time the vault re-checks the compiled-in
// host, method and path allowlist against the live request, so a service row
// edited directly in the database cannot widen what a credential reaches.
package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/identity"
	"github.com/Infisical/agent-vault/internal/servicepolicy"
)

const (
	displayToken   = "SENTINEL-ID-0001-notion-token"
	displayWSID    = "ws-00000000-test"
	displayWSName  = "Example Workspace"
	displayBotName = "example-integration"
)

// notionFake answers /v1/users/me with a body built from the current fields.
type notionFake struct {
	mu   sync.Mutex
	body string
}

func (n *notionFake) set(body string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.body = body
}

func usersMe(wsID, wsName, name string) string {
	fields := []string{`"object":"user"`, `"id":"u"`, `"type":"bot"`}
	if name != "" {
		fields = append(fields, `"name":`+jsonString(name))
	}
	bot := []string{`"owner":{"type":"workspace","workspace":true}`}
	if wsName != "" {
		bot = append(bot, `"workspace_name":`+jsonString(wsName))
	}
	if wsID != "" {
		bot = append(bot, `"workspace_id":`+jsonString(wsID))
	}
	return "{" + strings.Join(fields, ",") + `,"bot":{` + strings.Join(bot, ",") + "}}"
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// newDisplayEnv returns an owner-authenticated server whose default vault has
// a Notion service and the token stored, with the probe pointed at a fake.
func newDisplayEnv(t *testing.T, tdb testDB) (*kenv, *notionFake) {
	t.Helper()
	t.Setenv("AGENT_VAULT_IDENTITY_PROBE", "off") // the tests run the probe themselves
	fake := &notionFake{body: usersMe(displayWSID, displayWSName, displayBotName)}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/users/me" {
			http.NotFound(w, r)
			return
		}
		fake.mu.Lock()
		body := fake.body
		fake.mu.Unlock()
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(up.Close)
	old := identityProbeBaseURL
	identityProbeBaseURL = up.URL
	t.Cleanup(func() { identityProbeBaseURL = old })

	e := newKEnv(t, tdb)
	if _, err := e.st.SetBrokerConfig(context.Background(), e.vaultID,
		`[{"name":"notion-read","host":"api.notion.com/v1/pages/{id}","methods":["GET"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}]`); err != nil {
		t.Fatal(err)
	}
	e.setCreds("default", map[string]string{"NOTION_TOKEN": displayToken})
	return e, fake
}

// metadataEntries returns the NOTION_TOKEN entry from every metadata view a
// caller can get: the list, and the single-key read.
func metadataEntries(t *testing.T, e *kenv) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for name, path := range map[string]string{
		"list":       "/v1/credentials?vault=default",
		"single key": "/v1/credentials?vault=default&reveal=true&key=NOTION_TOKEN",
	} {
		rec := e.do(http.MethodGet, path, "", e.ownerToken)
		if strings.Contains(rec.Body.String(), displayToken) {
			t.Errorf("%s metadata response contains the credential value", name)
		}
		if rec.Code != http.StatusOK {
			out[name] = nil
			continue
		}
		var resp struct {
			Credentials []map[string]any `json:"credentials"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		for _, c := range resp.Credentials {
			if c["key"] == "NOTION_TOKEN" {
				out[name] = c
			}
		}
	}
	return out
}

func identityOf(entry map[string]any) map[string]any {
	if entry == nil {
		return nil
	}
	id, _ := entry["identity"].(map[string]any)
	return id
}

func TestIdentityDisplay_MetadataReturnsAllFourValues(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e, _ := newDisplayEnv(t, tdb)
		if err := e.srv.runIdentityProbe(context.Background(), e.vaultID, "NOTION_TOKEN"); err != nil {
			t.Fatalf("identity probe: %v", err)
		}
		wantDigest, err := identity.NotionDigest([]byte(usersMe(displayWSID, displayWSName, displayBotName)))
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{
			"workspace_name":   displayWSName,
			"workspace_id":     displayWSID,
			"integration_name": displayBotName,
			"digest":           wantDigest,
		}
		for view, entry := range metadataEntries(t, e) {
			if entry == nil {
				t.Errorf("%s: no metadata entry for NOTION_TOKEN", view)
				continue
			}
			id := identityOf(entry)
			if id == nil {
				t.Errorf("%s: metadata has no identity object; want identity.workspace_name, workspace_id, integration_name and digest", view)
				continue
			}
			for k, v := range want {
				if got, _ := id[k].(string); got != v {
					t.Errorf("%s: identity.%s = %q, want %q", view, k, got, v)
				}
			}
		}
	})
}

// An identity field that carries the credential value is refused: nothing is
// recorded, and no metadata view ever shows the value.
func TestIdentityDisplay_FieldCarryingCredentialValueRefused(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		for name, body := range map[string]string{
			"workspace_name equals the token":     usersMe(displayWSID, displayToken, displayBotName),
			"workspace_id equals the token":       usersMe(displayToken, displayWSName, displayBotName),
			"integration name equals the token":   usersMe(displayWSID, displayWSName, displayToken),
			"workspace_name contains the token":   usersMe(displayWSID, "ws "+displayToken+" x", displayBotName),
			"integration name contains the token": usersMe(displayWSID, displayWSName, "bot-"+displayToken),
		} {
			t.Run(name, func(t *testing.T) {
				e, fake := newDisplayEnv(t, tdb.fresh(t))
				fake.set(body)
				if err := e.srv.runIdentityProbe(context.Background(), e.vaultID, "NOTION_TOKEN"); err == nil {
					t.Error("probe recorded an identity whose field carries the credential value")
				}
				for view, entry := range metadataEntries(t, e) {
					if identityOf(entry) != nil {
						t.Errorf("%s: an identity was recorded from a response that echoes the credential", view)
					}
				}
			})
		}
	})
}

// A response missing any of the three fields records no identity, and a
// previously recorded identity does not survive it.
func TestIdentityDisplay_MissingFieldRecordsNothing(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		for name, body := range map[string]string{
			"no workspace_id":   usersMe("", displayWSName, displayBotName),
			"no workspace_name": usersMe(displayWSID, "", displayBotName),
			"no name":           usersMe(displayWSID, displayWSName, ""),
		} {
			t.Run(name, func(t *testing.T) {
				e, fake := newDisplayEnv(t, tdb.fresh(t))
				if err := e.srv.runIdentityProbe(context.Background(), e.vaultID, "NOTION_TOKEN"); err != nil {
					t.Fatalf("precondition: probe with a complete response: %v", err)
				}
				for view, entry := range metadataEntries(t, e) {
					if identityOf(entry) == nil {
						t.Fatalf("precondition: %s shows no identity after a complete probe", view)
					}
				}
				fake.set(body)
				if err := e.srv.runIdentityProbe(context.Background(), e.vaultID, "NOTION_TOKEN"); err == nil {
					t.Error("probe accepted a /v1/users/me response with a missing field")
				}
				for view, entry := range metadataEntries(t, e) {
					if identityOf(entry) != nil {
						t.Errorf("%s still shows an identity after a probe whose response lacked a field", view)
					}
				}
			})
		}
	})
}

// Fork change 7: a service row edited directly in the database to reach a
// write path, or another host, is refused at injection with no credential
// attached, because the live request is re-checked against the compiled-in
// allowlist.
func TestInjectionTimeAllowlist_DirectRowEditRefused(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		t.Setenv(servicepolicy.EnvMode, servicepolicy.ModeReadonlyAllowlist)
		e := newKEnv(t, tdb)
		e.setCreds("default", map[string]string{"NOTION_TOKEN": displayToken})
		ctx := context.Background()
		inject := func(services, method, host, path string) (*brokercore.InjectResult, error) {
			t.Helper()
			if _, err := e.st.SetBrokerConfig(ctx, e.vaultID, services); err != nil {
				t.Fatal(err)
			}
			return e.srv.CredentialProvider().Inject(brokercore.WithRequestMethod(ctx, method), e.vaultID, host, 443, path)
		}
		attached := func(res *brokercore.InjectResult) bool {
			if res == nil {
				return false
			}
			for _, v := range res.Headers {
				if strings.Contains(v, displayToken) {
					return true
				}
			}
			return false
		}

		const pages = `[{"name":"notion-read","host":"api.notion.com/v1/pages/{id}","methods":["GET"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}]`
		if res, err := inject(pages, "GET", "api.notion.com", "/v1/pages/abc"); err != nil || !attached(res) {
			t.Fatalf("control: allowed GET /v1/pages/{id} did not inject the credential (err %v)", err)
		}

		cases := []struct {
			name, services, method, host, path string
		}{
			{"row widened to POST /v1/search",
				`[{"name":"notion-search","host":"api.notion.com/v1/search","methods":["POST"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}]`,
				"POST", "api.notion.com", "/v1/search"},
			{"row widened to GET /v1/users",
				`[{"name":"notion-users","host":"api.notion.com/v1/users","methods":["GET"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}]`,
				"GET", "api.notion.com", "/v1/users"},
			{"row moved to another host",
				`[{"name":"other","host":"api.example.test/v1/pages/{id}","methods":["GET"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}]`,
				"GET", "api.example.test", "/v1/pages/abc"},
			{"row allows PATCH on pages",
				`[{"name":"notion-write","host":"api.notion.com/v1/pages/{id}","methods":["GET","PATCH"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}]`,
				"PATCH", "api.notion.com", "/v1/pages/abc"},
			{"row with no methods list",
				`[{"name":"notion-any","host":"api.notion.com/v1/pages/{id}","auth":{"type":"bearer","token":"NOTION_TOKEN"}}]`,
				"DELETE", "api.notion.com", "/v1/pages/abc"},
		}
		for _, c := range cases {
			res, err := inject(c.services, c.method, c.host, c.path)
			if attached(res) {
				t.Errorf("%s: %s %s%s was injected with the credential", c.name, c.method, c.host, c.path)
			}
			if err == nil && res != nil && !res.Passthrough {
				t.Errorf("%s: injection returned no refusal", c.name)
			}
		}
	})
}
