//go:build kmsaad

// Runtime tests for row-bound AAD on the OAuth refresh path
// (brokercore/credential.go maybeRefreshOAuth). They compile against v0.40.0
// and fail at runtime: the refresh path decrypts refresh_token_ct and
// client_secret_ct with nil AAD, so ciphertexts moved between rows or fields
// are accepted and sent to a token endpoint.
//
// The fixtures write ciphertexts with crypto.Encrypt (nil AAD), i.e. what the
// v0.40.0 write paths produce. Once the patch lands, the implementer switches
// the helper encOAuthField to the AAD form (crypto.EncryptAAD with
// crypto.AAD{Table:"credential_oauth", Field:..., VaultID, Key, Version}) so
// the control assertions keep passing and the swap assertions keep failing
// only when binding is missing. See FAILURE_MODES_KMS_AAD.md.
package brokercore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

type fakeOAuthStore struct {
	mu     sync.Mutex
	rows   map[string]*store.CredentialOAuth // vaultID|key
	creds  *fakeCredStore
	errors map[string]string
}

func (f *fakeOAuthStore) GetCredentialOAuth(_ context.Context, vaultID, key string) (*store.CredentialOAuth, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rows[vaultID+"|"+key]
	if !ok {
		return nil, context.Canceled
	}
	cp := *r
	return &cp, nil
}

func (f *fakeOAuthStore) UpdateCredentialOAuthTokens(_ context.Context, vaultID, key string, accessCT, accessNonce, refreshCT, refreshNonce []byte, expiresAt *time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.creds.creds[vaultID+"|"+key]; ok {
		c.Ciphertext, c.Nonce = accessCT, accessNonce
	}
	if r, ok := f.rows[vaultID+"|"+key]; ok {
		if refreshCT != nil {
			r.RefreshTokenCT, r.RefreshTokenNonce = refreshCT, refreshNonce
		}
		r.TokenExpiresAt = expiresAt
	}
	return nil
}

func (f *fakeOAuthStore) UpdateCredentialOAuthError(_ context.Context, vaultID, key string, errMsg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errors[vaultID+"|"+key] = errMsg
	if r, ok := f.rows[vaultID+"|"+key]; ok {
		r.LastRefreshError = errMsg
	}
	return nil
}

// tokenRecorder is a token endpoint that records every refresh_token and
// client_secret it receives.
type tokenRecorder struct {
	mu       sync.Mutex
	srv      *httptest.Server
	received []string
	status   int
	body     string
}

func newTokenRecorder(t *testing.T) *tokenRecorder {
	t.Helper()
	r := &tokenRecorder{status: 200}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		r.mu.Lock()
		r.received = append(r.received, req.Form.Get("refresh_token"), req.Form.Get("client_secret"))
		status, body := r.status, r.body
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fresh-access", "token_type": "bearer", "expires_in": 3600})
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *tokenRecorder) saw(s string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.received {
		if v == s {
			return true
		}
	}
	return false
}

func encOAuthField(t *testing.T, k []byte, value string) ([]byte, []byte) {
	t.Helper()
	ct, n, err := crypto.Encrypt([]byte(value), k)
	if err != nil {
		t.Fatal(err)
	}
	return ct, n
}

type oauthFixture struct {
	k     []byte
	creds *fakeCredStore
	oa    *fakeOAuthStore
	p     *StoreCredentialProvider
}

func newOAuthFixture(t *testing.T) *oauthFixture {
	t.Helper()
	k := make32(0x5a)
	creds := newFakeCredStore()
	oa := &fakeOAuthStore{rows: map[string]*store.CredentialOAuth{}, creds: creds, errors: map[string]string{}}
	p := &StoreCredentialProvider{Store: creds, OAuthStore: oa, EncKey: k, Refresher: oauth.NewRefresher()}
	return &oauthFixture{k: k, creds: creds, oa: oa, p: p}
}

// addExpiredOAuth registers an OAuth credential whose access token is about
// to expire, so the next Inject triggers a refresh against tokenURL.
func (fx *oauthFixture) addExpiredOAuth(t *testing.T, vaultID, key, host, tokenURL, refresh, clientSecret string) {
	t.Helper()
	fx.creds.setCred(t, fx.k, vaultID, key, "stale-access-"+key)
	fx.creds.creds[vaultID+"|"+key].Type = "oauth"
	rCT, rN := encOAuthField(t, fx.k, refresh)
	csCT, csN := encOAuthField(t, fx.k, clientSecret)
	exp := time.Now().Add(-time.Minute)
	fx.oa.rows[vaultID+"|"+key] = &store.CredentialOAuth{
		VaultID: vaultID, CredentialKey: key, TokenURL: tokenURL, ClientID: "cid-" + key,
		ClientSecretCT: csCT, ClientSecretNonce: csN, RefreshTokenCT: rCT, RefreshTokenNonce: rN,
		TokenAuthMethod: "client_secret_post", TokenExpiresAt: &exp,
	}
	b, _ := json.Marshal(existingServices(fx.creds, vaultID, broker.Service{Name: strings.ToLower(key), Host: host, Auth: broker.Auth{Type: "bearer", Token: key}}))
	fx.creds.brokerCfg[vaultID] = &store.BrokerConfig{VaultID: vaultID, ServicesJSON: string(b)}
}

func existingServices(f *fakeCredStore, vaultID string, add broker.Service) []broker.Service {
	var svcs []broker.Service
	if c, ok := f.brokerCfg[vaultID]; ok {
		_ = json.Unmarshal([]byte(c.ServicesJSON), &svcs)
	}
	return append(svcs, add)
}

// Control for the swap tests: an untouched row refreshes with its own token.
func TestKMSAAD_OAuthRefresh_Control(t *testing.T) {
	fx := newOAuthFixture(t)
	tok := newTokenRecorder(t)
	fx.addExpiredOAuth(t, "v1", "A_OAUTH", "a.example.test", tok.srv.URL, "SENTINEL-AV-TEST-0301-refresh-A", "SENTINEL-AV-TEST-0302-cs-A")
	res, err := fx.p.Inject(context.Background(), "v1", "a.example.test", 0, "/")
	if err != nil {
		t.Fatalf("control refresh failed: %v", err)
	}
	if res.Headers["Authorization"] != "Bearer fresh-access" || !tok.saw("SENTINEL-AV-TEST-0301-refresh-A") {
		t.Fatalf("control: refresh did not use row A's token: %v", res.Headers)
	}
}

// Credential A's refresh_token_ct copied into credential B's row. B's token
// endpoint (which an attacker who can edit B's config controls) must never
// receive A's refresh token.
func TestKMSAAD_OAuthRefresh_CrossRowRefreshTokenSwapRefused(t *testing.T) {
	fx := newOAuthFixture(t)
	tokA, tokB := newTokenRecorder(t), newTokenRecorder(t)
	fx.addExpiredOAuth(t, "v1", "A_OAUTH", "a.example.test", tokA.srv.URL, "SENTINEL-AV-TEST-0311-refresh-A", "cs-A")
	fx.addExpiredOAuth(t, "v1", "B_OAUTH", "b.example.test", tokB.srv.URL, "refresh-B", "cs-B")
	a, b := fx.oa.rows["v1|A_OAUTH"], fx.oa.rows["v1|B_OAUTH"]
	b.RefreshTokenCT, b.RefreshTokenNonce = a.RefreshTokenCT, a.RefreshTokenNonce

	_, err := fx.p.Inject(context.Background(), "v1", "b.example.test", 0, "/")
	if tokB.saw("SENTINEL-AV-TEST-0311-refresh-A") {
		t.Fatal("credential A's refresh token was decrypted from credential B's row and sent to B's token endpoint")
	}
	if err == nil {
		t.Fatal("refresh with a swapped refresh_token_ct succeeded")
	}
}

// Cross-vault variant: same key name in two vaults.
func TestKMSAAD_OAuthRefresh_CrossVaultRefreshTokenSwapRefused(t *testing.T) {
	fx := newOAuthFixture(t)
	tok1, tok2 := newTokenRecorder(t), newTokenRecorder(t)
	fx.addExpiredOAuth(t, "vault-1", "GH_OAUTH", "gh1.example.test", tok1.srv.URL, "SENTINEL-AV-TEST-0321-refresh-v1", "cs-1")
	fx.addExpiredOAuth(t, "vault-2", "GH_OAUTH", "gh2.example.test", tok2.srv.URL, "refresh-v2", "cs-2")
	v1, v2 := fx.oa.rows["vault-1|GH_OAUTH"], fx.oa.rows["vault-2|GH_OAUTH"]
	v2.RefreshTokenCT, v2.RefreshTokenNonce = v1.RefreshTokenCT, v1.RefreshTokenNonce

	_, err := fx.p.Inject(context.Background(), "vault-2", "gh2.example.test", 0, "/")
	if tok2.saw("SENTINEL-AV-TEST-0321-refresh-v1") {
		t.Fatal("vault-1's refresh token was accepted from vault-2's row and sent to vault-2's token endpoint")
	}
	if err == nil {
		t.Fatal("refresh with a cross-vault refresh_token_ct succeeded")
	}
}

// Cross-field: client_secret_ct copied into refresh_token_ct of the same row.
func TestKMSAAD_OAuthRefresh_ClientSecretIntoRefreshTokenRefused(t *testing.T) {
	fx := newOAuthFixture(t)
	tok := newTokenRecorder(t)
	fx.addExpiredOAuth(t, "v1", "A_OAUTH", "a.example.test", tok.srv.URL, "refresh-A", "SENTINEL-AV-TEST-0331-cs-A")
	a := fx.oa.rows["v1|A_OAUTH"]
	a.RefreshTokenCT, a.RefreshTokenNonce = a.ClientSecretCT, a.ClientSecretNonce

	tok.mu.Lock()
	tok.received = nil
	tok.mu.Unlock()
	_, err := fx.p.Inject(context.Background(), "v1", "a.example.test", 0, "/")
	tok.mu.Lock()
	sentAsRefresh := len(tok.received) >= 1 && tok.received[0] == "SENTINEL-AV-TEST-0331-cs-A"
	tok.mu.Unlock()
	if sentAsRefresh {
		t.Fatal("client_secret_ct decrypted as refresh_token_ct (cross-field swap accepted)")
	}
	if err == nil {
		t.Fatal("refresh with client_secret_ct in the refresh_token_ct slot succeeded")
	}
}

// Old-version replay: the row's refresh token is rotated by a successful
// refresh, then the old refresh_token_ct is restored. Must be refused.
func TestKMSAAD_OAuthRefresh_OldVersionReplayRefused(t *testing.T) {
	fx := newOAuthFixture(t)
	tok := newTokenRecorder(t)
	fx.addExpiredOAuth(t, "v1", "A_OAUTH", "a.example.test", tok.srv.URL, "SENTINEL-AV-TEST-0341-refresh-old", "cs-A")
	old := *fx.oa.rows["v1|A_OAUTH"]

	tok.body = `{"access_token":"fresh-access","refresh_token":"refresh-new","expires_in":3600}`
	if _, err := fx.p.Inject(context.Background(), "v1", "a.example.test", 0, "/"); err != nil {
		t.Fatalf("precondition: first refresh failed: %v", err)
	}
	// Restore the earlier ciphertext and force another refresh.
	r := fx.oa.rows["v1|A_OAUTH"]
	r.RefreshTokenCT, r.RefreshTokenNonce = old.RefreshTokenCT, old.RefreshTokenNonce
	exp := time.Now().Add(-time.Minute)
	r.TokenExpiresAt = &exp
	tok.mu.Lock()
	tok.received = nil
	tok.mu.Unlock()

	_, err := fx.p.Inject(context.Background(), "v1", "a.example.test", 0, "/")
	if tok.saw("SENTINEL-AV-TEST-0341-refresh-old") {
		t.Fatal("restored (older-version) refresh_token_ct was accepted and sent to the token endpoint")
	}
	if err == nil {
		t.Fatal("refresh with a replayed old refresh_token_ct succeeded")
	}
}

// A failing token endpoint that echoes the refresh token in its error body
// must not cause the token to be persisted as plaintext in
// credential_oauth.last_refresh_error (which the credentials list returns).
func TestKMSAAD_OAuthRefresh_ErrorBodyNotPersisted(t *testing.T) {
	fx := newOAuthFixture(t)
	tok := newTokenRecorder(t)
	fx.addExpiredOAuth(t, "v1", "A_OAUTH", "a.example.test", tok.srv.URL, "SENTINEL-AV-TEST-0351-refresh", "SENTINEL-AV-TEST-0352-cs")
	tok.status = 400
	tok.body = `{"error":"invalid_grant","error_description":"refresh_token SENTINEL-AV-TEST-0351-refresh with client_secret SENTINEL-AV-TEST-0352-cs is revoked"}`

	_, err := fx.p.Inject(context.Background(), "v1", "a.example.test", 0, "/")
	if err == nil {
		t.Fatal("precondition: refresh should fail")
	}
	stored := fx.oa.errors["v1|A_OAUTH"]
	for _, s := range []string{"SENTINEL-AV-TEST-0351-refresh", "SENTINEL-AV-TEST-0352-cs"} {
		if strings.Contains(stored, s) {
			t.Errorf("last_refresh_error persisted a secret from the token endpoint body: %q", stored)
		}
		if strings.Contains(err.Error(), s) {
			t.Errorf("Inject error carries a secret from the token endpoint body: %v", err)
		}
	}
}
