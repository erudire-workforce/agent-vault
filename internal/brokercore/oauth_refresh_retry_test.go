package brokercore

import (
	"context"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
)

// racingOAuthStore moves the credential row to a new version just before
// the first `races` token writes, as a concurrent writer would.
type racingOAuthStore struct {
	*fakeOAuthStore
	races int
	calls int
}

func (r *racingOAuthStore) UpdateCredentialOAuthTokens(ctx context.Context, vaultID, key string, u store.OAuthTokenUpdate) error {
	r.calls++
	if r.races > 0 {
		r.races--
		r.mu.Lock()
		r.creds.creds[vaultID+"|"+key].Version++
		r.mu.Unlock()
	}
	return r.fakeOAuthStore.UpdateCredentialOAuthTokens(ctx, vaultID, key, u)
}

// A refresh whose token write loses a compare-and-set re-reads the row,
// re-seals the minted token for the new version and stores it; one that
// keeps losing gives up after oauthWriteAttempts writes.
func TestOAuthRefresh_RetriesOnVersionConflict(t *testing.T) {
	fx := newOAuthFixture(t)
	tok := newTokenRecorder(t)
	fx.addExpiredOAuth(t, "v1", "A_OAUTH", "a.example.test", tok.srv.URL, "refresh-A", "cs-A")
	rs := &racingOAuthStore{fakeOAuthStore: fx.oa, races: 1}
	fx.p.OAuthStore = rs

	res, err := fx.p.Inject(context.Background(), "v1", "a.example.test", 0, "/")
	if err != nil {
		t.Fatalf("refresh after one conflict: %v", err)
	}
	if res.Headers["Authorization"] != "Bearer fresh-access" || rs.calls != 2 {
		t.Fatalf("headers %v after %d writes; want the fresh token after 2", res.Headers, rs.calls)
	}
	c := fx.creds.creds["v1|A_OAUTH"]
	if got, err := store.CredentialValueAAD("v1", "A_OAUTH", c.Version).Open(c.Ciphertext, c.Nonce, fx.k); err != nil || string(got) != "fresh-access" {
		t.Fatalf("stored access token = %q, %v at version %d", got, err, c.Version)
	}

	fx2 := newOAuthFixture(t)
	tok2 := newTokenRecorder(t)
	fx2.addExpiredOAuth(t, "v1", "B_OAUTH", "b.example.test", tok2.srv.URL, "refresh-B", "cs-B")
	rs2 := &racingOAuthStore{fakeOAuthStore: fx2.oa, races: 1 << 20}
	fx2.p.OAuthStore = rs2
	if _, err := fx2.p.Inject(context.Background(), "v1", "b.example.test", 0, "/"); err == nil {
		t.Fatal("refresh that lost every compare-and-set reported success")
	}
	if rs2.calls != oauthWriteAttempts {
		t.Fatalf("writes = %d, want %d", rs2.calls, oauthWriteAttempts)
	}
}
