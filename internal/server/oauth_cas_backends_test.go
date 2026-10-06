package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// racingStore lets another writer move the OAuth rows just before each of
// the first `races` token writes, as a concurrent refresh would.
type racingStore struct {
	Store
	races int
	race  func()
	calls int
}

func (r *racingStore) UpdateCredentialOAuthTokens(ctx context.Context, vaultID, key string, u store.OAuthTokenUpdate) error {
	r.calls++
	if r.races > 0 {
		r.races--
		r.race()
	}
	return r.Store.UpdateCredentialOAuthTokens(ctx, vaultID, key, u)
}

// The OAuth compare-and-set SQL and the handlers' bounded retry, on both
// backends.
//
// Failure modes covered: a write sealed for a stale version lands (SQL
// CAS missing on one dialect); a conflict is surfaced instead of retried
// with a re-read and re-seal; the retry is unbounded; the value left in the
// row does not decrypt at the row's version.
func TestOAuthCompareAndSet_Backends(t *testing.T) {
	forEachBackend(t, func(t *testing.T, db testDB) {
		ctx := context.Background()
		st := db.Open(t)
		key := make([]byte, 32)
		v, err := st.CreateVault(ctx, "oauth-cas")
		if err != nil {
			t.Fatal(err)
		}
		const k = "EXAMPLE_OAUTH"
		cs1, csn1, err := store.OAuthClientSecretAAD(v.ID, k, 1).Seal([]byte("client-secret"), key)
		if err != nil {
			t.Fatal(err)
		}
		row := &store.CredentialOAuth{VaultID: v.ID, CredentialKey: k, TokenURL: "https://token.example.test/token", ClientID: "cid",
			ClientSecretCT: cs1, ClientSecretNonce: csn1, ClientSecretVersion: 1}
		if err := st.SetCredentialOAuth(ctx, row); err != nil {
			t.Fatalf("first config write: %v", err)
		}
		if err := st.SetCredentialOAuth(ctx, row); !errors.Is(err, store.ErrVersionConflict) {
			t.Fatalf("second config write sealed for the same client_secret_version: %v, want ErrVersionConflict", err)
		}

		// Another writer stores its own access token at the next version.
		other := func() {
			c, err := st.GetCredential(ctx, v.ID, k)
			if err != nil {
				t.Fatal(err)
			}
			ct, n, err := store.CredentialValueAAD(v.ID, k, c.Version+1).Seal([]byte("other-writer"), key)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.UpdateCredentialOAuthTokens(ctx, v.ID, k, store.OAuthTokenUpdate{AccessCT: ct, AccessNonce: n, AccessVersion: c.Version + 1}); err != nil {
				t.Fatalf("racing writer: %v", err)
			}
		}

		rs := &racingStore{Store: st, races: 1, race: other}
		srv := newTestServer(withStore(rs), withEncKey(key))
		exp := time.Now().Add(time.Hour)
		if err := srv.storeOAuthTokens(ctx, v.ID, k, []byte("access-mine"), []byte("refresh-mine"), &exp); err != nil {
			t.Fatalf("write after one conflict: %v (calls %d)", err, rs.calls)
		}
		if rs.calls != 2 {
			t.Fatalf("token writes = %d, want 2 (one conflict, one retry)", rs.calls)
		}
		c, _ := st.GetCredential(ctx, v.ID, k)
		got, err := store.CredentialValueAAD(v.ID, k, c.Version).Open(c.Ciphertext, c.Nonce, key)
		if err != nil || string(got) != "access-mine" {
			t.Fatalf("stored access token = %q, %v; want the retried value at version %d", got, err, c.Version)
		}
		co, _ := st.GetCredentialOAuth(ctx, v.ID, k)
		if r, err := store.OAuthRefreshTokenAAD(v.ID, k, co.Version).Open(co.RefreshTokenCT, co.RefreshTokenNonce, key); err != nil || string(r) != "refresh-mine" {
			t.Fatalf("stored refresh token = %q, %v", r, err)
		}

		// A writer that loses every race gives up after a bounded number of
		// attempts and reports the conflict.
		rs = &racingStore{Store: st, races: 1 << 20, race: other}
		srv = newTestServer(withStore(rs), withEncKey(key))
		if err := srv.storeOAuthTokens(ctx, v.ID, k, []byte("access-never"), nil, &exp); !errors.Is(err, store.ErrVersionConflict) {
			t.Fatalf("always-conflicting write: %v, want ErrVersionConflict", err)
		}
		if rs.calls != oauthWriteAttempts {
			t.Fatalf("attempts = %d, want %d", rs.calls, oauthWriteAttempts)
		}
	})
}
