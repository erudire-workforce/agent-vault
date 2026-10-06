package server

import (
	"context"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
)

// The probe's conditional identity write and the proposal-delete cleanup
// are raw SQL that differs per dialect; run them on both backends.
//
// Failure modes covered: the write lands for a row whose ID or version has
// moved on; the write is refused for the matching row; the statement does
// not parse or bind on one dialect; ApplyProposal's delete leaves the
// record behind.
func TestCredentialIdentityConditionalWrite_Backends(t *testing.T) {
	forEachBackend(t, func(t *testing.T, db testDB) {
		ctx := context.Background()
		st := db.Open(t)
		w, ok := st.(credentialIdentityWriter)
		if !ok {
			t.Fatalf("%T does not implement the conditional identity write", st)
		}
		v, err := st.CreateVault(ctx, "identity-backends")
		if err != nil {
			t.Fatal(err)
		}
		c, err := st.SetCredentialVersion(ctx, v.ID, "TOKEN", []byte("ct"), []byte("nonce-123456"), 1)
		if err != nil {
			t.Fatal(err)
		}
		rec := func() string {
			s, _ := st.GetVaultSetting(ctx, v.ID, store.CredentialIdentitySettingKey("TOKEN"))
			return s
		}

		for _, tc := range []struct {
			name    string
			id      string
			version uint64
		}{
			{"other row id", "00000000-0000-0000-0000-000000000000", c.Version},
			{"stale version", c.ID, c.Version + 1},
		} {
			if wrote, err := w.SetCredentialIdentity(ctx, v.ID, "TOKEN", tc.id, tc.version, "x:"+tc.name); err != nil || wrote {
				t.Fatalf("%s: wrote=%v err=%v, want no write", tc.name, wrote, err)
			}
			if got := rec(); got != "" {
				t.Fatalf("%s: record %q written for a row that does not match", tc.name, got)
			}
		}

		for _, val := range []string{"first", "second"} { // insert, then update
			if wrote, err := w.SetCredentialIdentity(ctx, v.ID, "TOKEN", c.ID, c.Version, val); err != nil || !wrote {
				t.Fatalf("matching row: wrote=%v err=%v", wrote, err)
			}
			if got := rec(); got != val {
				t.Fatalf("record = %q, want %q", got, val)
			}
		}

		sess, err := st.CreateScopedSession(ctx, store.CreateScopedSessionParams{VaultID: v.ID, VaultRole: "proxy"})
		if err != nil {
			t.Fatal(err)
		}
		p, err := st.CreateProposal(ctx, v.ID, sess.ID, `[]`, `[{"action":"delete","key":"TOKEN"}]`, "delete", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.ApplyProposal(ctx, v.ID, p.ID, `[]`, nil, []string{"TOKEN"}, nil); err != nil {
			t.Fatal(err)
		}
		if got := rec(); got != "" {
			t.Fatalf("identity record %q survived a proposal delete", got)
		}
	})
}
