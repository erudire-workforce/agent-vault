// Provider-key rotation review follow-up: the bootstrap document is the
// declared state, so a service whose identity_pin is removed from the
// document loses its stored pin on the next Apply. Failure mode: Apply
// writes a pin only when the document carries one, so a pin removed from
// the document (or moved to another key) stays enforced forever.
package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func TestProviderPin_OmittedPinIsCleared(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		ctx := context.Background()
		st := tdb.Open(t)
		if err := Apply(ctx, newFixture(t, st, pinnedDoc(pinA)).opts); err != nil {
			t.Fatalf("Apply with identity_pin: %v", err)
		}
		v, err := st.GetVault(ctx, "example-integration")
		if err != nil || v == nil {
			t.Fatalf("vault: %v", err)
		}
		const key = "credential_identity_pin:NOTION_TOKEN"
		if got, _ := st.GetVaultSetting(ctx, v.ID, key); got != pinA {
			t.Fatalf("control: stored pin %q; want the document's pin", got)
		}
		if err := Apply(ctx, newFixture(t, st, docJSON).opts); err != nil {
			t.Fatalf("re-Apply without identity_pin: %v", err)
		}
		got, err := st.GetVaultSetting(ctx, v.ID, key)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			t.Fatal(err)
		}
		if got != "" {
			t.Errorf("the document no longer pins NOTION_TOKEN, but the stored pin %q is still enforced", got)
		}
	})
}
