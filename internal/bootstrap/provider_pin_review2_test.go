// Provider-key rotation review follow-up: a bootstrap document that omits
// identity_pin keeps the pin already stored. Only an explicit pin change
// (a document carrying a different identity_pin) alters it; silently
// un-pinning would weaken the identity check. Failure mode: Apply clears
// the pin setting whenever a service carries no identity_pin, so a
// re-apply of an older or partial document stops enforcing the pin.
package bootstrap

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestProviderPin_OmittedPinIsKept(t *testing.T) {
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
		if got, _ := st.GetVaultSetting(ctx, v.ID, key); got != pinA {
			t.Fatalf("a document omitting identity_pin changed the stored pin to %q; it must keep the existing pin", got)
		}

		// Still enforced: a stored value with no identity matching the pin
		// is not injected.
		encKey := make([]byte, 32)
		_, _ = rand.Read(encKey)
		ct, nonce, err := store.CredentialValueAAD(v.ID, "NOTION_TOKEN", 1).Seal([]byte("SENTINEL-PIN-0001-token"), encKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.SetCredentialVersion(ctx, v.ID, "NOTION_TOKEN", ct, nonce, 1); err != nil {
			t.Fatal(err)
		}
		p := brokercore.NewStoreCredentialProvider(st, encKey)
		res, err := p.Inject(brokercore.WithRequestMethod(ctx, http.MethodGet), v.ID, "api.notion.com", 443, "/v1/pages/abc")
		if !errors.Is(err, brokercore.ErrIdentityMismatch) {
			t.Errorf("after re-applying a document without identity_pin the pin is not enforced (inject err %v)", err)
		}
		if res != nil && len(res.Headers) > 0 {
			t.Error("a value with no identity matching the kept pin was injected")
		}
	})
}
