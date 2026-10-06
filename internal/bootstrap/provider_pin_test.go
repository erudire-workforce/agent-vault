// Provider-key rotation (fork change 17): the pin a pasted key must match
// comes from the bootstrap document. A service may carry identity_pin, the
// expected identity digest (64 lowercase hex) of the account its credential
// acts as. Apply stores it as the vault setting
// "credential_identity_pin:<credential_key>", which the server checks at
// paste and injection (internal/server/provider_rotation_test.go).
//
// Failure modes: the pin is not accepted in the document, or is accepted and
// dropped; a malformed pin is stored (so no value can ever match, or a
// prefix matches); a re-apply with a changed pin keeps the old one.
package bootstrap

import (
	"context"
	"strings"
	"testing"
)

const (
	pinA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	pinB = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func pinnedDoc(pin string) string {
	return strings.Replace(docJSON, `"credential_key":"NOTION_TOKEN",`,
		`"credential_key":"NOTION_TOKEN","identity_pin":"`+pin+`",`, 1)
}

func TestProviderPin_BootstrapStoresIdentityPin(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		ctx := context.Background()
		st := tdb.Open(t)
		doc := pinnedDoc(pinA)
		if !strings.Contains(doc, pinA) {
			t.Fatal("control: fixture document did not take the pin")
		}
		fx := newFixture(t, st, doc)
		if err := Apply(ctx, fx.opts); err != nil {
			t.Fatalf("Apply with identity_pin: %v", err)
		}
		v, err := st.GetVault(ctx, "example-integration")
		if err != nil || v == nil {
			t.Fatalf("vault: %v", err)
		}
		got, err := st.GetVaultSetting(ctx, v.ID, "credential_identity_pin:NOTION_TOKEN")
		if err != nil || got != pinA {
			t.Fatalf("stored pin = %q (err %v); want the document's identity_pin", got, err)
		}

		fx2 := newFixture(t, st, pinnedDoc(pinB))
		if err := Apply(ctx, fx2.opts); err != nil {
			t.Fatalf("re-Apply with a changed pin: %v", err)
		}
		if got, _ := st.GetVaultSetting(ctx, v.ID, "credential_identity_pin:NOTION_TOKEN"); got != pinB {
			t.Fatalf("after re-Apply the stored pin is %q; want the changed pin", got)
		}
	})
}

func TestProviderPin_MalformedPinRefused(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		ctx := context.Background()
		// Control: the same document with a well-formed pin applies, so a
		// refusal below is about the pin's form.
		if err := Apply(ctx, newFixture(t, tdb.Open(t), pinnedDoc(pinA)).opts); err != nil {
			t.Fatalf("control: a well-formed identity_pin was refused: %v", err)
		}
		for name, pin := range map[string]string{
			"short":     pinA[:63],
			"long":      pinA + "0",
			"uppercase": strings.ToUpper(pinA),
			"not hex":   strings.Repeat("zz", 32),
		} {
			st := tdb.fresh(t).Open(t)
			fx := newFixture(t, st, pinnedDoc(pin))
			if err := Apply(ctx, fx.opts); err == nil {
				t.Errorf("%s pin accepted by Apply", name)
			}
		}
	})
}
