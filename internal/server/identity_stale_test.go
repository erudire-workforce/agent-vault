// Fork change 6, review follow-up: two checks that no test pinned.
//
//  1. Credential metadata shows an identity only when its record is bound to
//     the credential's current row ID and version (credentialIdentityFor). A
//     record left from an earlier value, or from a deleted row, never shows.
//  2. The identity probe refuses a /v1/users/me field that carries the
//     credential in an encoded form (base64, URL-safe base64, hex,
//     percent-encoded), not only verbatim.
package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// identityShown reports, per metadata view, whether an identity is shown.
func identityShown(t *testing.T, e *kenv) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for view, entry := range metadataEntries(t, e) {
		out[view] = identityOf(entry) != nil
	}
	return out
}

// probeAndCapture records the identity for the current value and returns the
// raw stored record.
func probeAndCapture(t *testing.T, e *kenv) string {
	t.Helper()
	ctx := context.Background()
	if err := e.srv.runIdentityProbe(ctx, e.vaultID, "NOTION_TOKEN"); err != nil {
		t.Fatalf("identity probe: %v", err)
	}
	for view, shown := range identityShown(t, e) {
		if !shown {
			t.Fatalf("control: %s shows no identity right after a successful probe", view)
		}
	}
	raw, err := e.st.GetVaultSetting(ctx, e.vaultID, brokercore.IdentitySettingKey("NOTION_TOKEN"))
	if err != nil || raw == "" {
		t.Fatalf("control: no identity record stored after the probe (%v)", err)
	}
	return raw
}

// restoreRecord writes the earlier record back, as a stale record left by a
// crash or an in-flight probe would be, so only the binding check stands
// between it and the metadata.
func restoreRecord(t *testing.T, e *kenv, raw string) {
	t.Helper()
	if err := e.st.SetVaultSetting(context.Background(), e.vaultID, brokercore.IdentitySettingKey("NOTION_TOKEN"), raw); err != nil {
		t.Fatal(err)
	}
}

// Token A probed at version 1, then token B stored (version 2) with no
// probe: the version-1 record must not be shown for B.
func TestIdentityStale_NewVersionWithoutProbeShowsNoIdentity(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e, _ := newDisplayEnv(t, tdb) // token A stored, probe scheduling off
		raw := probeAndCapture(t, e)

		e.setCreds("default", map[string]string{"NOTION_TOKEN": "SENTINEL-ID-0003-token-b"})
		restoreRecord(t, e, raw)
		for view, shown := range identityShown(t, e) {
			if shown {
				t.Errorf("%s shows the identity recorded for token A after token B was stored without a probe", view)
			}
		}
	})
}

// A credential deleted and recreated gets a new row ID; the old row's record
// must not be shown for the new row, even at the same version.
func TestIdentityStale_DeletedAndRecreatedShowsNoIdentity(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e, _ := newDisplayEnv(t, tdb)
		raw := probeAndCapture(t, e)

		rec := e.do(http.MethodDelete, "/v1/credentials", `{"vault":"default","keys":["NOTION_TOKEN"]}`, e.ownerToken)
		if rec.Code/100 != 2 {
			t.Fatalf("delete credential: %d %s", rec.Code, rec.Body.String())
		}
		e.setCreds("default", map[string]string{"NOTION_TOKEN": displayToken}) // same value, new row
		restoreRecord(t, e, raw)
		for view, shown := range identityShown(t, e) {
			if shown {
				t.Errorf("%s shows the deleted row's identity for the recreated credential", view)
			}
		}
	})
}

// The probe refuses a workspace name or integration name that is the token
// in an encoded form. The token contains characters that every encoding
// changes, so no encoded form contains the raw token.
func TestIdentityProbe_EncodedEchoOfCredentialRefused(t *testing.T) {
	const tok = "SENTINEL-ID-0004/notion+token=1?"
	encodings := map[string]string{
		"base64":          base64.StdEncoding.EncodeToString([]byte(tok)),
		"base64 url":      base64.URLEncoding.EncodeToString([]byte(tok)),
		"hex":             hex.EncodeToString([]byte(tok)),
		"percent-encoded": url.QueryEscape(tok),
	}
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		for encName, enc := range encodings {
			for field, body := range map[string]string{
				"workspace_name":   usersMe(displayWSID, enc, displayBotName),
				"integration name": usersMe(displayWSID, displayWSName, enc),
			} {
				t.Run(field+" "+encName, func(t *testing.T) {
					e, fake := newDisplayEnv(t, tdb.fresh(t))
					e.setCreds("default", map[string]string{"NOTION_TOKEN": tok})
					fake.set(body)
					if err := e.srv.runIdentityProbe(context.Background(), e.vaultID, "NOTION_TOKEN"); err == nil {
						t.Errorf("probe recorded an identity whose %s is the token, %s", field, encName)
					}
					for view, shown := range identityShown(t, e) {
						if shown {
							t.Errorf("%s shows an identity whose %s is the token, %s", view, field, encName)
						}
					}
				})
			}
		}
	})
}
