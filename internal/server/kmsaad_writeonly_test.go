//go:build kmsaad

// Stored keys are write-only for every role, including the owner. Read
// endpoints return 403 or metadata only (name, masked hint, version,
// identity digest, timestamps), never a stored value. At v0.40.0
// GET /v1/credentials?reveal=true (handle_credentials.go:114-166, route
// server.go:829) returns plaintext to members and owners.
//
// Not covered: dynamic-credential reveal (needs an Infisical dynamic secret);
// the patch must apply the same rule in revealDynamicCredential and
// enumerateDynamicCredentials.
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func TestKMSAAD_WriteOnly_OwnerRevealRefusedOrMetadataOnly(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := newKEnv(t, tdb)
		e.setCreds("default", map[string]string{"WO_STATIC": "SENTINEL-AV-TEST-1301-static"})
		if rec := e.do(http.MethodPost, "/v1/credentials/oauth/tokens",
			`{"vault":"default","key":"WO_OAUTH","access_token":"SENTINEL-AV-TEST-1302-access","refresh_token":"SENTINEL-AV-TEST-1303-refresh","token_url":"manual"}`,
			e.ownerToken); rec.Code != http.StatusOK {
			t.Fatalf("token upload: %d %s", rec.Code, rec.Body.String())
		}
		for _, path := range []string{
			"/v1/credentials?vault=default&reveal=true",
			"/v1/credentials?vault=default&reveal=true&key=WO_STATIC",
			"/v1/credentials?vault=default&reveal=true&key=WO_OAUTH",
			"/v1/credentials?vault=default",
		} {
			rec := e.do(http.MethodGet, path, "", e.ownerToken)
			if rec.Code == http.StatusForbidden {
				continue
			}
			var resp struct {
				Credentials []map[string]any `json:"credentials"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &resp)
			for _, c := range resp.Credentials {
				for _, f := range []string{"value", "access_token", "refresh_token", "client_secret"} {
					if v, ok := c[f].(string); ok && v != "" && v != oauthSecretSentinel {
						t.Errorf("owner GET %s returned stored field %q=%q; keys are write-only", path, f, v)
					}
				}
			}
		}
	})
}

func TestKMSAAD_WriteOnly_NoStoredValueInAnyResponseBody(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := newKEnv(t, tdb)
		secrets := []string{
			"SENTINEL-AV-TEST-1311-static", "SENTINEL-AV-TEST-1312-access", "SENTINEL-AV-TEST-1313-refresh",
			"SENTINEL-AV-TEST-1314-proposal", "SENTINEL-AV-TEST-1315-client-secret",
		}
		e.setCreds("default", map[string]string{"WO_STATIC": secrets[0]})
		e.do(http.MethodPost, "/v1/credentials/oauth/tokens",
			fmt.Sprintf(`{"vault":"default","key":"WO_OAUTH","access_token":"%s","refresh_token":"%s","token_url":"manual","client_secret":"%s"}`, secrets[1], secrets[2], secrets[4]),
			e.ownerToken)
		sess, err := e.st.CreateScopedSession(t.Context(), scopedParams(e.vaultID))
		if err != nil {
			t.Fatal(err)
		}
		pid := e.createProposal(sess.ID, "WO_PROPOSED", secrets[3])

		// Responses captured so far include the write requests; start the scan
		// from the read surface only.
		e.responses = &syncBuffer{}
		for _, path := range []string{
			"/v1/credentials?vault=default",
			"/v1/credentials?vault=default&reveal=true",
			"/v1/credentials?vault=default&reveal=true&key=WO_STATIC",
			"/v1/credentials?vault=default&reveal=true&key=WO_OAUTH",
			"/v1/credentials/oauth/status?vault=default&key=WO_OAUTH",
			fmt.Sprintf("/v1/proposals/%d?vault=default", pid),
			"/v1/proposals?vault=default",
			fmt.Sprintf("/v1/admin/proposals/%d?vault=default", pid),
			"/v1/admin/proposals?vault=default",
			"/v1/vaults",
			"/v1/vaults/default/context",
			"/v1/vaults/default/services",
			"/v1/vaults/default/services/credential-usage",
			"/v1/vaults/default/logs",
			"/v1/vaults/default/settings",
			"/",
			"/vaults/default",
			"/agents",
		} {
			e.do(http.MethodGet, path, "", e.ownerToken)
		}
		e.do(http.MethodGet, fmt.Sprintf("/v1/proposals/%d", pid), "", sess.ID)
		if hits := findSentinels(map[string]string{"http responses": e.responses.String()}, secrets); len(hits) > 0 {
			t.Errorf("stored values returned by read endpoints to an owner session: %v", hits)
		}
	})
}
