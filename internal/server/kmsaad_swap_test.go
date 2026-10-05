//go:build kmsaad

// Row-bound AAD, end to end through the HTTP API on a real store. Each test
// writes through the API, tampers with ciphertext columns directly in the
// database (the threat: write access to the DB or a restored backup, no DEK),
// then reads back through the real credential provider (the proxy injection path). At v0.40.0 every swap is accepted.
//
// Replays restore only the ciphertext/nonce columns. Restoring the ciphertext
// AND the row version together is out of scope (AAD cannot detect a full-row
// rollback; that needs an external monotonic anchor) and is not claimed.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func (e *kenv) copyCredentialCT(fromVaultID, fromKey, toVaultID, toKey string) {
	e.t.Helper()
	var ct, n []byte
	if err := e.tdb.QueryRow(`SELECT ciphertext, nonce FROM credentials WHERE vault_id = ? AND key = ?`, fromVaultID, fromKey).Scan(&ct, &n); err != nil {
		e.t.Fatalf("read %s/%s: %v", fromVaultID, fromKey, err)
	}
	e.tdb.Exec(e.t, `UPDATE credentials SET ciphertext = ?, nonce = ? WHERE vault_id = ? AND key = ?`, ct, n, toVaultID, toKey)
}

// injected resolves key through the server's real CredentialProvider (the
// path the proxy uses) and returns the bearer value it would inject. Reveal
// is not used as the observation channel because stored keys become
// write-only for every role (see kmsaad_writeonly_test.go).
func (e *kenv) injected(vaultName, key string) (string, error) {
	e.t.Helper()
	vid := e.vaultIDByName(vaultName)
	host := slug(key) + ".inject.example.test"
	svc := fmt.Sprintf(`[{"name":"probe-%s","host":"%s","auth":{"type":"bearer","token":"%s"}}]`, slug(key), host, key)
	if _, err := e.st.SetBrokerConfig(context.Background(), vid, svc); err != nil {
		e.t.Fatalf("SetBrokerConfig: %v", err)
	}
	res, err := e.srv.CredentialProvider().Inject(context.Background(), vid, host, 0, "/")
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(res.Headers["Authorization"], "Bearer "), nil
}

func mustInject(t *testing.T, e *kenv, vault, key, want string) {
	t.Helper()
	if got, err := e.injected(vault, key); err != nil || got != want {
		t.Fatalf("control: %s/%s injects %q (err %v), want %q", vault, key, got, err, want)
	}
}

func assertNotInjected(t *testing.T, e *kenv, vault, key, forbidden, what string) {
	t.Helper()
	val, err := e.injected(vault, key)
	if err == nil && val == forbidden {
		t.Errorf("%s: %s/%s injects the swapped-in secret into upstream requests", what, vault, key)
	} else if err == nil {
		t.Errorf("%s: %s/%s injected %q from a tampered row; it must fail to decrypt", what, vault, key, val)
	}
}

func TestKMSAAD_API_RowSwapSameVaultRefused(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := newKEnv(t, tdb)
		e.setCreds("default", map[string]string{"A_KEY": "SENTINEL-AV-TEST-0701-A", "B_KEY": "SENTINEL-AV-TEST-0702-B"})
		mustInject(t, e, "default", "B_KEY", "SENTINEL-AV-TEST-0702-B")
		e.copyCredentialCT(e.vaultID, "A_KEY", e.vaultID, "B_KEY")
		assertNotInjected(t, e, "default", "B_KEY", "SENTINEL-AV-TEST-0701-A", "same-vault row swap")
		mustInject(t, e, "default", "A_KEY", "SENTINEL-AV-TEST-0701-A")
	})
}

func TestKMSAAD_API_CrossVaultSwapRefused(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := newKEnv(t, tdb)
		if rec := e.do(http.MethodPost, "/v1/vaults", `{"name":"other-vault"}`, e.ownerToken); rec.Code/100 != 2 {
			t.Fatalf("create vault: %d %s", rec.Code, rec.Body.String())
		}
		e.setCreds("default", map[string]string{"SAME_KEY": "SENTINEL-AV-TEST-0711-default"})
		e.setCreds("other-vault", map[string]string{"SAME_KEY": "SENTINEL-AV-TEST-0712-other"})
		e.copyCredentialCT(e.vaultIDByName("other-vault"), "SAME_KEY", e.vaultID, "SAME_KEY")
		assertNotInjected(t, e, "default", "SAME_KEY", "SENTINEL-AV-TEST-0712-other", "cross-vault swap (same key name)")
	})
}

func TestKMSAAD_API_OldCiphertextReplayRefused(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := newKEnv(t, tdb)
		e.setCreds("default", map[string]string{"ROTATED_KEY": "SENTINEL-AV-TEST-0721-old"})
		var oldCT, oldN []byte
		if err := e.tdb.QueryRow(`SELECT ciphertext, nonce FROM credentials WHERE vault_id = ? AND key = ?`, e.vaultID, "ROTATED_KEY").Scan(&oldCT, &oldN); err != nil {
			t.Fatal(err)
		}
		e.setCreds("default", map[string]string{"ROTATED_KEY": "SENTINEL-AV-TEST-0722-new"})
		// Roll back ciphertext+nonce only; the row's version column (added by
		// the patch) is left at its current value.
		e.tdb.Exec(t, `UPDATE credentials SET ciphertext = ?, nonce = ? WHERE vault_id = ? AND key = ?`, oldCT, oldN, e.vaultID, "ROTATED_KEY")
		assertNotInjected(t, e, "default", "ROTATED_KEY", "SENTINEL-AV-TEST-0721-old", "ciphertext-only rollback to an earlier version")
	})
}

// OAuth: the refresh token ciphertext copied into the access-token slot
// (credentials.ciphertext) of the same credential.
func TestKMSAAD_API_OAuthRefreshIntoAccessSlotRefused(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		e := newKEnv(t, tdb)
		body := `{"vault":"default","key":"GH_OAUTH","access_token":"SENTINEL-AV-TEST-0731-access","refresh_token":"SENTINEL-AV-TEST-0732-refresh","token_url":"manual"}`
		if rec := e.do(http.MethodPost, "/v1/credentials/oauth/tokens", body, e.ownerToken); rec.Code != http.StatusOK {
			t.Fatalf("token upload: %d %s", rec.Code, rec.Body.String())
		}
		mustInject(t, e, "default", "GH_OAUTH", "SENTINEL-AV-TEST-0731-access")
		var rct, rn []byte
		if err := e.tdb.QueryRow(`SELECT refresh_token_ct, refresh_token_nonce FROM credential_oauth WHERE vault_id = ? AND credential_key = ?`, e.vaultID, "GH_OAUTH").Scan(&rct, &rn); err != nil {
			t.Fatal(err)
		}
		e.tdb.Exec(t, `UPDATE credentials SET ciphertext = ?, nonce = ? WHERE vault_id = ? AND key = ?`, rct, rn, e.vaultID, "GH_OAUTH")
		assertNotInjected(t, e, "default", "GH_OAUTH", "SENTINEL-AV-TEST-0732-refresh", "cross-table/field swap refresh_token_ct -> credentials.ciphertext")
	})
}

func slug(key string) string { return strings.ReplaceAll(strings.ToLower(key), "_", "-") }

func (e *kenv) createProposal(scopedToken, key, value string) int {
	e.t.Helper()
	body := fmt.Sprintf(`{"services":[{"action":"set","name":"svc-%s","host":"%s.example.test","auth":{"type":"bearer","token":"%s"}}],
	  "credentials":[{"action":"set","key":"%s","value":"%s"}],"message":"kmsaad"}`, slug(key), slug(key), key, key, value)
	rec := e.do(http.MethodPost, "/v1/proposals", body, scopedToken)
	if rec.Code != http.StatusCreated {
		e.t.Fatalf("create proposal: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID int `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return resp.ID
}

// Proposal ciphertexts (handle_proposals.go:201, re-encrypted at 482/499).
func TestKMSAAD_API_ProposalCiphertextSwapRefused(t *testing.T) {
	forEachBackend(t, func(t *testing.T, tdb testDB) {
		cases := map[string]func(e *kenv, p1, p2 int){
			"proposal-to-proposal": func(e *kenv, p1, p2 int) {
				var ct, n []byte
				if err := e.tdb.QueryRow(`SELECT ciphertext, nonce FROM proposal_credentials WHERE vault_id = ? AND proposal_id = ? AND key = ?`, e.vaultID, p1, "P_ONE").Scan(&ct, &n); err != nil {
					e.t.Fatal(err)
				}
				e.tdb.Exec(e.t, `UPDATE proposal_credentials SET ciphertext = ?, nonce = ? WHERE vault_id = ? AND proposal_id = ? AND key = ?`, ct, n, e.vaultID, p2, "P_TWO")
			},
			"credentials-to-proposal": func(e *kenv, _, p2 int) {
				var ct, n []byte
				if err := e.tdb.QueryRow(`SELECT ciphertext, nonce FROM credentials WHERE vault_id = ? AND key = ?`, e.vaultID, "EXISTING_SECRET").Scan(&ct, &n); err != nil {
					e.t.Fatal(err)
				}
				e.tdb.Exec(e.t, `UPDATE proposal_credentials SET ciphertext = ?, nonce = ? WHERE vault_id = ? AND proposal_id = ? AND key = ?`, ct, n, e.vaultID, p2, "P_TWO")
			},
		}
		for name, tamper := range cases {
			t.Run(name, func(t *testing.T) {
				e := newKEnv(t, tdb.fresh(t))
				e.setCreds("default", map[string]string{"EXISTING_SECRET": "SENTINEL-AV-TEST-0741-existing"})
				sess, err := e.st.CreateScopedSession(t.Context(), scopedParams(e.vaultID))
				if err != nil {
					t.Fatal(err)
				}
				p1 := e.createProposal(sess.ID, "P_ONE", "SENTINEL-AV-TEST-0742-p1")
				p2 := e.createProposal(sess.ID, "P_TWO", "SENTINEL-AV-TEST-0743-p2")
				tamper(e, p1, p2)
				rec := e.do(http.MethodPost, fmt.Sprintf("/v1/admin/proposals/%d/approve", p2), `{"vault":"default"}`, e.ownerToken)
				v, _ := e.injected("default", "P_TWO")
				if v == "SENTINEL-AV-TEST-0742-p1" || v == "SENTINEL-AV-TEST-0741-existing" {
					t.Errorf("approval applied a swapped proposal ciphertext: P_TWO now injects %q (approve status %d)", v, rec.Code)
				}
				if rec.Code == http.StatusOK {
					t.Errorf("approve of a proposal with a tampered ciphertext returned 200")
				}
			})
		}
	})
}
