// Startup must refuse when the configured KMS key is not Enabled
// (Disabled, PendingDeletion, PendingImport) and when DescribeKey fails.
// Run with: go test -tags aadkms ./cmd/
//
// The KMS is the existing in-memory fake (fakeAWSKMS, reached through
// AWS_ENDPOINT_URL_KMS). A wrapper in front of it answers DescribeKey with
// the key state under test and forwards every other operation, so Encrypt
// and Decrypt keep working: the refusal must come from an explicit key-state
// check, not from a later KMS error.
package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type keyStateKMS struct {
	inner     *fakeAWSKMS
	srv       *httptest.Server
	mu        sync.Mutex
	state     string // KeyState DescribeKey reports
	fail      bool   // DescribeKey returns an error
	describes int
}

func newKeyStateKMS(t *testing.T) *keyStateKMS {
	t.Helper()
	k := &keyStateKMS{inner: newFakeAWSKMS(t), state: "Enabled"}
	k.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != "TrentService.DescribeKey" {
			k.inner.ServeHTTP(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		k.mu.Lock()
		k.describes++
		state, fail := k.state, k.fail
		k.mu.Unlock()
		if fail {
			kmsErr(w, "AccessDeniedException", "not authorized to perform kms:DescribeKey")
			return
		}
		var req struct{ KeyId string }
		_ = json.Unmarshal(body, &req)
		id, ok := k.inner.resolve(req.KeyId)
		if !ok {
			kmsErr(w, "NotFoundException", "key not found")
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_ = json.NewEncoder(w).Encode(map[string]any{"KeyMetadata": map[string]any{
			"KeyId": id, "Arn": fakeARN(id), "Enabled": state == "Enabled", "KeyState": state,
			"KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "SYMMETRIC_DEFAULT",
		}})
	}))
	t.Cleanup(k.srv.Close)
	return k
}

func (k *keyStateKMS) set(state string, fail bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.state, k.fail = state, fail
}

func (k *keyStateKMS) describeCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.describes
}

var notEnabledStates = []string{"Disabled", "PendingDeletion", "PendingImport"}

// Known-positive for the fake: DescribeKey really reports the state under
// test and the error case really errors, so the startup tests cannot pass
// against a fake that always says Enabled.
func TestAADKMS_FakeDescribeKeyReportsState(t *testing.T) {
	k := newKeyStateKMS(t)
	describe := func() (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodPost, k.srv.URL, strings.NewReader(`{"KeyId":"`+fakeAliasA+`"}`))
		req.Header.Set("X-Amz-Target", "TrentService.DescribeKey")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	for _, state := range notEnabledStates {
		k.set(state, false)
		code, out := describe()
		md, _ := out["KeyMetadata"].(map[string]any)
		if code != http.StatusOK || md["KeyState"] != state || md["Enabled"] != false {
			t.Fatalf("fake DescribeKey for %s returned %d %v", state, code, out)
		}
	}
	k.set("Enabled", true)
	if code, _ := describe(); code == http.StatusOK {
		t.Fatal("fake DescribeKey did not fail when told to")
	}
}

// Known-bad cases on a fresh store: each non-Enabled state refuses setup
// and persists no master key record. The Enabled control succeeds.
func TestAADKMS_FreshStartupRefusesKeyNotEnabled(t *testing.T) {
	isolateEnv(t)
	for _, state := range notEnabledStates {
		t.Run(state, func(t *testing.T) {
			k := newKeyStateKMS(t)
			k.set(state, false)
			kmsMode(t, k.srv.URL, fakeAliasA, envNameProd)
			db := newSQLiteTestDB(t).Open(t)
			mk, err := unlockOrSetup(quietCmd(), db, false)
			if err == nil {
				mk.Wipe()
				t.Errorf("fresh startup succeeded with the KMS key in state %s (DescribeKey called %d times)", state, k.describeCount())
			} else if !strings.Contains(err.Error(), state) {
				t.Errorf("refusal %q does not name the key state %s", err, state)
			}
			if rec, _ := db.GetMasterKeyRecord(t.Context()); rec != nil {
				t.Errorf("a master key record was persisted with the key in state %s", state)
			}
		})
	}

	t.Run("Enabled control", func(t *testing.T) {
		k := newKeyStateKMS(t)
		kmsMode(t, k.srv.URL, fakeAliasA, envNameProd)
		mk, err := unlockOrSetup(quietCmd(), newSQLiteTestDB(t).Open(t), false)
		if err != nil {
			t.Fatalf("control: startup with an Enabled key failed: %v", err)
		}
		mk.Wipe()
		if k.describeCount() == 0 {
			t.Error("startup never called DescribeKey, so it cannot have checked the key state")
		}
	})
}

// After a normal setup, a restart with the key moved out of Enabled is
// refused even though Decrypt would still answer.
func TestAADKMS_RestartRefusesKeyNotEnabled(t *testing.T) {
	isolateEnv(t)
	for _, state := range notEnabledStates {
		t.Run(state, func(t *testing.T) {
			k := newKeyStateKMS(t)
			tdb := newSQLiteTestDB(t)
			kmsMode(t, k.srv.URL, fakeAliasA, envNameProd)
			mk, err := unlockOrSetup(quietCmd(), tdb.Open(t), false)
			if err != nil {
				t.Fatalf("precondition: setup with an Enabled key: %v", err)
			}
			mk.Wipe()

			k.set(state, false)
			if mk, err := unlockOrSetup(quietCmd(), tdb.Open(t), false); err == nil {
				mk.Wipe()
				t.Errorf("restart succeeded with the KMS key in state %s", state)
			}
		})
	}
}

// A DescribeKey failure refuses startup rather than proceeding unchecked.
func TestAADKMS_DescribeKeyFailureRefusesStartup(t *testing.T) {
	isolateEnv(t)
	k := newKeyStateKMS(t)
	k.set("Enabled", true)
	kmsMode(t, k.srv.URL, fakeAliasA, envNameProd)
	db := newSQLiteTestDB(t).Open(t)
	mk, err := unlockOrSetup(quietCmd(), db, false)
	if err == nil {
		mk.Wipe()
		t.Errorf("startup proceeded although DescribeKey failed (called %d times)", k.describeCount())
	}
	if rec, _ := db.GetMasterKeyRecord(t.Context()); rec != nil {
		t.Error("a master key record was persisted although DescribeKey failed")
	}
}
