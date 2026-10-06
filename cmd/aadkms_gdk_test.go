//go:build aadkms

// The DEK comes from kms:GenerateDataKey (plaintext used in memory,
// CiphertextBlob stored); kms:Encrypt is never called. The deployment's key
// policy grants only kms:Decrypt, kms:GenerateDataKey and kms:DescribeKey, so
// an Encrypt call is denied on first boot. Run with:
// go test -tags aadkms ./cmd/
package cmd

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var allowedKMSOps = map[string]bool{"GenerateDataKey": true, "Decrypt": true, "DescribeKey": true}

// policyKMS is the in-memory fake behind the deployment's key policy: any
// operation outside allowedKMSOps is denied as AWS would, and every call is
// recorded by the inner fake.
func policyKMS(t *testing.T) (*fakeAWSKMS, string) {
	t.Helper()
	f := newFakeAWSKMS(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "TrentService.")
		if !allowedKMSOps[op] {
			f.mu.Lock()
			f.calls = append(f.calls, kmsCall{Op: op})
			f.mu.Unlock()
			kmsErr(w, "AccessDeniedException", "not authorized to perform kms:"+op+" under the key policy")
			return
		}
		f.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return f, srv.URL
}

func TestAADKMS_SetupAndRestartUseOnlyGenerateDataKeyDecryptDescribeKey(t *testing.T) {
	isolateEnv(t)
	f, endpoint := policyKMS(t)
	kmsMode(t, endpoint, fakeAliasA, envNameProd)
	tdb := newSQLiteTestDB(t)

	mk, err := unlockOrSetup(quietCmd(), tdb.Open(t), false)
	if err != nil {
		t.Errorf("first boot under a key policy without kms:Encrypt failed: %v", err)
	} else {
		mk.Wipe()
	}
	if err == nil {
		mk2, err := unlockOrSetup(quietCmd(), tdb.Open(t), false)
		if err != nil {
			t.Errorf("restart failed: %v", err)
		} else {
			mk2.Wipe()
		}
	}

	want := map[string]string{"service": "agent-vault", "environment": envNameProd}
	sawGDK, sawDecrypt := false, false
	for _, c := range f.snapshot() {
		if !allowedKMSOps[c.Op] {
			t.Errorf("KMS operation %s was called; setup and restart may call only GenerateDataKey, Decrypt and DescribeKey", c.Op)
			continue
		}
		switch c.Op {
		case "GenerateDataKey":
			sawGDK = true
		case "Decrypt":
			sawDecrypt = true
		}
		if (c.Op == "GenerateDataKey" || c.Op == "Decrypt") && !maps.Equal(c.Ctx, want) {
			t.Errorf("KMS %s sent encryption context %v, want exactly %v", c.Op, c.Ctx, want)
		}
	}
	if !sawGDK {
		t.Error("first boot did not obtain the DEK from GenerateDataKey")
	}
	if !sawDecrypt {
		t.Error("restart did not unwrap the stored CiphertextBlob with Decrypt")
	}
}

// Known positive: the policy fake denies and records an Encrypt call, so the
// test above cannot pass while Encrypt is still used.
func TestAADKMS_PolicyFakeRecordsAndDeniesEncrypt(t *testing.T) {
	f, endpoint := policyKMS(t)
	req, _ := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{"KeyId":"`+fakeAliasA+`","Plaintext":"AAAA"}`))
	req.Header.Set("X-Amz-Target", "TrentService.Encrypt")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("policy fake allowed Encrypt")
	}
	calls := f.snapshot()
	if len(calls) != 1 || calls[0].Op != "Encrypt" {
		t.Fatalf("policy fake did not record the Encrypt call: %v", calls)
	}
}
