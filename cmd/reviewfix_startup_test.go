// Review-fix startup tests.
//
// The startup checks are expected in attachServerExtensions (cmd/server.go),
// which both the foreground and detached paths call before serving.
package cmd

import (
	"context"
	"io"
	"log/slog"
	"maps"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/servicepolicy"
	"github.com/Infisical/agent-vault/internal/store"
)

// Blocker 2: the KMS encryption context is exactly
// {"service":"agent-vault","environment":<env>} on every KMS call.
func TestReviewFix_KMSEncryptionContextShape(t *testing.T) {
	isolateEnv(t)
	f := newFakeAWSKMS(t)
	tdb := newSQLiteTestDB(t)
	setupKMSInstance(t, tdb, f, fakeAliasA, envNameProd)
	mk, err := unlockOrSetup(quietCmd(), tdb.Open(t), false)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	mk.Wipe()

	want := map[string]string{"service": "agent-vault", "environment": envNameProd}
	calls := f.snapshot()
	if len(calls) == 0 {
		t.Fatal("no KMS calls recorded")
	}
	for _, c := range calls {
		if c.Op == "DescribeKey" {
			continue
		}
		if !maps.Equal(c.Ctx, want) {
			t.Errorf("KMS %s sent encryption context %v, want exactly %v", c.Op, c.Ctx, want)
		}
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func startupErr(t *testing.T, db store.Store) error {
	t.Helper()
	return attachServerExtensions(nil, "127.0.0.1", 0, make([]byte, 32), db, discardLogger(), 0, 0)
}

// Blocker 3: KMS required without the policy mode is refused at startup.
func TestReviewFix_StartupRefusesKMSWithoutPolicyMode(t *testing.T) {
	isolateEnv(t)
	f := newFakeAWSKMS(t)
	kmsMode(t, f.srv.URL, fakeAliasA, envNameProd)
	unsetenv(t, servicepolicy.EnvMode)
	db := newSQLiteTestDB(t).Open(t)

	err := startupErr(t, db)
	if err == nil || !strings.Contains(err.Error(), servicepolicy.EnvMode) {
		t.Errorf("startup with AGENT_VAULT_REQUIRE_KMS=1 and no %s returned %v; want a refusal naming %s",
			servicepolicy.EnvMode, err, servicepolicy.EnvMode)
	}

	t.Setenv(servicepolicy.EnvMode, servicepolicy.ModeReadonlyAllowlist)
	if err := startupErr(t, db); err != nil {
		t.Errorf("control: startup with KMS required and the policy mode active failed: %v", err)
	}
}

// Blocker 3: a configured bootstrap secret without the policy mode is
// refused at startup, before any AWS call.
func TestReviewFix_StartupRefusesBootstrapWithoutPolicyMode(t *testing.T) {
	isolateEnv(t)
	unsetenv(t, servicepolicy.EnvMode)
	t.Setenv("AGENT_VAULT_BOOTSTRAP_SECRET_ID", "example/bootstrap-document")
	t.Setenv("AGENT_VAULT_BOOTSTRAP_TOKEN_SECRET_ID", "example/executor-token")
	t.Setenv("AGENT_VAULT_BOOTSTRAP_EXECUTOR", "example-executor")
	t.Setenv("AWS_ENDPOINT_URL_SECRETS_MANAGER", closedEndpoint(t))
	t.Setenv("AWS_ENDPOINT_URL_SSM", closedEndpoint(t))

	err := startupErr(t, newSQLiteTestDB(t).Open(t))
	if err == nil || !strings.Contains(err.Error(), servicepolicy.EnvMode) {
		t.Errorf("startup with a bootstrap secret and no %s returned %v; want a refusal naming %s",
			servicepolicy.EnvMode, err, servicepolicy.EnvMode)
	}
}

// Non-blocking: any vault still on an external credential store refuses
// startup (the switching endpoint is gone, so such a row is a leftover).
func TestReviewFix_StartupRefusesExternalCredentialStoreRows(t *testing.T) {
	isolateEnv(t)
	t.Setenv(servicepolicy.EnvMode, servicepolicy.ModeReadonlyAllowlist)
	tdb := newSQLiteTestDB(t)
	db := tdb.Open(t)
	v, err := db.CreateVault(context.Background(), "external-vault")
	if err != nil {
		t.Fatal(err)
	}
	if err := startupErr(t, db); err != nil {
		t.Fatalf("control: startup without external stores failed: %v", err)
	}
	tdb.Exec(t, `INSERT INTO vault_credential_stores (vault_id, kind, config_json, poll_interval_seconds) VALUES (?, 'infisical', '{}', 60)`, v.ID)
	if err := startupErr(t, db); err == nil {
		t.Error("startup succeeded although a vault row still uses an external credential store")
	}
}
