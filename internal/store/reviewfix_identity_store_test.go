// Review-fix tests for blocker 1 at the store level.
package store

import (
	"context"
	"testing"
)

func reviewVault(t *testing.T, s *SQLStore) string {
	t.Helper()
	v, err := s.CreateVault(context.Background(), "review-vault")
	if err != nil {
		t.Fatal(err)
	}
	return v.ID
}

// Blocker 1 (and the non-blocking "identity cleared after a proposal
// delete"): ApplyProposal must delete the credential_identity:<key> record
// with the credential row, so a value recreated at version 1 cannot inherit
// the old digest.
func TestReviewFix_ApplyProposalDeleteClearsIdentity(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	vid := reviewVault(t, s)
	if _, err := s.SetCredentialVersion(ctx, vid, "EXAMPLE_TOKEN", []byte("ct"), []byte("nonce-123456"), 1); err != nil {
		t.Fatal(err)
	}
	if err := s.SetVaultSetting(ctx, vid, CredentialIdentitySettingKey("EXAMPLE_TOKEN"), "1:digest-of-old-value"); err != nil {
		t.Fatal(err)
	}
	sess, err := s.CreateScopedSession(ctx, CreateScopedSessionParams{VaultID: vid, VaultRole: "proxy"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.CreateProposal(ctx, vid, sess.ID, `[]`, `[{"action":"delete","key":"EXAMPLE_TOKEN"}]`, "delete", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyProposal(ctx, vid, p.ID, `[]`, nil, []string{"EXAMPLE_TOKEN"}, nil); err != nil {
		t.Fatalf("ApplyProposal: %v", err)
	}
	if c, _ := s.GetCredential(ctx, vid, "EXAMPLE_TOKEN"); c != nil {
		t.Fatal("precondition: credential not deleted by the proposal")
	}
	if rec, _ := s.GetVaultSetting(ctx, vid, CredentialIdentitySettingKey("EXAMPLE_TOKEN")); rec != "" {
		t.Fatalf("identity record %q survived a proposal delete; a value recreated at version 1 would inherit it", rec)
	}
}
