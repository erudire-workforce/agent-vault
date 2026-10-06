// Review-fix tests for blocker 5 (OAuth compare-and-set), using the
// OAuthTokenUpdate API specified below.
// See internal/crypto/REVIEW_FIX_TESTS.md.
package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// oauthRow creates an OAuth credential with refresh token and client secret
// sealed for their first versions and returns the row.
func oauthRow(t *testing.T, s *SQLStore, vid string, dek []byte) *CredentialOAuth {
	t.Helper()
	ctx := context.Background()
	csCT, csN, err := OAuthClientSecretAAD(vid, "EXAMPLE_OAUTH", 1).Seal([]byte("client-secret-v1"), dek)
	if err != nil {
		t.Fatal(err)
	}
	rCT, rN, err := OAuthRefreshTokenAAD(vid, "EXAMPLE_OAUTH", 1).Seal([]byte("refresh-v1"), dek)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetCredentialOAuth(ctx, &CredentialOAuth{
		VaultID: vid, CredentialKey: "EXAMPLE_OAUTH", TokenURL: "https://token.example.test/token", ClientID: "cid",
		ClientSecretCT: csCT, ClientSecretNonce: csN, ClientSecretVersion: 1,
		RefreshTokenCT: rCT, RefreshTokenNonce: rN, Version: 1,
	}); err != nil {
		t.Fatal(err)
	}
	co, err := s.GetCredentialOAuth(ctx, vid, "EXAMPLE_OAUTH")
	if err != nil {
		t.Fatal(err)
	}
	return co
}

// Blocker 5 API (specified here, same pattern as SetCredentialVersion):
//
//	// OAuthTokenUpdate is one token write. Each ciphertext is sealed for the
//	// version given beside it, which is the row's next version; the write
//	// lands only if the row is still at that version minus one, otherwise
//	// it returns ErrVersionConflict and changes nothing.
//	type OAuthTokenUpdate struct {
//	    AccessCT, AccessNonce   []byte
//	    AccessVersion           uint64     // credentials.version AccessCT was sealed for
//	    RefreshCT, RefreshNonce []byte     // nil keeps the stored refresh token
//	    RefreshVersion          uint64     // credential_oauth.version RefreshCT was sealed for; ignored when RefreshCT is nil
//	    ExpiresAt               *time.Time
//	}
//	UpdateCredentialOAuthTokens(ctx, vaultID, key string, u OAuthTokenUpdate) error
//
// SetCredentialOAuth: when ClientSecretCT is set, co.ClientSecretVersion is
// the version it was sealed for (compare-and-set against version-1); when
// RefreshTokenCT is set, co.Version is likewise the version it was sealed for.
//
// Blocker 5: two concurrent refreshes read the same row versions and both
// seal for v+1. The second write must fail its compare-and-set (so the
// caller retries); it must not move the row to v+2 with ciphertexts that
// were sealed for v+1 and therefore no longer decrypt.
func TestReviewFix_OAuthTokenRefreshCompareAndSet(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	vid := reviewVault(t, s)
	dek := make([]byte, 32)
	co := oauthRow(t, s, vid, dek)
	cred, err := s.GetCredential(ctx, vid, "EXAMPLE_OAUTH")
	if err != nil {
		t.Fatal(err)
	}
	accessNext, refreshNext := cred.Version+1, co.Version+1

	seal := func(tag string) (aCT, aN, rCT, rN []byte) {
		aCT, aN, err := CredentialValueAAD(vid, "EXAMPLE_OAUTH", accessNext).Seal([]byte("access-"+tag), dek)
		if err != nil {
			t.Fatal(err)
		}
		rCT, rN, err = OAuthRefreshTokenAAD(vid, "EXAMPLE_OAUTH", refreshNext).Seal([]byte("refresh-"+tag), dek)
		if err != nil {
			t.Fatal(err)
		}
		return aCT, aN, rCT, rN
	}
	exp := time.Now().Add(time.Hour)
	update := func(tag string) OAuthTokenUpdate {
		aCT, aN, rCT, rN := seal(tag)
		return OAuthTokenUpdate{
			AccessCT: aCT, AccessNonce: aN, AccessVersion: accessNext,
			RefreshCT: rCT, RefreshNonce: rN, RefreshVersion: refreshNext,
			ExpiresAt: &exp,
		}
	}
	first, second := update("first"), update("second")
	if err := s.UpdateCredentialOAuthTokens(ctx, vid, "EXAMPLE_OAUTH", first); err != nil {
		t.Fatalf("first refresh write: %v", err)
	}
	err2 := s.UpdateCredentialOAuthTokens(ctx, vid, "EXAMPLE_OAUTH", second)
	if err2 == nil {
		t.Error("second refresh sealed for the same versions succeeded; it must fail its compare-and-set")
	} else if !errors.Is(err2, ErrVersionConflict) {
		t.Errorf("second refresh failed with %v, want ErrVersionConflict so the caller retries", err2)
	}

	cred, _ = s.GetCredential(ctx, vid, "EXAMPLE_OAUTH")
	co, _ = s.GetCredentialOAuth(ctx, vid, "EXAMPLE_OAUTH")
	if cred.Version != accessNext {
		t.Errorf("credentials.version = %d, want %d (one successful write)", cred.Version, accessNext)
	}
	if co.Version != refreshNext {
		t.Errorf("credential_oauth.version = %d, want %d (one successful write)", co.Version, refreshNext)
	}
	if _, err := CredentialValueAAD(vid, "EXAMPLE_OAUTH", cred.Version).Open(cred.Ciphertext, cred.Nonce, dek); err != nil {
		t.Errorf("stored access token does not decrypt at the row's version %d: %v", cred.Version, err)
	}
	if _, err := OAuthRefreshTokenAAD(vid, "EXAMPLE_OAUTH", co.Version).Open(co.RefreshTokenCT, co.RefreshTokenNonce, dek); err != nil {
		t.Errorf("stored refresh token does not decrypt at the row's version %d: %v", co.Version, err)
	}
}

// Blocker 5, client_secret_version: two config writers both seal the client
// secret for client_secret_version+1.
func TestReviewFix_OAuthClientSecretCompareAndSet(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	vid := reviewVault(t, s)
	dek := make([]byte, 32)
	co := oauthRow(t, s, vid, dek)
	next := co.ClientSecretVersion + 1

	write := func(tag string) error {
		ct, n, err := OAuthClientSecretAAD(vid, "EXAMPLE_OAUTH", next).Seal([]byte("client-secret-"+tag), dek)
		if err != nil {
			t.Fatal(err)
		}
		return s.SetCredentialOAuth(ctx, &CredentialOAuth{
			VaultID: vid, CredentialKey: "EXAMPLE_OAUTH", TokenURL: "https://token.example.test/token", ClientID: "cid",
			ClientSecretCT: ct, ClientSecretNonce: n, ClientSecretVersion: next,
		})
	}
	if err := write("first"); err != nil {
		t.Fatalf("first client-secret write: %v", err)
	}
	err2 := write("second")
	if err2 == nil {
		t.Error("second client-secret write sealed for the same version succeeded; it must fail its compare-and-set")
	} else if !errors.Is(err2, ErrVersionConflict) {
		t.Errorf("second client-secret write failed with %v, want ErrVersionConflict", err2)
	}
	co, _ = s.GetCredentialOAuth(ctx, vid, "EXAMPLE_OAUTH")
	if co.ClientSecretVersion != next {
		t.Errorf("client_secret_version = %d, want %d", co.ClientSecretVersion, next)
	}
	if _, err := OAuthClientSecretAAD(vid, "EXAMPLE_OAUTH", co.ClientSecretVersion).Open(co.ClientSecretCT, co.ClientSecretNonce, dek); err != nil {
		t.Errorf("stored client secret does not decrypt at client_secret_version %d: %v", co.ClientSecretVersion, err)
	}
}
