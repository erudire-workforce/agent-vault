// Package aadmigrate performs the one-time conversion of v0.40.0
// ciphertexts (AES-GCM with nil additional data) to row-bound AAD
// (crypto.AAD). It covers credentials.ciphertext (static values and OAuth
// access tokens), credential_oauth.refresh_token_ct and client_secret_ct,
// proposal_credentials.ciphertext and the database-backed CA root key
// (ca_state). The file-backed CA root key is converted by RunCAKeyFile.
//
// The production read path only accepts AAD-bound values, so startup runs
// this migration before serving. Once it has completed, Run is a no-op and
// the server never converts a nil-AAD value again: a legacy value planted
// afterwards (restored backup, direct DB write) is refused on read.
package aadmigrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

// CompleteSetting is the instance_settings key recording completion.
const CompleteSetting = "aad_migration_complete"

// Result counts ciphertext fields converted and fields found already bound.
type Result struct {
	Rewrapped    int
	AlreadyBound int
}

// IsComplete reports whether the migration has completed on this store.
func IsComplete(ctx context.Context, db store.Store) (bool, error) {
	v, err := db.GetSetting(ctx, CompleteSetting)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", CompleteSetting, err)
	}
	return v == "1", nil
}

// Run converts every legacy ciphertext and marks the migration complete. It
// is idempotent and resumable: rows already bound are counted and left
// alone, so a run that died midway is finished by the next one. A value that
// opens neither as bound nor as legacy stops the migration (the remaining
// rows are still converted) and leaves it incomplete; nothing is skipped or
// deleted.
func Run(ctx context.Context, db store.Store, dek []byte) (Result, error) {
	var res Result
	done, err := IsComplete(ctx, db)
	if err != nil {
		return res, err
	}
	if done {
		return res, nil
	}

	var failures []error
	fail := func(err error) { failures = append(failures, err) }

	vaults, err := db.ListVaults(ctx)
	if err != nil {
		return res, fmt.Errorf("listing vaults: %w", err)
	}
	for _, v := range vaults {
		creds, err := db.ListCredentials(ctx, v.ID)
		if err != nil {
			return res, fmt.Errorf("listing credentials: %w", err)
		}
		for _, c := range creds {
			if len(c.Ciphertext) == 0 {
				continue // OAuth row with no access token yet
			}
			aad := store.CredentialValueAAD(c.VaultID, c.Key, c.Version)
			if _, err := aad.Open(c.Ciphertext, c.Nonce, dek); err == nil {
				res.AlreadyBound++
				continue
			}
			pt, err := crypto.Decrypt(c.Ciphertext, c.Nonce, dek)
			if err != nil {
				fail(fmt.Errorf("credential %s/%s: undecryptable", c.VaultID, c.Key))
				continue
			}
			ct, n, err := store.CredentialValueAAD(c.VaultID, c.Key, c.Version+1).Seal(pt, dek)
			crypto.WipeBytes(pt)
			if err != nil {
				return res, err
			}
			if err := db.RewrapCredential(ctx, c.VaultID, c.Key, c.Version, ct, n); err != nil {
				fail(fmt.Errorf("credential %s/%s: %w", c.VaultID, c.Key, err))
				continue
			}
			res.Rewrapped++
		}
	}

	oauthKeys, err := db.ListCredentialOAuthKeys(ctx)
	if err != nil {
		return res, err
	}
	for _, vk := range oauthKeys {
		if err := migrateOAuth(ctx, db, dek, vk[0], vk[1], &res); err != nil {
			fail(err)
		}
	}

	refs, err := db.ListProposalCredentialRefs(ctx)
	if err != nil {
		return res, err
	}
	byProposal := map[[2]any]map[string]store.EncryptedCredential{}
	for _, r := range refs {
		k := [2]any{r.VaultID, r.ProposalID}
		creds, ok := byProposal[k]
		if !ok {
			creds, err = db.GetProposalCredentials(ctx, r.VaultID, r.ProposalID)
			if err != nil {
				return res, err
			}
			byProposal[k] = creds
		}
		enc, ok := creds[r.Key]
		if !ok || len(enc.Ciphertext) == 0 {
			continue
		}
		aad := store.ProposalCredentialAAD(r.VaultID, r.ProposalID, r.Key, enc.Version)
		if _, err := aad.Open(enc.Ciphertext, enc.Nonce, dek); err == nil {
			res.AlreadyBound++
			continue
		}
		pt, err := crypto.Decrypt(enc.Ciphertext, enc.Nonce, dek)
		if err != nil {
			fail(fmt.Errorf("proposal credential %s/%d/%s: undecryptable", r.VaultID, r.ProposalID, r.Key))
			continue
		}
		ct, n, err := store.ProposalCredentialAAD(r.VaultID, r.ProposalID, r.Key, enc.Version+1).Seal(pt, dek)
		crypto.WipeBytes(pt)
		if err != nil {
			return res, err
		}
		if err := db.RewrapProposalCredential(ctx, r.VaultID, r.ProposalID, r.Key, enc.Version, ct, n); err != nil {
			fail(fmt.Errorf("proposal credential %s/%d/%s: %w", r.VaultID, r.ProposalID, r.Key, err))
			continue
		}
		res.Rewrapped++
	}

	if st, err := db.GetCAState(ctx); err != nil {
		return res, fmt.Errorf("reading ca_state: %w", err)
	} else if st != nil {
		newCT, newNonce, bound, err := ca.RewrapLegacyRootKey(st.RootKeyCT, st.RootKeyNonce, dek)
		switch {
		case err != nil:
			fail(fmt.Errorf("ca_state: %w", err))
		case bound:
			res.AlreadyBound++
		default:
			if err := db.ReplaceCAStateKey(ctx, st.RootKeyCT, newCT, newNonce); err != nil {
				fail(fmt.Errorf("ca_state: %w", err))
			} else {
				res.Rewrapped++
			}
		}
	}

	if len(failures) > 0 {
		return res, fmt.Errorf("aad migration incomplete (%d value(s) could not be converted): %w", len(failures), errors.Join(failures...))
	}
	if err := db.SetSetting(ctx, CompleteSetting, "1"); err != nil {
		return res, fmt.Errorf("recording completion: %w", err)
	}
	return res, nil
}

func migrateOAuth(ctx context.Context, db store.Store, dek []byte, vaultID, key string, res *Result) error {
	o, err := db.GetCredentialOAuth(ctx, vaultID, key)
	if err != nil {
		return fmt.Errorf("oauth %s/%s: %w", vaultID, key, err)
	}
	type field struct {
		ct, nonce *[]byte
		version   *uint64
		aad       func(v uint64) crypto.AAD
	}
	fields := []field{
		{&o.RefreshTokenCT, &o.RefreshTokenNonce, &o.Version, func(v uint64) crypto.AAD { return store.OAuthRefreshTokenAAD(vaultID, key, v) }},
		{&o.ClientSecretCT, &o.ClientSecretNonce, &o.ClientSecretVersion, func(v uint64) crypto.AAD { return store.OAuthClientSecretAAD(vaultID, key, v) }},
	}
	fromV, fromCSV := o.Version, o.ClientSecretVersion
	changed := 0
	for _, f := range fields {
		if len(*f.ct) == 0 {
			continue
		}
		if _, err := f.aad(*f.version).Open(*f.ct, *f.nonce, dek); err == nil {
			res.AlreadyBound++
			continue
		}
		pt, err := crypto.Decrypt(*f.ct, *f.nonce, dek)
		if err != nil {
			return fmt.Errorf("oauth %s/%s: undecryptable", vaultID, key)
		}
		ct, n, err := f.aad(*f.version+1).Seal(pt, dek)
		crypto.WipeBytes(pt)
		if err != nil {
			return err
		}
		*f.ct, *f.nonce = ct, n
		*f.version++
		changed++
	}
	if changed == 0 {
		return nil
	}
	if err := db.RewrapCredentialOAuth(ctx, o, fromV, fromCSV); err != nil {
		return fmt.Errorf("oauth %s/%s: %w", vaultID, key, err)
	}
	res.Rewrapped += changed
	return nil
}

// RunCAKeyFile converts the file-backed CA root key in dir (SQLite
// deployments keep it in ca.key.enc) to the AAD-bound form. Idempotent; a
// missing file is a no-op. Callers run it only while the store migration is
// incomplete, for the same reason Run stops converting once complete.
func RunCAKeyFile(dir string, dek []byte) error {
	return ca.MigrateKeyFile(dir, dek)
}
