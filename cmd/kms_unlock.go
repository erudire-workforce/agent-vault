package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Infisical/agent-vault/internal/aadmigrate"
	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/kmswrap"
	"github.com/Infisical/agent-vault/internal/store"
)

// unlockOrSetupKMS handles startup when KMS is configured
// (AGENT_VAULT_KMS_KEY_ID) or required (AGENT_VAULT_REQUIRE_KMS=1).
// handled=false means KMS is not configured and the caller continues with
// the password / passwordless paths.
//
// When KMS is configured there is no fallback: a fresh store gets a
// KMS-wrapped DEK or nothing, an existing KMS record unlocks only through
// KMS, and a passwordless or password-wrapped record is refused.
func unlockOrSetupKMS(db store.Store) (mk *auth.MasterKey, handled bool, err error) {
	settings, err := kmswrap.SettingsFromEnv()
	if err != nil {
		return nil, true, err
	}
	ctx := context.Background()
	record, err := db.GetMasterKeyRecord(ctx)
	if err != nil {
		return nil, true, fmt.Errorf("checking master key: %w", err)
	}
	if !settings.Enabled() {
		if record != nil && len(record.KMSWrappedDEK) > 0 {
			return nil, true, fmt.Errorf("the master key is KMS-wrapped but %s is not set", kmswrap.EnvKeyID)
		}
		return nil, false, nil
	}

	// KMS mode: a master password in the environment is never used.
	_ = os.Unsetenv("AGENT_VAULT_MASTER_PASSWORD")

	if record != nil && len(record.KMSWrappedDEK) == 0 {
		kind := "password-wrapped"
		if record.DEKPlaintext != nil {
			kind = "unwrapped (passwordless)"
		}
		return nil, true, fmt.Errorf("KMS is configured (%s) but the stored master key is %s; refusing to start", kmswrap.EnvKeyID, kind)
	}

	w, err := kmswrap.NewAWS(ctx, settings.KeyID)
	if err != nil {
		return nil, true, err
	}
	// First setup and restart alike: the key must be Enabled, checked
	// explicitly before it wraps or unwraps anything.
	if err := w.CheckKeyEnabled(ctx); err != nil {
		return nil, true, err
	}

	if record == nil {
		mk, rec, err := auth.SetupWithKMS(ctx, w, settings.Ctx)
		if err != nil {
			return nil, true, fmt.Errorf("setting up KMS-wrapped master key: %w", err)
		}
		if err := db.SetMasterKeyRecord(ctx, verificationToStoreRecord(rec)); err != nil {
			mk.Wipe()
			return nil, true, fmt.Errorf("persisting master key record: %w", err)
		}
		// Another instance may have won the insert race (ON CONFLICT DO
		// NOTHING): unlock whatever is stored.
		mk.Wipe()
		if record, err = db.GetMasterKeyRecord(ctx); err != nil || record == nil {
			return nil, true, fmt.Errorf("re-reading master key after setup: %v", err)
		}
		if len(record.KMSWrappedDEK) == 0 {
			return nil, true, errors.New("stored master key is not KMS-wrapped; refusing to start")
		}
	}

	mk, err = auth.UnlockWithKMS(ctx, w, buildVerificationRecord(record), settings.Ctx)
	if err != nil {
		return nil, true, fmt.Errorf("unlocking master key with KMS: %w", err)
	}
	return mk, true, nil
}

// refuseIfKMSRequired is the guard for the non-KMS unlock entry points.
func refuseIfKMSRequired() error {
	settings, err := kmswrap.SettingsFromEnv()
	if err != nil {
		return err
	}
	if settings.Required || settings.Enabled() {
		return fmt.Errorf("KMS is configured; refusing the password / passwordless master key path")
	}
	return nil
}

// legacyUpgradeAllowed reports whether a v0.40.0 (nil-AAD) master key record
// may still be unlocked: only until the row-bound AAD migration completes.
func legacyUpgradeAllowed(db store.Store) bool {
	done, err := aadmigrate.IsComplete(context.Background(), db)
	return err == nil && !done
}

// unlockPasswordWithUpgrade unlocks a password-wrapped record. A v0.40.0
// record is accepted only while the AAD migration is incomplete, and is
// rewritten in the AAD-bound form on success.
func unlockPasswordWithUpgrade(db store.Store, password []byte, record *store.MasterKeyRecord) (*auth.MasterKey, error) {
	verRec := buildVerificationRecord(record)
	mk, err := auth.Unlock(password, verRec)
	if err == nil || !errors.Is(err, auth.ErrWrongPassword) || !legacyUpgradeAllowed(db) {
		return mk, err
	}
	mk, up, lerr := auth.UnlockLegacy(password, verRec)
	if lerr != nil {
		return nil, err
	}
	if uerr := db.UpdateMasterKeyRecord(context.Background(), verificationToStoreRecord(up)); uerr != nil {
		mk.Wipe()
		return nil, fmt.Errorf("upgrading master key record: %w", uerr)
	}
	return mk, nil
}

// unlockPasswordlessWithUpgrade is unlockPasswordWithUpgrade for a
// passwordless record.
func unlockPasswordlessWithUpgrade(db store.Store, record *store.MasterKeyRecord) (*auth.MasterKey, error) {
	verRec := buildVerificationRecord(record)
	mk, err := auth.UnlockPasswordless(verRec)
	if err == nil || !legacyUpgradeAllowed(db) {
		return mk, err
	}
	mk, up, lerr := auth.UnlockPasswordlessLegacy(verRec)
	if lerr != nil {
		return nil, err
	}
	if uerr := db.UpdateMasterKeyRecord(context.Background(), verificationToStoreRecord(up)); uerr != nil {
		mk.Wipe()
		return nil, fmt.Errorf("upgrading master key record: %w", uerr)
	}
	return mk, nil
}

// runAADMigration converts v0.40.0 (nil-AAD) ciphertexts to row-bound AAD
// before the server reads any of them. It runs only while the migration is
// incomplete; afterwards nil-AAD values are refused, never converted.
func runAADMigration(db store.Store, dek []byte) error {
	ctx := context.Background()
	done, err := aadmigrate.IsComplete(ctx, db)
	if err != nil || done {
		return err
	}
	if db.DialectName() != "postgres" {
		dir, err := ca.DefaultDir()
		if err != nil {
			return err
		}
		if err := aadmigrate.RunCAKeyFile(dir, dek); err != nil {
			return fmt.Errorf("migrating CA key file to row-bound AAD: %w", err)
		}
	}
	res, err := aadmigrate.Run(ctx, db, dek)
	if err != nil {
		return fmt.Errorf("migrating stored secrets to row-bound AAD: %w", err)
	}
	if res.Rewrapped > 0 {
		fmt.Fprintf(os.Stderr, "row-bound AAD migration: %d value(s) rewrapped\n", res.Rewrapped)
	}
	return nil
}
