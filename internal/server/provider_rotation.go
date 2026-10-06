package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/identity"
	"github.com/Infisical/agent-vault/internal/store"
)

// Provider-key rotation (fork change 17, provider-key half).
//
// Pasting a value that replaces an existing value of a key with an identity
// probe journals the superseded value (credential_rotations, in the same
// compare-and-set transaction that stores the new version). When the key
// has a pinned identity (vault setting credential_identity_pin:<KEY>), the
// pasted value is probed first and refused with IDENTITY_MISMATCH unless its
// identity is the pin. A paste is refused while the key has an open
// rotation, so at most two values of a key are ever live.
//
// CredentialRotationTick probes each open rotation's superseded value; only
// a 401 proves it dead, and then the stored copy is destroyed and the row
// closed (once, whatever the number of instances). It also records the
// identity of a current value that has none. RunCredentialRotations runs a
// pass at startup and on every tick; Start runs it. While a rotation stays
// open longer than brokercore.CredentialRotationGrace the key is not
// injected (CREDENTIAL_ROTATION_UNVERIFIED).
//
// AGENT_VAULT_IDENTITY_PROBE=off disables only the scheduled background
// probe, never the paste-time pin check or the rotation passes. No key value
// is ever logged or returned.

// credentialRotationTickInterval is the period of the rotation loop Start
// runs.
const credentialRotationTickInterval = time.Minute

// credentialRotationPassTimeout bounds one rotation pass.
const credentialRotationPassTimeout = 2 * time.Minute

// rotationStore is the store surface for provider-key rotation
// (store.SQLStore implements it).
type rotationStore interface {
	ReplaceCredentialJournaled(ctx context.Context, vaultID, key string, ciphertext, nonce []byte, version uint64) (*store.Credential, error)
	HasOpenCredentialRotation(ctx context.Context, vaultID, key string) (bool, error)
	ListOpenCredentialRotations(ctx context.Context) ([]store.CredentialRotation, error)
	CloseCredentialRotation(ctx context.Context, id int64) (bool, error)
}

// CredentialRotationSuspended exposes the store's suspension check to the
// broker; a store without the journal suspends nothing.
func (a credentialStoreAdapter) CredentialRotationSuspended(ctx context.Context, vaultID, key string, openedBefore time.Time) (bool, error) {
	if rs, ok := a.Store.(brokercore.CredentialRotationState); ok {
		return rs.CredentialRotationSuspended(ctx, vaultID, key, openedBefore)
	}
	return false, nil
}

// pasteRefusal is an HTTP refusal of a paste; msg never carries a value.
type pasteRefusal struct {
	status int
	msg    string
}

// pastePlan is what checkPaste decided for one key.
type pastePlan struct {
	journaled bool                    // replaces a probeable value: journal it
	probed    *identity.NotionAccount // the pasted value's identity, when a pin required probing it
}

// checkPaste runs every check for one pasted key before anything is stored.
func (s *Server) checkPaste(ctx context.Context, vaultID, key string, value []byte) (pastePlan, *pasteRefusal) {
	var plan pastePlan
	svc, probeable, err := s.identityProbeService(ctx, vaultID, key)
	if err != nil {
		return plan, &pasteRefusal{http.StatusInternalServerError, "Failed to load services"}
	}
	pin, err := s.store.GetVaultSetting(ctx, vaultID, store.CredentialIdentityPinSettingKey(key))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return plan, &pasteRefusal{http.StatusInternalServerError, "Failed to read the identity pin"}
	}
	if probeable {
		if cur, err := s.store.GetCredential(ctx, vaultID, key); err == nil && cur != nil {
			rs, ok := s.store.(rotationStore)
			if !ok {
				return plan, &pasteRefusal{http.StatusInternalServerError, "This store cannot journal a key replacement"}
			}
			open, err := rs.HasOpenCredentialRotation(ctx, vaultID, key)
			if err != nil {
				return plan, &pasteRefusal{http.StatusInternalServerError, "Failed to check open rotations"}
			}
			if open {
				return plan, &pasteRefusal{http.StatusConflict, fmt.Sprintf("CREDENTIAL_ROTATION_IN_PROGRESS: %s was replaced and the provider still accepts the previous key; revoke it at the provider, then paste again", key)}
			}
			plan.journaled = true
		}
	}
	if pin == "" {
		return plan, nil
	}
	if !probeable {
		return plan, &pasteRefusal{http.StatusConflict, fmt.Sprintf("IDENTITY_MISMATCH: %s has a pinned identity but no identity probe to verify a pasted value", key)}
	}
	headers, err := svc.Auth.Resolve(func(k string) (string, error) {
		if k != key {
			return "", fmt.Errorf("unexpected credential reference")
		}
		return string(value), nil
	})
	if err != nil {
		return plan, &pasteRefusal{http.StatusInternalServerError, "Failed to build the identity probe"}
	}
	acct, _, err := probeNotion(ctx, headers)
	if err != nil {
		return plan, &pasteRefusal{http.StatusBadGateway, fmt.Sprintf("IDENTITY_UNVERIFIED: the pasted value for %s could not be verified against its pinned identity (%s)", key, err.Error())}
	}
	if acct.Digest != pin {
		return plan, &pasteRefusal{http.StatusConflict, fmt.Sprintf("IDENTITY_MISMATCH: the pasted value for %s acts as a different account than the one pinned", key)}
	}
	plan.probed = &acct
	return plan, nil
}

// storePaste stores one checked paste and, when its identity was probed,
// records it for the new row and version.
func (s *Server) storePaste(ctx context.Context, vaultID, key string, value []byte, plan pastePlan) *pasteRefusal {
	if plan.journaled {
		if refusal := s.putCredentialJournaled(ctx, vaultID, key, value); refusal != nil {
			return refusal
		}
	} else if err := s.putCredentialValue(ctx, vaultID, key, value); err != nil {
		return &pasteRefusal{http.StatusInternalServerError, fmt.Sprintf("Failed to set credential %q", key)}
	}
	if plan.probed == nil {
		s.scheduleIdentityProbe(vaultID, key)
		return nil
	}
	cred, err := s.store.GetCredential(ctx, vaultID, key)
	w, ok := s.store.(credentialIdentityWriter)
	if err != nil || cred == nil || !ok {
		return nil // no record: injection refuses until a rotation pass records it
	}
	rec, err := brokercore.IdentityRecord{
		Binding:         brokercore.VersionBinding(cred.ID, cred.Version),
		Digest:          plan.probed.Digest,
		WorkspaceName:   plan.probed.WorkspaceName,
		WorkspaceID:     plan.probed.WorkspaceID,
		IntegrationName: plan.probed.IntegrationName,
	}.Encode()
	if err == nil {
		_, _ = w.SetCredentialIdentity(ctx, vaultID, key, cred.ID, cred.Version, rec)
	}
	return nil
}

// putCredentialJournaled replaces a value and journals the superseded one in
// one transaction, retrying a lost compare-and-set a bounded number of times.
func (s *Server) putCredentialJournaled(ctx context.Context, vaultID, key string, value []byte) *pasteRefusal {
	rs, ok := s.store.(rotationStore)
	if !ok {
		return &pasteRefusal{http.StatusInternalServerError, "This store cannot journal a key replacement"}
	}
	for attempt := 0; attempt < 5; attempt++ {
		next := s.credentialVersion(ctx, vaultID, key) + 1
		ct, nonce, err := store.CredentialValueAAD(vaultID, key, next).Seal(value, s.encKey)
		if err != nil {
			return &pasteRefusal{http.StatusInternalServerError, "Encryption failed"}
		}
		_, err = rs.ReplaceCredentialJournaled(ctx, vaultID, key, ct, nonce, next)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, store.ErrCredentialRotationOpen):
			return &pasteRefusal{http.StatusConflict, fmt.Sprintf("CREDENTIAL_ROTATION_IN_PROGRESS: %s was replaced and the provider still accepts the previous key; revoke it at the provider, then paste again", key)}
		case errors.Is(err, store.ErrVersionConflict):
			continue
		default:
			if s.logger != nil {
				s.logger.Error("credential replacement not journaled; nothing replaced",
					slog.String("vault_id", vaultID), slog.String("key", key), slog.String("error", err.Error()))
			}
			return &pasteRefusal{http.StatusInternalServerError, fmt.Sprintf("Failed to set credential %q", key)}
		}
	}
	return &pasteRefusal{http.StatusConflict, fmt.Sprintf("Credential %q changed concurrently; try again", key)}
}

// CredentialRotationTick makes one pass over the open provider-key
// rotations. Safe to run any number of times, on any number of instances.
func (s *Server) CredentialRotationTick(ctx context.Context) error {
	rs, ok := s.store.(rotationStore)
	if !ok {
		return errors.New("store has no credential rotation journal")
	}
	rows, err := rs.ListOpenCredentialRotations(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		s.passCredentialRotation(ctx, rs, row)
	}
	return nil
}

func (s *Server) passCredentialRotation(ctx context.Context, rs rotationStore, row store.CredentialRotation) {
	log := func(msg string, extra ...any) {
		if s.logger != nil {
			args := append([]any{slog.String("vault_id", row.VaultID), slog.String("key", row.CredentialKey), slog.Int64("rotation", row.ID)}, extra...)
			s.logger.Warn(msg, args...)
		}
	}
	svc, ok, err := s.identityProbeService(ctx, row.VaultID, row.CredentialKey)
	if err != nil || !ok {
		log("credential rotation: no identity probe for the key; superseded value not checked")
		return
	}
	old, err := store.CredentialValueAAD(row.VaultID, row.CredentialKey, row.OldVersion).Open(row.OldCiphertext, row.OldNonce, s.encKey)
	if err != nil {
		log("credential rotation: superseded value does not open")
		return
	}
	headers, err := svc.Auth.Resolve(func(string) (string, error) { return string(old), nil })
	crypto.WipeBytes(old)
	if err != nil {
		log("credential rotation: building the probe failed")
		return
	}
	_, _, perr := probeNotion(ctx, headers)
	if errors.Is(perr, errProbeUnauthorized) {
		closed, err := rs.CloseCredentialRotation(ctx, row.ID)
		switch {
		case err != nil:
			log("credential rotation: closing failed", slog.String("error", err.Error()))
		case closed && s.logger != nil:
			s.logger.Info("credential rotation closed: the provider rejects the superseded key, its copy is destroyed",
				slog.String("vault_id", row.VaultID), slog.String("key", row.CredentialKey), slog.Int64("rotation", row.ID))
		}
	}

	// Record the current value's identity if it has none (a crash between
	// the replacement and its first probe), so the pin check can pass.
	if cred, err := s.store.GetCredential(ctx, row.VaultID, row.CredentialKey); err == nil && cred != nil &&
		s.credentialIdentityFor(ctx, row.VaultID, cred) == nil {
		if err := s.runIdentityProbeFor(ctx, row.VaultID, row.CredentialKey, svc); err != nil {
			log("credential rotation: current value's identity not recorded", slog.String("reason", err.Error()))
		}
	}
}

// RunCredentialRotations makes a rotation pass at once (startup), then one
// per tick, until ctx ends or tick closes.
func (s *Server) RunCredentialRotations(ctx context.Context, tick <-chan time.Time) {
	pass := func() {
		pctx, cancel := context.WithTimeout(ctx, credentialRotationPassTimeout)
		defer cancel()
		if err := s.CredentialRotationTick(pctx); err != nil && s.logger != nil && ctx.Err() == nil {
			s.logger.Warn("credential rotation pass failed", slog.String("error", err.Error()))
		}
	}
	pass()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-tick:
			if !ok {
				return
			}
			pass()
		}
	}
}
