package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/identity"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/servicepolicy"
)

// writeServicePolicyError enforces the compiled-in service policy on a
// service write. It writes a 403 and returns false when svcs breaks it.
func writeServicePolicyError(w http.ResponseWriter, svcs []broker.Service) bool {
	if err := servicepolicy.CheckServices(svcs); err != nil {
		jsonError(w, http.StatusForbidden, fmt.Sprintf("Refused by %s: %v", servicepolicy.EnvMode, err))
		return false
	}
	return true
}

// identityProbeTimeout bounds one probe end to end.
const identityProbeTimeout = 15 * time.Second

// identityProbeMaxBody caps the users/me body read.
const identityProbeMaxBody = 1 << 20

// identityProbeBaseURL is the Notion API origin. A var so tests can point
// it at a local server.
var identityProbeBaseURL = "https://" + identity.NotionHost

// identityProbes de-duplicates concurrent probes per vault/key.
var identityProbes sync.Map

// scheduleIdentityProbe runs the identity probe for vaultID/key in the
// background after a credential is set or refreshed. Setting
// AGENT_VAULT_IDENTITY_PROBE=off disables it.
func (s *Server) scheduleIdentityProbe(vaultID, key string) {
	if strings.EqualFold(os.Getenv("AGENT_VAULT_IDENTITY_PROBE"), "off") {
		return
	}
	// Decide synchronously whether this key has a probe at all, so the
	// common case (not a Notion credential) starts no goroutine.
	svc, ok, err := s.identityProbeService(context.Background(), vaultID, key)
	if err != nil || !ok {
		return
	}
	id := vaultID + "\x00" + key
	if _, busy := identityProbes.LoadOrStore(id, true); busy {
		return
	}
	go func() {
		defer identityProbes.Delete(id)
		ctx, cancel := context.WithTimeout(context.Background(), identityProbeTimeout)
		defer cancel()
		if err := s.runIdentityProbeFor(ctx, vaultID, key, svc); err != nil && s.logger != nil {
			s.logger.Warn("credential identity not recorded",
				slog.String("vault_id", vaultID), slog.String("key", key), slog.String("reason", err.Error()))
		}
	}()
}

// runIdentityProbe calls the provider identity endpoint with the
// credential exactly as the proxy would inject it and records the
// identity digest beside the stored value it ran with. Any failure,
// including a response that lacks a required field, deletes the record
// instead of keeping a stale one.
func (s *Server) runIdentityProbe(ctx context.Context, vaultID, key string) error {
	svc, ok, err := s.identityProbeService(ctx, vaultID, key)
	if err != nil {
		return err
	}
	if !ok {
		_ = s.store.DeleteVaultSetting(ctx, vaultID, brokercore.IdentitySettingKey(key))
		return nil // not a credential with an identity probe
	}
	return s.runIdentityProbeFor(ctx, vaultID, key, svc)
}

func (s *Server) runIdentityProbeFor(ctx context.Context, vaultID, key string, svc broker.Service) error {
	settingKey := brokercore.IdentitySettingKey(key)
	clear := func(reason error) error {
		_ = s.store.DeleteVaultSetting(ctx, vaultID, settingKey)
		return reason
	}

	cp, ok := s.CredentialProvider().(*brokercore.StoreCredentialProvider)
	if !ok {
		return clear(errors.New("credential provider does not support identity probes"))
	}
	inj, err := cp.Inject(brokercore.WithProbeService(ctx, svc), vaultID, identity.NotionHost, 443, identity.NotionProbePath)
	if err != nil {
		return clear(fmt.Errorf("resolving credential: %w", err))
	}
	if inj == nil || inj.ProbeBinding == "" || len(inj.Headers) == 0 {
		return clear(errors.New("credential is not a single stored value"))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, identityProbeBaseURL+identity.NotionProbePath, nil)
	if err != nil {
		return clear(err)
	}
	for k, v := range inj.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Notion-Version", identity.NotionVersion)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{
		Timeout: identityProbeTimeout,
		Transport: &http.Transport{
			DialContext:         netguard.SafeDialContext(netguard.AllowPrivateFromEnv()),
			TLSHandshakeTimeout: 10 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return clear(errors.New("identity endpoint unreachable"))
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, identityProbeMaxBody))
	if err != nil {
		return clear(errors.New("reading identity response failed"))
	}
	if resp.StatusCode != http.StatusOK {
		return clear(fmt.Errorf("identity endpoint returned %d", resp.StatusCode))
	}
	digest, err := identity.NotionDigest(body)
	if err != nil {
		return clear(err)
	}
	if err := s.store.SetVaultSetting(ctx, vaultID, settingKey, inj.ProbeBinding+":"+digest); err != nil {
		return fmt.Errorf("storing identity: %w", err)
	}
	if s.logger != nil {
		s.logger.Info("credential identity recorded",
			slog.String("vault_id", vaultID), slog.String("key", key), slog.String("identity", digest))
	}
	return nil
}

// identityProbeService returns the vault's Notion service whose auth
// injects exactly key, if any.
func (s *Server) identityProbeService(ctx context.Context, vaultID, key string) (broker.Service, bool, error) {
	svcs, err := s.loadServices(ctx, vaultID)
	if err != nil {
		return broker.Service{}, false, err
	}
	for _, svc := range svcs {
		if !strings.EqualFold(svc.Host, identity.NotionHost) || svc.Auth.Type == "passthrough" {
			continue
		}
		if keys := svc.Auth.CredentialKeys(); len(keys) == 1 && keys[0] == key {
			return svc, true, nil
		}
	}
	return broker.Service{}, false, nil
}
