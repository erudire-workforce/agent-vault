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
	"github.com/Infisical/agent-vault/internal/scrub"
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

// identityProbes serializes probes per vault/key. A key present in the map
// has a probe running; its value records whether another was requested
// meanwhile, in which case the runner probes again once it finishes so the
// newest value gets its own identity.
var (
	identityProbesMu sync.Mutex
	identityProbes   = map[string]bool{}
)

// scheduleIdentityProbe runs the identity probe for vaultID/key in the
// background after a credential is set or refreshed. A request that
// arrives while a probe for the same key is running is queued behind it,
// never dropped. Setting AGENT_VAULT_IDENTITY_PROBE=off disables it.
func (s *Server) scheduleIdentityProbe(vaultID, key string) {
	if strings.EqualFold(os.Getenv("AGENT_VAULT_IDENTITY_PROBE"), "off") {
		return
	}
	// Decide synchronously whether this key has a probe at all, so the
	// common case (not a Notion credential) starts no goroutine.
	if _, ok, err := s.identityProbeService(context.Background(), vaultID, key); err != nil || !ok {
		return
	}
	id := vaultID + "\x00" + key
	identityProbesMu.Lock()
	if _, running := identityProbes[id]; running {
		identityProbes[id] = true // re-queue behind the running probe
		identityProbesMu.Unlock()
		return
	}
	identityProbes[id] = false
	identityProbesMu.Unlock()
	go func() {
		for {
			s.runScheduledIdentityProbe(vaultID, key)
			identityProbesMu.Lock()
			if !identityProbes[id] {
				delete(identityProbes, id)
				identityProbesMu.Unlock()
				return
			}
			identityProbes[id] = false
			identityProbesMu.Unlock()
		}
	}()
}

func (s *Server) runScheduledIdentityProbe(vaultID, key string) {
	ctx, cancel := context.WithTimeout(context.Background(), identityProbeTimeout)
	defer cancel()
	if err := s.runIdentityProbe(ctx, vaultID, key); err != nil && s.logger != nil {
		s.logger.Warn("credential identity not recorded",
			slog.String("vault_id", vaultID), slog.String("key", key), slog.String("reason", err.Error()))
	}
}

// credentialIdentityWriter is the store surface for the probe's
// conditional write (store.SQLStore implements it).
type credentialIdentityWriter interface {
	SetCredentialIdentity(ctx context.Context, vaultID, key, credentialID string, version uint64, value string) (bool, error)
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
	if inj == nil || inj.ProbeBinding == "" || inj.ProbeCredentialID == "" || len(inj.Headers) == 0 {
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
	acct, err := identity.ParseNotion(body)
	if err != nil {
		return clear(err)
	}
	// A field that equals or contains the credential (in any encoding the
	// echo scrubber knows) would put the value in credential metadata.
	sc := scrub.New(probeSecrets(inj.Headers)...)
	for _, f := range []string{acct.WorkspaceName, acct.WorkspaceID, acct.IntegrationName} {
		if sc.String(f) != f {
			return clear(errors.New("identity response field carries the credential value"))
		}
	}
	rec, err := brokercore.IdentityRecord{
		Binding:         inj.ProbeBinding,
		Digest:          acct.Digest,
		WorkspaceName:   acct.WorkspaceName,
		WorkspaceID:     acct.WorkspaceID,
		IntegrationName: acct.IntegrationName,
	}.Encode()
	if err != nil {
		return clear(err)
	}
	w, ok := s.store.(credentialIdentityWriter)
	if !ok {
		return clear(errors.New("store does not support conditional identity writes"))
	}
	// Written only if the row still has the ID and version the probe ran
	// with: a value replaced, or deleted and recreated, while the probe was
	// in flight gets no record from it.
	written, err := w.SetCredentialIdentity(ctx, vaultID, key, inj.ProbeCredentialID, inj.ProbeCredentialVersion, rec)
	if err != nil {
		return fmt.Errorf("storing identity: %w", err)
	}
	if !written {
		return errors.New("credential changed while the probe ran; identity not recorded")
	}
	if s.logger != nil {
		s.logger.Info("credential identity recorded",
			slog.String("vault_id", vaultID), slog.String("key", key), slog.String("identity", acct.Digest))
	}
	return nil
}

// probeSecrets returns the values the probe injected: each header value
// and, for "<scheme> <value>" headers, the value alone.
func probeSecrets(headers map[string]string) []string {
	var out []string
	for _, v := range headers {
		out = append(out, v)
		if _, rest, ok := strings.Cut(v, " "); ok && rest != "" {
			out = append(out, rest)
		}
	}
	return out
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
