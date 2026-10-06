// Package bootstrap applies a declarative instance configuration (vaults,
// services, agents) from a JSON document and delivers the executor
// agent's proxy token to a sink, rotating it before it expires.
//
// The document comes from a pluggable SecretsSource (AWS Secrets Manager
// in production, see package bootstrap/awssinks). The token goes to a
// TokenSink and the MITM CA certificate (never its key) to a CertSink.
//
// Guarantees:
//   - Apply is idempotent: re-applying the same document changes nothing
//     and does not mint a token while the delivered one is valid and
//     outside the rotation window.
//   - Compiled-in limits are checked before any write: every agent is
//     instance role "no-access" with vault role "proxy" only, and every
//     service passes servicepolicy.CheckServicesStrict (provider template,
//     fixed auth type, explicit read-only method+path allowlist, no
//     substitutions).
//   - Rotation is journaled (token_rotations, see rotation_journal.go) and
//     resumed from its state by every run. A new session is pending
//     (PendingExpiry) until the sink is written and read back with a
//     matching digest; at mint the old session is cut to RotationOverlap
//     and it is revoked RevokeAfter after the publish. An unconfirmed
//     session is expired and replaced, never deleted, and at most two
//     executor sessions are valid at a time.
//   - All of it runs under one cross-process lock (Postgres advisory lock
//     through store.LockVault), so concurrent bootstraps mint once.
//   - The token is never logged.
package bootstrap

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/servicepolicy"
	"github.com/Infisical/agent-vault/internal/store"
)

// RotateBefore is how long before expiry the delivered token is replaced.
const RotateBefore = 7 * 24 * time.Hour

// RotationOverlap is how long a replaced token keeps working after the
// new one has been delivered.
const RotationOverlap = 10 * time.Minute

// MinTokenTTL and MaxTokenTTL bound an agent's expires_in. The minimum
// keeps a fresh token outside the rotation window; the maximum keeps a
// leaked token short-lived.
const (
	MinTokenTTL = RotateBefore + 24*time.Hour
	MaxTokenTTL = 90 * 24 * time.Hour
)

// RotationTickTimeout bounds one rotation-loop tick end to end. The tick
// holds the bootstrap lock while it delivers the token, so a token sink
// that hangs would otherwise keep every later rotation (and every other
// task's bootstrap) waiting forever. A variable so tests can shorten it.
var RotationTickTimeout = 2 * time.Minute

// lockKey is the store lock all bootstrap work runs under.
const lockKey = "agent-vault-bootstrap"

// createdBy marks agents created by bootstrap.
const createdBy = "bootstrap"

// settingUnmatchedHostPolicy mirrors the server's vault setting key.
const settingUnmatchedHostPolicy = "unmatched_host_policy"

// Document is the declarative configuration.
type Document struct {
	Vaults   []string      `json:"vaults"`
	Services []ServiceSpec `json:"services"`
	Agents   []AgentSpec   `json:"agents"`
}

// ServiceSpec declares one broker service.
type ServiceSpec struct {
	Vault         string   `json:"vault"`
	Name          string   `json:"name"`
	Host          string   `json:"host"`
	Path          string   `json:"path"`
	Methods       []string `json:"methods"`
	AuthType      string   `json:"auth_type"`
	CredentialKey string   `json:"credential_key"`
	StrictDeny    bool     `json:"strict_deny"` // vault unmatched_host_policy=deny
}

// AgentSpec declares one agent.
type AgentSpec struct {
	Name         string            `json:"name"`
	InstanceRole string            `json:"instance_role"`
	VaultRoles   map[string]string `json:"vault_roles"`
	ExpiresIn    string            `json:"expires_in"` // Go duration, e.g. "720h"
}

// SecretsSource returns the raw bootstrap document.
type SecretsSource interface {
	BootstrapDocument(ctx context.Context) ([]byte, error)
}

// TokenSink stores the executor's proxy token where the executor reads it.
type TokenSink interface {
	PutToken(ctx context.Context, agent, token string, expiresAt time.Time) error
	GetToken(ctx context.Context, agent string) (token string, expiresAt time.Time, err error)
}

// CertSink publishes the MITM CA certificate.
type CertSink interface {
	PutCACert(ctx context.Context, certPEM []byte) error
}

// TokenCapper shortens an agent's other tokens. Bootstrap no longer calls
// it (the rotation journal caps by stored session ID); it is kept only
// because TestFinalFix_AmbiguousSinkFailureKeepsDeliveredTokenValid uses it
// in its counter self-check. Remove it together with that use.
type TokenCapper interface {
	CapAgentTokenExpiry(ctx context.Context, agentID, keepRawToken string, until time.Time) (int64, error)
}

// Options configures Apply, RotateIfDue and RunRotationLoop.
type Options struct {
	Store    store.Store
	Source   SecretsSource
	Tokens   TokenSink
	Certs    CertSink
	RootPEM  func() []byte // MITM CA certificate (public part only)
	Executor string        // agent whose token is delivered to Tokens
	Now      func() time.Time
	Logger   *slog.Logger
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o Options) log() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.Default()
}

// Apply reads the document, checks the compiled-in limits, converges
// vaults, services and agents, delivers the executor token when missing,
// unreadable, invalid or due for rotation, and publishes the CA cert.
func Apply(ctx context.Context, o Options) error {
	doc, err := load(ctx, o)
	if err != nil {
		return err
	}
	if o.Store == nil {
		return errors.New("bootstrap: no store")
	}
	unlock, err := o.Store.LockVault(ctx, lockKey)
	if err != nil {
		return fmt.Errorf("bootstrap: acquiring lock: %w", err)
	}
	defer unlock()

	vaultIDs, err := applyVaults(ctx, o, doc)
	if err != nil {
		return err
	}
	if err := applyServices(ctx, o, doc, vaultIDs); err != nil {
		return err
	}
	agentIDs, err := applyAgents(ctx, o, doc, vaultIDs)
	if err != nil {
		return err
	}
	if o.Executor != "" {
		spec, _ := agentSpec(doc, o.Executor)
		ttl, _ := time.ParseDuration(spec.ExpiresIn)
		if _, err := ensureToken(ctx, o, agentIDs[o.Executor], ttl); err != nil {
			return err
		}
	}
	if err := publishCACert(ctx, o); err != nil {
		return err
	}
	return nil
}

// RotateIfDue re-mints the executor token when the delivered one is
// missing, unreadable, invalid or within RotateBefore of expiry. It does
// not re-apply the rest of the document.
func RotateIfDue(ctx context.Context, o Options) (bool, error) {
	doc, err := load(ctx, o)
	if err != nil {
		return false, err
	}
	if o.Executor == "" {
		return false, errors.New("bootstrap: no executor configured")
	}
	unlock, err := o.Store.LockVault(ctx, lockKey)
	if err != nil {
		return false, fmt.Errorf("bootstrap: acquiring lock: %w", err)
	}
	defer unlock()

	a, err := o.Store.GetAgentByName(ctx, o.Executor)
	if err != nil || a == nil {
		return false, fmt.Errorf("bootstrap: executor agent %q not found; run Apply first", o.Executor)
	}
	if a.Status != "active" {
		return false, fmt.Errorf("bootstrap: executor agent %q is %s", o.Executor, a.Status)
	}
	spec, _ := agentSpec(doc, o.Executor)
	ttl, _ := time.ParseDuration(spec.ExpiresIn)
	return ensureToken(ctx, o, a.ID, ttl)
}

// RunRotationLoop calls RotateIfDue on every tick until ctx is done.
// Errors are logged (never the token) and retried on the next tick.
func RunRotationLoop(ctx context.Context, o Options, tick <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-tick:
			if !ok {
				return
			}
			tickCtx, cancel := context.WithTimeout(ctx, RotationTickTimeout)
			rotated, err := RotateIfDue(tickCtx, o)
			cancel()
			switch {
			case err != nil:
				o.log().Error("bootstrap: token rotation failed", slog.String("agent", o.Executor), slog.String("error", err.Error()))
			case rotated:
				o.log().Info("bootstrap: executor token rotated", slog.String("agent", o.Executor))
			}
		}
	}
}

// load reads, parses and validates the document.
func load(ctx context.Context, o Options) (*Document, error) {
	if o.Source == nil {
		return nil, errors.New("bootstrap: no document source")
	}
	raw, err := o.Source.BootstrapDocument(ctx)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: reading document: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("bootstrap: parsing document: %w", err)
	}
	if err := Validate(&doc, o.Executor); err != nil {
		return nil, err
	}
	return &doc, nil
}

// Validate enforces document consistency and the compiled-in limits. It
// runs before any write.
func Validate(doc *Document, executor string) error {
	vaults := map[string]bool{}
	for _, v := range doc.Vaults {
		if err := broker.ValidateSlug(v); err != nil {
			return fmt.Errorf("bootstrap: vault: %w", err)
		}
		if vaults[v] {
			return fmt.Errorf("bootstrap: vault %q listed twice", v)
		}
		vaults[v] = true
	}

	svcNames := map[string]bool{}
	byVault := map[string][]broker.Service{}
	for i, sp := range doc.Services {
		if !vaults[sp.Vault] {
			return fmt.Errorf("bootstrap: service %d: vault %q is not declared", i, sp.Vault)
		}
		if svcNames[sp.Vault+"/"+sp.Name] {
			return fmt.Errorf("bootstrap: service %q listed twice in vault %q", sp.Name, sp.Vault)
		}
		svcNames[sp.Vault+"/"+sp.Name] = true
		// In the policy mode every vault denies unmatched hosts, so every
		// service must say so (strict_deny sets unmatched_host_policy=deny).
		if servicepolicy.Active() && !sp.StrictDeny {
			return fmt.Errorf("bootstrap: service %q: %s is active, so strict_deny must be true", sp.Name, servicepolicy.EnvMode)
		}
		svc, err := sp.toService()
		if err != nil {
			return fmt.Errorf("bootstrap: service %q: %w", sp.Name, err)
		}
		byVault[sp.Vault] = append(byVault[sp.Vault], svc)
	}
	for v, svcs := range byVault {
		if err := broker.Validate(&broker.Config{Vault: v, Services: svcs}); err != nil {
			return fmt.Errorf("bootstrap: vault %q: %w", v, err)
		}
		if err := servicepolicy.CheckServicesStrict(svcs); err != nil {
			return fmt.Errorf("bootstrap: vault %q: compiled-in limit: %w", v, err)
		}
	}

	agents := map[string]bool{}
	for _, a := range doc.Agents {
		if err := broker.ValidateSlug(a.Name); err != nil {
			return fmt.Errorf("bootstrap: agent: %w", err)
		}
		if agents[a.Name] {
			return fmt.Errorf("bootstrap: agent %q listed twice", a.Name)
		}
		agents[a.Name] = true
		if a.InstanceRole != "no-access" {
			return fmt.Errorf("bootstrap: agent %q: compiled-in limit: instance_role must be \"no-access\", not %q", a.Name, a.InstanceRole)
		}
		if len(a.VaultRoles) == 0 {
			return fmt.Errorf("bootstrap: agent %q: at least one vault role is required", a.Name)
		}
		for v, r := range a.VaultRoles {
			if !vaults[v] {
				return fmt.Errorf("bootstrap: agent %q: vault %q is not declared", a.Name, v)
			}
			if r != "proxy" {
				return fmt.Errorf("bootstrap: agent %q: compiled-in limit: vault role on %q must be \"proxy\", not %q", a.Name, v, r)
			}
		}
		ttl, err := time.ParseDuration(a.ExpiresIn)
		if err != nil {
			return fmt.Errorf("bootstrap: agent %q: expires_in: %w", a.Name, err)
		}
		if ttl < MinTokenTTL || ttl > MaxTokenTTL {
			return fmt.Errorf("bootstrap: agent %q: expires_in %s outside [%s, %s]", a.Name, ttl, MinTokenTTL, MaxTokenTTL)
		}
	}
	if executor != "" && !agents[executor] {
		return fmt.Errorf("bootstrap: executor %q is not declared as an agent", executor)
	}
	return nil
}

func (sp ServiceSpec) toService() (broker.Service, error) {
	if err := broker.ValidateHost(sp.Host); err != nil {
		return broker.Service{}, err
	}
	if strings.Contains(sp.Host, "/") || strings.Contains(sp.Host, ":") {
		return broker.Service{}, fmt.Errorf("host %q must be a bare hostname", sp.Host)
	}
	if sp.CredentialKey == "" {
		return broker.Service{}, errors.New("credential_key is required")
	}
	auth := broker.Auth{Type: sp.AuthType}
	switch sp.AuthType {
	case "bearer":
		auth.Token = sp.CredentialKey
	case "api-key":
		auth.Key = sp.CredentialKey
	default:
		return broker.Service{}, fmt.Errorf("auth_type %q is not supported by bootstrap (bearer, api-key)", sp.AuthType)
	}
	var methods []string
	if sp.Methods != nil {
		methods = make([]string, len(sp.Methods))
		for i, m := range sp.Methods {
			methods[i] = strings.ToUpper(strings.TrimSpace(m))
		}
	}
	return broker.Service{Name: sp.Name, Host: sp.Host, Path: sp.Path, Methods: methods, Auth: auth}, nil
}

func agentSpec(doc *Document, name string) (AgentSpec, bool) {
	for _, a := range doc.Agents {
		if a.Name == name {
			return a, true
		}
	}
	return AgentSpec{}, false
}

func applyVaults(ctx context.Context, o Options, doc *Document) (map[string]string, error) {
	ids := map[string]string{}
	for _, name := range doc.Vaults {
		v, err := o.Store.GetVault(ctx, name)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("bootstrap: reading vault %q: %w", name, err)
		}
		if v == nil {
			v, err = o.Store.CreateVault(ctx, name)
			if err != nil {
				return nil, fmt.Errorf("bootstrap: creating vault %q: %w", name, err)
			}
			o.log().Info("bootstrap: vault created", slog.String("vault", name))
		}
		ids[name] = v.ID
	}
	return ids, nil
}

// applyServices upserts the declared services by name into each vault's
// broker config, leaving other services in place, and writes only when
// the result differs.
func applyServices(ctx context.Context, o Options, doc *Document, vaultIDs map[string]string) error {
	byVault := map[string][]broker.Service{}
	strict := map[string]bool{}
	for _, sp := range doc.Services {
		svc, _ := sp.toService() // validated in load
		byVault[sp.Vault] = append(byVault[sp.Vault], svc)
		if sp.StrictDeny {
			strict[sp.Vault] = true
		}
	}
	names := make([]string, 0, len(byVault))
	for v := range byVault {
		names = append(names, v)
	}
	sort.Strings(names)
	for _, vault := range names {
		vaultID := vaultIDs[vault]
		existing, oldJSON, err := loadServices(ctx, o.Store, vaultID)
		if err != nil {
			return fmt.Errorf("bootstrap: vault %q: %w", vault, err)
		}
		idx := map[string]int{}
		for i, s := range existing {
			idx[s.Name] = i
		}
		for _, svc := range byVault[vault] {
			if i, ok := idx[svc.Name]; ok {
				existing[i] = svc
			} else {
				idx[svc.Name] = len(existing)
				existing = append(existing, svc)
			}
		}
		if err := broker.Validate(&broker.Config{Vault: vault, Services: existing}); err != nil {
			return fmt.Errorf("bootstrap: vault %q: %w", vault, err)
		}
		if err := servicepolicy.CheckServices(existing); err != nil {
			return fmt.Errorf("bootstrap: vault %q: %w", vault, err)
		}
		newJSON, err := json.Marshal(existing)
		if err != nil {
			return err
		}
		if string(newJSON) != oldJSON {
			if _, err := o.Store.SetBrokerConfig(ctx, vaultID, string(newJSON)); err != nil {
				return fmt.Errorf("bootstrap: vault %q: writing services: %w", vault, err)
			}
			o.log().Info("bootstrap: services applied", slog.String("vault", vault), slog.Int("count", len(byVault[vault])))
		}
		if strict[vault] {
			cur, err := o.Store.GetVaultSetting(ctx, vaultID, settingUnmatchedHostPolicy)
			if (err != nil && !errors.Is(err, sql.ErrNoRows)) || cur != "deny" {
				if err := o.Store.SetVaultSetting(ctx, vaultID, settingUnmatchedHostPolicy, "deny"); err != nil {
					return fmt.Errorf("bootstrap: vault %q: setting strict deny: %w", vault, err)
				}
			}
		}
	}
	return nil
}

func loadServices(ctx context.Context, st store.Store, vaultID string) ([]broker.Service, string, error) {
	bc, err := st.GetBrokerConfig(ctx, vaultID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, "", err
	}
	if bc == nil || bc.ServicesJSON == "" {
		return nil, "", nil
	}
	var svcs []broker.Service
	if err := json.Unmarshal([]byte(bc.ServicesJSON), &svcs); err != nil {
		return nil, "", err
	}
	for i := range svcs {
		svcs[i].Host, svcs[i].Path, svcs[i].Port = broker.SplitInlineHost(svcs[i].Host, svcs[i].Path)
	}
	broker.AssignSlugNames(svcs)
	return svcs, bc.ServicesJSON, nil
}

// applyAgents creates missing agents and converges role and grants of
// existing ones to the document (grants not in the document are revoked).
func applyAgents(ctx context.Context, o Options, doc *Document, vaultIDs map[string]string) (map[string]string, error) {
	ids := map[string]string{}
	for _, spec := range doc.Agents {
		a, err := o.Store.GetAgentByName(ctx, spec.Name)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("bootstrap: reading agent %q: %w", spec.Name, err)
		}
		if a == nil {
			a, err = o.Store.CreateAgent(ctx, spec.Name, createdBy, spec.InstanceRole)
			if err != nil {
				return nil, fmt.Errorf("bootstrap: creating agent %q: %w", spec.Name, err)
			}
			o.log().Info("bootstrap: agent created", slog.String("agent", spec.Name))
		} else {
			if a.Status != "active" {
				return nil, fmt.Errorf("bootstrap: agent %q is %s; restore or delete it before bootstrapping", spec.Name, a.Status)
			}
			if a.Role != spec.InstanceRole {
				if err := o.Store.UpdateAgentRole(ctx, a.ID, spec.InstanceRole); err != nil {
					return nil, fmt.Errorf("bootstrap: agent %q: setting role: %w", spec.Name, err)
				}
			}
		}
		want := map[string]string{}
		for v, r := range spec.VaultRoles {
			want[vaultIDs[v]] = r
		}
		grants, err := o.Store.ListActorGrants(ctx, a.ID)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: agent %q: listing grants: %w", spec.Name, err)
		}
		have := map[string]string{}
		for _, g := range grants {
			have[g.VaultID] = g.Role
			if _, ok := want[g.VaultID]; !ok {
				if err := o.Store.RevokeVaultAccess(ctx, a.ID, g.VaultID); err != nil {
					return nil, fmt.Errorf("bootstrap: agent %q: revoking grant: %w", spec.Name, err)
				}
			}
		}
		for vid, role := range want {
			if have[vid] == role {
				continue
			}
			if err := o.Store.GrantVaultRole(ctx, a.ID, "agent", vid, role); err != nil {
				return nil, fmt.Errorf("bootstrap: agent %q: granting role: %w", spec.Name, err)
			}
		}
		ids[spec.Name] = a.ID
	}
	return ids, nil
}

// liveSession returns tok's session when the store still accepts it as a
// token of agentID (wall-clock expiry, as the proxy checks it), else nil.
func liveSession(ctx context.Context, st store.Store, tok, agentID string) *store.Session {
	sess, err := st.GetSession(ctx, tok)
	if err != nil || sess == nil || sess.AgentID != agentID || sess.IsExpired(time.Now()) {
		return nil
	}
	return sess
}

// publishCACert writes the CA certificate to the cert sink after checking
// that it holds certificate blocks only.
func publishCACert(ctx context.Context, o Options) error {
	if o.Certs == nil || o.RootPEM == nil {
		return nil
	}
	certPEM := o.RootPEM()
	if len(certPEM) == 0 {
		return errors.New("bootstrap: CA certificate is empty")
	}
	rest := certPEM
	blocks := 0
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return fmt.Errorf("bootstrap: refusing to publish a %q PEM block", blk.Type)
		}
		blocks++
	}
	if blocks == 0 || len(bytes.TrimSpace(rest)) != 0 || bytes.Contains(certPEM, []byte("PRIVATE KEY")) {
		return errors.New("bootstrap: CA material is not a plain certificate")
	}
	if err := o.Certs.PutCACert(ctx, certPEM); err != nil {
		return fmt.Errorf("bootstrap: publishing CA certificate: %w", err)
	}
	return nil
}
