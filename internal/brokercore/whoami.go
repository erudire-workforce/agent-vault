package brokercore

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// Whoami describes the principal behind a proxy token: its instance
// role, its vault grants and when the token expires. It never carries a
// credential or the token itself.
type Whoami struct {
	InstanceRole string        `json:"instance_role"`
	Vaults       []WhoamiVault `json:"vaults"`
	ExpiresAt    *string       `json:"expires_at"` // RFC 3339 UTC; null = never
}

// WhoamiVault is one vault grant.
type WhoamiVault struct {
	Vault string `json:"vault"`
	Role  string `json:"role"`
}

// WhoamiResolver is implemented by session resolvers that can describe a
// token. The proxy listener serves GET /v1/whoami through it.
type WhoamiResolver interface {
	Whoami(ctx context.Context, token string) (*Whoami, error)
}

// whoamiStore is the optional store surface Whoami needs on top of
// SessionStore. The production store implements it.
type whoamiStore interface {
	GetAgentByID(ctx context.Context, id string) (*store.Agent, error)
	GetUserByID(ctx context.Context, id string) (*store.User, error)
}

// Whoami validates token exactly as ResolveForProxy does (same expiry and
// revocation rules) and describes it. Only tokens usable on the proxy
// qualify: agent tokens and vault-scoped sessions. A user login session
// is refused with ErrInvalidSession.
func (r *StoreSessionResolver) Whoami(ctx context.Context, token string) (*Whoami, error) {
	if _, err := r.ResolveForProxy(ctx, token, ""); err != nil &&
		!errors.Is(err, ErrAgentVaultAmbiguous) && !errors.Is(err, ErrNoVaultContext) {
		return nil, ErrInvalidSession
	}
	sess, err := r.Store.GetSession(ctx, token)
	if err != nil || sess == nil {
		return nil, ErrInvalidSession
	}
	if sess.VaultID == "" && sess.AgentID == "" {
		return nil, ErrInvalidSession // user login session, not a proxy token
	}
	ws, _ := r.Store.(whoamiStore)

	out := &Whoami{InstanceRole: "none", Vaults: []WhoamiVault{}}
	switch {
	case sess.AgentID != "" && ws != nil:
		if a, err := ws.GetAgentByID(ctx, sess.AgentID); err == nil && a != nil {
			out.InstanceRole = a.Role
		}
	case sess.UserID != "" && ws != nil:
		if u, err := ws.GetUserByID(ctx, sess.UserID); err == nil && u != nil {
			out.InstanceRole = u.Role
		}
	}

	if sess.VaultID != "" {
		v, err := r.Store.GetVaultByID(ctx, sess.VaultID)
		if err != nil || v == nil {
			return nil, ErrVaultNotFound
		}
		out.Vaults = append(out.Vaults, WhoamiVault{Vault: v.Name, Role: sess.VaultRole})
	} else {
		grants, err := r.Store.ListActorGrants(ctx, sess.AgentID)
		if err != nil {
			return nil, err
		}
		for _, g := range grants {
			name := g.VaultName
			if name == "" {
				if v, err := r.Store.GetVaultByID(ctx, g.VaultID); err == nil && v != nil {
					name = v.Name
				}
			}
			out.Vaults = append(out.Vaults, WhoamiVault{Vault: name, Role: g.Role})
		}
		sort.Slice(out.Vaults, func(i, j int) bool { return out.Vaults[i].Vault < out.Vaults[j].Vault })
	}

	if sess.ExpiresAt != nil {
		s := sess.ExpiresAt.UTC().Format(time.RFC3339)
		out.ExpiresAt = &s
	}
	return out, nil
}
