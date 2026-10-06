package brokercore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/servicepolicy"
	"github.com/Infisical/agent-vault/internal/store"
)

// UnmatchedHostPolicy controls what happens when a request's target host
// does not match any configured broker service. PolicyPassthrough is the
// system-wide default; PolicyDeny is the opt-in strict mode.
type UnmatchedHostPolicy string

const (
	PolicyPassthrough UnmatchedHostPolicy = "passthrough"
	PolicyDeny        UnmatchedHostPolicy = "deny"
)

func IsValidUnmatchedHostPolicy(p UnmatchedHostPolicy) bool {
	return p == PolicyPassthrough || p == PolicyDeny
}

// InjectResult is the outcome of matching (host, path) and resolving
// credentials to ready-to-attach HTTP headers.
type InjectResult struct {
	// Headers carries SECRET values — never log. Caller must Set (not
	// Add) so injected values win over client-supplied duplicates.
	// Nil for passthrough services.
	Headers map[string]string

	// MatchedName/Host/Path/Port describe the matched service. Safe to log.
	// Empty under unmatched-host passthrough.
	MatchedName string
	MatchedHost string
	MatchedPath string
	MatchedPort *int

	// CredentialKeys are the key names referenced by the matched
	// service. Populated before resolution so credential-missing
	// errors still carry diagnostic context. Safe to log.
	CredentialKeys []string

	// Substitutions are resolved placeholder rewrites; each entry
	// carries a SECRET Value — never log placeholder values.
	Substitutions []ResolvedSubstitution

	// Passthrough is set when no service matched but the unmatched-host
	// policy permitted forwarding.
	Passthrough bool

	// CredentialIdentity is the recorded identity digest (see package
	// identity) of the account the injected credential acts as, or ""
	// when none is recorded for the exact stored value that was
	// injected. Not secret.
	CredentialIdentity string

	// ProbeBinding is set only for WithProbeService calls: the
	// VersionBinding of the single stored value that was injected, or
	// "" when the value was not a plain stored credential (dynamic, or
	// refreshed during the call). The probe records its digest under this
	// binding, never under a binding read separately.
	ProbeBinding string
	// ProbeCredentialID and ProbeCredentialVersion are the credentials
	// row ID and version ProbeBinding was built from. The probe's write is
	// conditional on the row still carrying both.
	ProbeCredentialID      string
	ProbeCredentialVersion uint64
}

// CredentialProvider resolves a service for (targetHost, targetPath) in
// vaultID and returns the headers to attach. targetPath must be the URL
// path only — no query, no fragment.
type CredentialProvider interface {
	Inject(ctx context.Context, vaultID, targetHost string, targetPort int, targetPath string) (*InjectResult, error)
}

// CredentialStore is the minimal store surface used by StoreCredentialProvider.
type CredentialStore interface {
	GetBrokerConfig(ctx context.Context, vaultID string) (*store.BrokerConfig, error)
	GetCredential(ctx context.Context, vaultID, key string) (*store.Credential, error)
	UnmatchedHostPolicy(ctx context.Context, vaultID string) (UnmatchedHostPolicy, error)
}

// OAuthStore is the store surface for OAuth token refresh.
// Passed separately to StoreCredentialProvider to keep CredentialStore minimal.
type OAuthStore interface {
	GetCredentialOAuth(ctx context.Context, vaultID, key string) (*store.CredentialOAuth, error)
	UpdateCredentialOAuthTokens(ctx context.Context, vaultID, key string, accessCT, accessNonce, refreshCT, refreshNonce []byte, expiresAt *time.Time) error
	UpdateCredentialOAuthError(ctx context.Context, vaultID, key string, errMsg string) error
}

// DynamicCredentialResolver resolves credential keys that are not stored
// statically — e.g. Infisical dynamic-secret leases minted on demand. ok=false
// means "not a dynamic credential" (the caller keeps its not-found error); a
// non-nil error is a real failure. Implemented outside brokercore (infisical)
// and injected, so brokercore takes no dependency on it.
type DynamicCredentialResolver interface {
	Resolve(ctx context.Context, vaultID, key string) (value string, ok bool, err error)
}

// StoreCredentialProvider injects credentials using a CredentialStore and a
// 32-byte AES-256-GCM key held in memory for the lifetime of the process.
type StoreCredentialProvider struct {
	Store      CredentialStore
	OAuthStore OAuthStore // nil = no OAuth refresh
	EncKey     []byte
	Refresher  *oauth.Refresher          // nil = no OAuth refresh
	Dynamic    DynamicCredentialResolver // nil = no dynamic-secret resolution

	// OnCredentialRefreshed, when set, is called (in its own goroutine)
	// after an OAuth refresh minted a new access token, so the identity
	// probe can re-run for the new value.
	OnCredentialRefreshed func(vaultID, key string)
}

// NewStoreCredentialProvider constructs a provider. encKey must be 32 bytes.
func NewStoreCredentialProvider(s CredentialStore, encKey []byte) *StoreCredentialProvider {
	return &StoreCredentialProvider{Store: s, EncKey: encKey}
}

// Inject matches (targetHost, targetPath) and resolves the matched
// service's auth into HTTP headers. targetHost may include a port —
// stripped before matching. Pass "/" for targetPath when no path is
// meaningful.
func (p *StoreCredentialProvider) Inject(ctx context.Context, vaultID, targetHost string, targetPort int, targetPath string) (*InjectResult, error) {
	// A missing row is equivalent to an empty services list — fall
	// through to the unmatched-host policy. Any other error fails closed
	// so a transient store failure can't silently strip enforcement.
	cfg, err := p.Store.GetBrokerConfig(ctx, vaultID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, ErrServiceNotFound
	}

	var services []broker.Service
	if cfg != nil && cfg.ServicesJSON != "" {
		if err := json.Unmarshal([]byte(cfg.ServicesJSON), &services); err != nil {
			return nil, fmt.Errorf("brokercore: parsing broker services: %w", err)
		}
	}
	// MarshalJSON persists Host in joined-inline form; the matcher
	// requires Host without "/", so split before matching.
	for i := range services {
		services[i].Host, services[i].Path, services[i].Port = broker.SplitInlineHost(services[i].Host, services[i].Path)
	}
	// Heal legacy unnamed entries so MatchedName (which lands in the
	// request log and the X-Vault-Service header) is never blank for a
	// matched service — the documented `?service=<name>` log filter
	// depends on it.
	broker.AssignSlugNames(services)

	matchHost := targetHost
	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		matchHost = h
	}
	if targetPath == "" {
		targetPath = "/"
	}
	// The matcher must see exactly what is forwarded. Callers pass the
	// decoded path after CanonicalRequestPath; refuse anything that could
	// still be read differently by the upstream.
	if !IsCanonicalPath(targetPath) {
		return nil, ErrNonCanonicalPath
	}
	matched, score, methodDenied := broker.MatchServiceDetail(RequestMethod(ctx), matchHost, targetPort, targetPath, services)
	probe := probeServiceFrom(ctx)
	if probe != nil {
		// Identity probe: resolve the given service's auth through the
		// normal injection path, regardless of its path/method rules.
		// Only server-side code can set this; the proxy never does.
		matched, methodDenied = probe, false
	}
	if methodDenied {
		return nil, ErrMethodNotAllowed
	}
	if matched == nil {
		// Fail closed on policy lookup errors so a transient store
		// failure can't silently strip enforcement.
		policy, err := p.Store.UnmatchedHostPolicy(ctx, vaultID)
		if err != nil || policy == PolicyDeny {
			return nil, ErrServiceNotFound
		}
		return &InjectResult{Passthrough: true}, nil
	}
	if !matched.IsEnabled() {
		return nil, ErrServiceDisabled
	}
	// Re-check the compiled-in policy at request time so a services row
	// written behind the API (or before the mode was enabled) is refused.
	if servicepolicy.Active() && probe == nil {
		if err := servicepolicy.CheckService(*matched); err != nil {
			return nil, ErrServicePolicy
		}
	}
	slog.Default().Debug("broker matched",
		slog.String("vault", vaultID),
		slog.String("service", matched.Name),
		slog.String("host", matched.Host),
		slog.String("path", matched.Path),
		slog.String("host_tier", score.HostTierName()),
		slog.Int("path_prefix_len", score.PathLiteralLen),
		slog.Int("decl_order", score.DeclOrder),
	)

	// Memoize per-key lookups so a credential shared by auth and a
	// substitution decrypts only once.
	cache := make(map[string]string)
	// storedVersion binds each static value to the credential row and the
	// version it was sealed for, so a recorded identity is used only for
	// that value.
	storedVersion := make(map[string]storedRow)
	getCredential := func(key string) (string, error) {
		if v, ok := cache[key]; ok {
			return v, nil
		}
		cred, err := p.Store.GetCredential(ctx, vaultID, key)
		if err != nil || cred == nil {
			// No static credential: try resolving it as a dynamic-secret field.
			if p.Dynamic != nil {
				if val, ok, derr := p.Dynamic.Resolve(ctx, vaultID, key); derr != nil {
					return "", derr
				} else if ok {
					cache[key] = val
					return val, nil
				}
			}
			return "", fmt.Errorf("credential %q not found", key)
		}

		// Values are bound to (vault, key, version) through AAD: a ciphertext
		// copied from another row, vault, field or an older version fails here.
		plaintext, err := store.CredentialValueAAD(vaultID, key, cred.Version).Open(cred.Ciphertext, cred.Nonce, p.EncKey)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt credential %q", key)
		}
		s := string(plaintext)

		if cred.Type == "oauth" && s == "" {
			return "", fmt.Errorf("%w: credential %q", ErrOAuthNotConnected, key)
		}

		storedVersion[key] = storedRow{id: cred.ID, version: cred.Version}
		if cred.Type == "oauth" && p.Refresher != nil && p.OAuthStore != nil {
			refreshed, err := p.maybeRefreshOAuth(ctx, vaultID, key, cred.Version, s)
			if err != nil {
				return "", err
			}
			if refreshed != s {
				// A new access token was minted: the recorded identity was
				// bound to the old value. Re-probe in the background.
				delete(storedVersion, key)
				if p.OnCredentialRefreshed != nil {
					go p.OnCredentialRefreshed(vaultID, key)
				}
			}
			s = refreshed
		}

		cache[key] = s
		return s, nil
	}

	// Capture non-secret metadata up front so a downstream credential-missing
	// error still carries it for diagnostic logging.
	result := &InjectResult{
		MatchedName:    matched.Name,
		MatchedHost:    matched.Host,
		MatchedPath:    matched.Path,
		MatchedPort:    matched.Port,
		CredentialKeys: matched.CredentialKeys(),
	}

	// Resolve substitutions before auth so passthrough services (which
	// skip the auth branch) still surface ErrCredentialMissing here.
	// Hold locally and attach only on success — error returns must not
	// expose resolved secret values via result.
	var resolvedSubs []ResolvedSubstitution
	if len(matched.Substitutions) > 0 {
		resolvedSubs = make([]ResolvedSubstitution, 0, len(matched.Substitutions))
		for _, sub := range matched.Substitutions {
			val, err := getCredential(sub.Key)
			if err != nil {
				return result, fmt.Errorf("%w: %v", ErrCredentialMissing, err)
			}
			resolvedSubs = append(resolvedSubs, ResolvedSubstitution{
				Placeholder: sub.Placeholder,
				Value:       val,
				In:          sub.NormalizedIn(),
			})
		}
	}

	if matched.Auth.Type == "passthrough" {
		result.Substitutions = resolvedSubs
		return result, nil
	}

	headers, err := matched.Auth.Resolve(getCredential)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrCredentialMissing, err)
	}

	result.Headers = headers
	result.Substitutions = resolvedSubs
	result.CredentialIdentity = p.recordedIdentity(ctx, vaultID, matched.Auth.CredentialKeys(), storedVersion)
	if probe != nil {
		if keys := matched.Auth.CredentialKeys(); len(keys) == 1 {
			if row, ok := storedVersion[keys[0]]; ok && row.id != "" {
				result.ProbeBinding = VersionBinding(row.id, row.version)
				result.ProbeCredentialID = row.id
				result.ProbeCredentialVersion = row.version
			}
		}
	}
	return result, nil
}

type probeCtxKey struct{}

// WithProbeService makes Inject resolve svc's auth directly instead of
// matching the request against the vault's services. It is used only by
// the server-side identity probe, which must call the provider's identity
// endpoint (for Notion, GET /v1/users/me) even when the vault's rules
// allow only other paths.
func WithProbeService(ctx context.Context, svc broker.Service) context.Context {
	return context.WithValue(ctx, probeCtxKey{}, &svc)
}

func probeServiceFrom(ctx context.Context) *broker.Service {
	s, _ := ctx.Value(probeCtxKey{}).(*broker.Service)
	return s
}

// IdentityStore is the optional store surface for recorded credential
// identity digests. StoreCredentialProvider uses it when its Store
// implements it.
type IdentityStore interface {
	GetVaultSetting(ctx context.Context, vaultID, key string) (string, error)
}

// storedRow is the credentials row a static value was read from.
type storedRow struct {
	id      string
	version uint64
}

// IdentitySettingKey is the vault-setting key holding the identity record
// for credential key. Value format: "<binding>:<digest>" where binding is
// the VersionBinding of the stored value the probe ran with, so the digest
// sits beside the credential row and version it describes.
func IdentitySettingKey(credentialKey string) string {
	return store.CredentialIdentitySettingKey(credentialKey)
}

// VersionBinding is the non-secret handle that ties an identity record to
// one stored value: the credential row's ID and version ("<id>@<version>").
// The version is bound into the value's AAD and bumped on every write
// (including an OAuth refresh), so any change to the value invalidates the
// record; the row ID changes when the key is deleted and recreated, so a
// recreated row restarting at version 1 cannot match a record left behind.
func VersionBinding(credentialID string, version uint64) string {
	return credentialID + "@" + strconv.FormatUint(version, 10)
}

// recordedIdentity returns the digest recorded for the single credential
// the auth config injects, provided it was recorded for the exact stored
// value used now. Services that inject several keys, or none, get "".
func (p *StoreCredentialProvider) recordedIdentity(ctx context.Context, vaultID string, authKeys []string, rows map[string]storedRow) string {
	if len(authKeys) != 1 {
		return ""
	}
	key := authKeys[0]
	row, ok := rows[key]
	if !ok || row.id == "" {
		return ""
	}
	binding := VersionBinding(row.id, row.version)
	is, ok := p.Store.(IdentityStore)
	if !ok {
		return ""
	}
	rec, err := is.GetVaultSetting(ctx, vaultID, IdentitySettingKey(key))
	if err != nil {
		return ""
	}
	i := strings.LastIndexByte(rec, ':')
	if i < 0 {
		return ""
	}
	gotBinding, digest := rec[:i], rec[i+1:]
	if gotBinding != binding || len(digest) != 64 {
		return ""
	}
	return digest
}

const oauthRefreshBuffer = 5 * time.Minute

func (p *StoreCredentialProvider) maybeRefreshOAuth(ctx context.Context, vaultID, key string, accessVersion uint64, currentToken string) (string, error) {
	oauthCfg, err := p.OAuthStore.GetCredentialOAuth(ctx, vaultID, key)
	if err != nil {
		return currentToken, nil
	}

	if oauthCfg.TokenExpiresAt == nil {
		return currentToken, nil
	}
	if time.Until(*oauthCfg.TokenExpiresAt) > oauthRefreshBuffer {
		return currentToken, nil
	}

	if len(oauthCfg.RefreshTokenCT) == 0 {
		return currentToken, nil
	}

	sfKey := vaultID + "|" + key
	result := p.Refresher.Do(sfKey, func() oauth.RefreshResult {
		refreshToken, err := store.OAuthRefreshTokenAAD(vaultID, key, oauthCfg.Version).Open(oauthCfg.RefreshTokenCT, oauthCfg.RefreshTokenNonce, p.EncKey)
		if err != nil {
			return oauth.RefreshResult{Err: fmt.Errorf("%w: decrypt refresh token: %v", ErrOAuthRefreshFailed, err)}
		}

		var clientSecret string
		if len(oauthCfg.ClientSecretCT) > 0 {
			cs, err := store.OAuthClientSecretAAD(vaultID, key, oauthCfg.ClientSecretVersion).Open(oauthCfg.ClientSecretCT, oauthCfg.ClientSecretNonce, p.EncKey)
			if err != nil {
				return oauth.RefreshResult{Err: fmt.Errorf("%w: decrypt client secret: %v", ErrOAuthRefreshFailed, err)}
			}
			clientSecret = string(cs)
		}

		tok, err := oauth.Refresh(ctx, oauth.RefreshConfig{
			TokenURL:        oauthCfg.TokenURL,
			ClientID:        oauthCfg.ClientID,
			ClientSecret:    clientSecret,
			RefreshToken:    string(refreshToken),
			Scopes:          oauthCfg.Scopes,
			ScopeSeparator:  oauthCfg.ScopeSeparator,
			TokenAuthMethod: oauthCfg.TokenAuthMethod,
		})
		if err != nil {
			msg := RefreshErrorMessage(err)
			_ = p.OAuthStore.UpdateCredentialOAuthError(ctx, vaultID, key, msg)
			return oauth.RefreshResult{Err: fmt.Errorf("%w: %s", ErrOAuthRefreshFailed, msg)}
		}

		// The store bumps credentials.version on the access-token write and
		// credential_oauth.version on a refresh-token write; seal for the
		// versions the rows will have after the update.
		accessCT, accessNonce, err := store.CredentialValueAAD(vaultID, key, accessVersion+1).Seal([]byte(tok.AccessToken), p.EncKey)
		if err != nil {
			return oauth.RefreshResult{Err: fmt.Errorf("%w: encrypt access token: %v", ErrOAuthRefreshFailed, err)}
		}

		var newRefreshCT, newRefreshNonce []byte
		if tok.RefreshToken != "" {
			newRefreshCT, newRefreshNonce, err = store.OAuthRefreshTokenAAD(vaultID, key, oauthCfg.Version+1).Seal([]byte(tok.RefreshToken), p.EncKey)
			if err != nil {
				return oauth.RefreshResult{Err: fmt.Errorf("%w: encrypt refresh token: %v", ErrOAuthRefreshFailed, err)}
			}
		}

		var expiresAt *time.Time
		if !tok.ExpiresAt.IsZero() {
			expiresAt = &tok.ExpiresAt
		}

		if err := p.OAuthStore.UpdateCredentialOAuthTokens(ctx, vaultID, key, accessCT, accessNonce, newRefreshCT, newRefreshNonce, expiresAt); err != nil {
			return oauth.RefreshResult{Err: fmt.Errorf("%w: store tokens: %v", ErrOAuthRefreshFailed, err)}
		}

		return oauth.RefreshResult{AccessToken: tok.AccessToken, Refreshed: true}
	})

	if result.Err != nil {
		return "", result.Err
	}
	if result.Refreshed {
		return result.AccessToken, nil
	}
	return currentToken, nil
}

// RefreshErrorMessage is the only text about a failed OAuth token request
// that may be persisted (credential_oauth.last_refresh_error), logged or
// returned: token endpoints echo request secrets in their error bodies, so
// the message is built from the status code and a registered RFC 6749 error
// code only.
func RefreshErrorMessage(err error) string {
	var te *oauth.TokenError
	if errors.As(err, &te) {
		return te.Error()
	}
	return "oauth: token request failed"
}
