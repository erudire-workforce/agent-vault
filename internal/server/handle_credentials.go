package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/infisical"
	"github.com/Infisical/agent-vault/internal/store"
)

type credentialsSetRequest struct {
	Vault       string            `json:"vault"`
	Credentials map[string]string `json:"credentials"`
}

type credentialsSetResponse struct {
	Set []string `json:"set"`
}

func (s *Server) handleCredentialsSet(w http.ResponseWriter, r *http.Request) {
	var req credentialsSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}
	if len(req.Credentials) == 0 {
		jsonError(w, http.StatusBadRequest, "Credentials map is required")
		return
	}

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}

	// Setting credentials requires member+ role.
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	if !s.assertBuiltinCredentialStore(w, ctx, ns.ID, ns.Name) {
		return
	}

	for key := range req.Credentials {
		if !broker.CredentialKeyPattern.MatchString(key) {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid credential key %q: must be SCREAMING_SNAKE_CASE (e.g. STRIPE_KEY)", key))
			return
		}
	}

	var setKeys []string
	for key, value := range req.Credentials {
		if err := s.putCredentialValue(ctx, ns.ID, key, []byte(value)); err != nil {
			jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to set credential %q", key))
			return
		}
		setKeys = append(setKeys, key)
	}

	actor, _ := s.actorFromSession(r.Context(), sessionFromContext(r.Context()))
	s.captureEvent(r, "av.credential-set", actor, nil)
	jsonOK(w, credentialsSetResponse{Set: setKeys})
}

// credentialEntry is the metadata of a stored credential. Stored values are
// write-only for every role, including the owner: no read endpoint returns
// one. Value is never populated (it stays in the type so existing clients
// decode an absent field rather than fail).
type credentialEntry struct {
	Key              string  `json:"key"`
	Type             string  `json:"type,omitempty"`
	Value            string  `json:"value,omitempty"`
	Hint             string  `json:"hint,omitempty"`
	Version          uint64  `json:"version,omitempty"`
	UpdatedAt        string  `json:"updated_at,omitempty"`
	ConnectedAt      *string `json:"connected_at,omitempty"`
	LastRefreshedAt  *string `json:"last_refreshed_at,omitempty"`
	LastRefreshError *string `json:"last_refresh_error,omitempty"`
	// OAuth config (non-secret fields for edit form pre-fill)
	AuthorizationURL *string `json:"authorization_url,omitempty"`
	TokenURL         *string `json:"token_url,omitempty"`
	ClientID         *string `json:"client_id,omitempty"`
	Scopes           *string `json:"scopes,omitempty"`
	ClientSecret     *string `json:"client_secret,omitempty"`
	TokenAuthMethod  *string `json:"token_auth_method,omitempty"`
	AccessToken      *string `json:"access_token,omitempty"`
	RefreshToken     *string `json:"refresh_token,omitempty"`
	// Unavailable marks a dynamic-secret row whose lease could not be minted
	// (e.g. the machine identity lacks lease permission). No value is exposed.
	Unavailable bool `json:"unavailable,omitempty"`
}

type credentialsListResponse struct {
	Keys        []string          `json:"keys"`
	Credentials []credentialEntry `json:"credentials,omitempty"`
}

func (s *Server) handleCredentialsList(w http.ResponseWriter, r *http.Request) {
	vault := r.URL.Query().Get("vault")
	if vault == "" {
		vault = store.DefaultVault
	}
	reveal := r.URL.Query().Get("reveal") == "true"
	keyFilter := r.URL.Query().Get("key")

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vault))
		return
	}

	if reveal {
		// Revealing values requires member+ role (blocks proxy-role agents).
		if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
			return
		}
	} else {
		// Listing keys only requires any vault access.
		if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
			return
		}
	}

	// Single-key reveal: fetch and decrypt one credential.
	if reveal && keyFilter != "" {
		cred, err := s.store.GetCredential(ctx, ns.ID, keyFilter)
		if err != nil {
			// Not a static credential: it may be a dynamic-secret field, leased
			// on demand and held in memory rather than the credentials table.
			if entry, ok := s.revealDynamicCredential(ctx, ns.ID, keyFilter); ok {
				jsonOK(w, credentialsListResponse{Keys: []string{keyFilter}, Credentials: []credentialEntry{entry}})
				return
			}
			jsonError(w, http.StatusNotFound, fmt.Sprintf("Credential %q not found", keyFilter))
			return
		}
		entry := credentialMetadata(cred)
		if cred.Type == "oauth" {
			s.enrichOAuthEntry(ctx, ns.ID, &entry)
		}
		jsonOK(w, credentialsListResponse{
			Keys:        []string{cred.Key},
			Credentials: []credentialEntry{entry},
		})
		return
	}

	creds, err := s.store.ListCredentials(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list credentials")
		return
	}

	keys := make([]string, len(creds))
	entries := make([]credentialEntry, len(creds))
	isMember := s.isMemberOrAbove(r, ns.ID)
	for i, cred := range creds {
		keys[i] = cred.Key
		entries[i] = credentialMetadata(&cred)

		if cred.Type == "oauth" && isMember {
			s.enrichOAuthEntry(ctx, ns.ID, &entries[i])
		}
	}

	// Fold leased dynamic-secret fields into the same list, tagged type="dynamic".
	// Gated to member+: enumeration MINTS leases (provisions upstream resources),
	// so a proxy-role agent must not be able to trigger it by listing. Proxy
	// agents still lease on actual proxied use of a wired service.
	if isMember {
		for _, d := range s.enumerateDynamicCredentials(ctx, ns.ID) {
			keys = append(keys, d.Key)
			// Leased values are write-only too: metadata only.
			entries = append(entries, credentialEntry{Key: d.Key, Type: credentialTypeDynamic, Unavailable: d.Unavailable})
		}
	}

	resp := credentialsListResponse{Keys: keys}
	if isMember || reveal {
		resp.Credentials = entries
	}
	jsonOK(w, resp)
}

// credentialTypeDynamic tags entries sourced from an Infisical dynamic-secret
// lease rather than the local credentials table.
const credentialTypeDynamic = "dynamic"

// enumerateDynamicCredentials returns the vault's leased dynamic-secret fields
// as credential entries. Best-effort: a nil resolver or an upstream error
// yields none rather than failing the credential listing.
func (s *Server) enumerateDynamicCredentials(ctx context.Context, vaultID string) []infisical.EnumeratedCredential {
	if s.infisicalDynamic == nil {
		return nil
	}
	creds, err := s.infisicalDynamic.Enumerate(ctx, vaultID)
	if err != nil {
		s.logger.Warn("enumerating dynamic secrets failed",
			slog.String("vault_id", vaultID), slog.String("err", err.Error()))
		return nil
	}
	return creds
}

// revealDynamicCredential resolves a single dynamic-secret field key to a
// credential entry with its leased value. ok=false when the key is not a
// dynamic credential (callers then return the normal not-found error).
func (s *Server) revealDynamicCredential(ctx context.Context, vaultID, key string) (credentialEntry, bool) {
	if s.infisicalDynamic == nil {
		return credentialEntry{}, false
	}
	_, ok, err := s.infisicalDynamic.Resolve(ctx, vaultID, key)
	if err != nil || !ok {
		if err != nil {
			s.logger.Warn("resolving dynamic secret for reveal failed",
				slog.String("vault_id", vaultID), slog.String("err", err.Error()))
		}
		return credentialEntry{}, false
	}
	// Write-only: the leased value is never returned, only its metadata.
	return credentialEntry{Key: key, Type: credentialTypeDynamic}, true
}

func (s *Server) enrichOAuthEntry(ctx context.Context, vaultID string, entry *credentialEntry) {
	co, err := s.store.GetCredentialOAuth(ctx, vaultID, entry.Key)
	if err != nil || co == nil {
		return
	}
	if co.ConnectedAt != nil {
		t := co.ConnectedAt.Format(time.RFC3339)
		entry.ConnectedAt = &t
	}
	if co.LastRefreshedAt != nil {
		t := co.LastRefreshedAt.Format(time.RFC3339)
		entry.LastRefreshedAt = &t
	}
	if co.LastRefreshError != "" {
		msg := safeRefreshError(co.LastRefreshError)
		entry.LastRefreshError = &msg
	}
	if co.AuthorizationURL != "" {
		entry.AuthorizationURL = &co.AuthorizationURL
	}
	if co.TokenURL != "" {
		entry.TokenURL = &co.TokenURL
	}
	if co.ClientID != "" {
		entry.ClientID = &co.ClientID
	}
	if co.Scopes != "" {
		entry.Scopes = &co.Scopes
	}
	if len(co.ClientSecretCT) > 0 {
		s := oauthSecretSentinel
		entry.ClientSecret = &s
	}
	if co.TokenAuthMethod != "" {
		entry.TokenAuthMethod = &co.TokenAuthMethod
	}
	if co.ConnectedAt != nil {
		s := oauthSecretSentinel
		entry.AccessToken = &s
	}
	if len(co.RefreshTokenCT) > 0 {
		s := oauthSecretSentinel
		entry.RefreshToken = &s
	}
}

// credentialMetadata describes a stored credential without its value: the
// masked hint carries only the value's length, derived from the ciphertext
// size (AES-GCM adds a 16-byte tag) so nothing is decrypted.
func credentialMetadata(cred *store.Credential) credentialEntry {
	e := credentialEntry{Key: cred.Key, Type: cred.Type, Version: cred.Version}
	if !cred.UpdatedAt.IsZero() {
		e.UpdatedAt = cred.UpdatedAt.UTC().Format(time.RFC3339)
	}
	if n := len(cred.Ciphertext) - 16; n >= 0 && len(cred.Ciphertext) > 0 {
		e.Hint = fmt.Sprintf("%s (%d chars)", oauthSecretSentinel, n)
	}
	return e
}

// putCredentialValue seals value for the row's next version and writes it
// with compare-and-set, retrying when a concurrent write moved the version.
func (s *Server) putCredentialValue(ctx context.Context, vaultID, key string, value []byte) error {
	for attempt := 0; attempt < 5; attempt++ {
		next := s.credentialVersion(ctx, vaultID, key) + 1
		ct, nonce, err := store.CredentialValueAAD(vaultID, key, next).Seal(value, s.encKey)
		if err != nil {
			return err
		}
		_, err = s.store.SetCredentialVersion(ctx, vaultID, key, ct, nonce, next)
		if !errors.Is(err, store.ErrVersionConflict) {
			return err
		}
	}
	return store.ErrVersionConflict
}

func (s *Server) isMemberOrAbove(r *http.Request, vaultID string) bool {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		return false
	}
	if sess.VaultID != "" {
		return sess.VaultID == vaultID && roleSatisfies(sess.VaultRole, "member")
	}
	actor, err := s.actorFromSession(r.Context(), sess)
	if err != nil || actor == nil {
		return false
	}
	role, err := s.store.GetVaultRole(r.Context(), actor.ID, vaultID)
	if err != nil {
		return false
	}
	return roleSatisfies(role, "member")
}

type credentialsDeleteRequest struct {
	Vault string   `json:"vault"`
	Keys  []string `json:"keys"`
}

type credentialsDeleteResponse struct {
	Deleted []string `json:"deleted"`
}

func (s *Server) handleCredentialsDelete(w http.ResponseWriter, r *http.Request) {
	var req credentialsDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}
	if len(req.Keys) == 0 {
		jsonError(w, http.StatusBadRequest, "Keys list is required")
		return
	}

	ctx := r.Context()

	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}

	// Deleting credentials requires member+ role.
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	if !s.assertBuiltinCredentialStore(w, ctx, ns.ID, ns.Name) {
		return
	}

	var deleted []string
	for _, key := range req.Keys {
		if err := s.store.DeleteCredential(ctx, ns.ID, key); err != nil {
			jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to delete credential %q", key))
			return
		}
		deleted = append(deleted, key)
	}

	actor, _ := s.actorFromSession(r.Context(), sessionFromContext(r.Context()))
	s.captureEvent(r, "av.credential-delete", actor, nil)
	jsonOK(w, credentialsDeleteResponse{Deleted: deleted})
}

// listCredentialKeys returns the key names of all credentials in the given vault.
// Returns an empty (non-nil) slice on error so JSON serializes as [].
func (s *Server) listCredentialKeys(ctx context.Context, vaultID string) []string {
	creds, err := s.store.ListCredentials(ctx, vaultID)
	if err != nil || len(creds) == 0 {
		return []string{}
	}
	keys := make([]string, len(creds))
	for i, cred := range creds {
		keys[i] = cred.Key
	}
	return keys
}
