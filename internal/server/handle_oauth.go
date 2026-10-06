package server

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

const oauthStateTTL = 10 * time.Minute

const oauthSecretSentinel = "••••••••"

// oauthWriteAttempts bounds the compare-and-set retries of an OAuth write.
const oauthWriteAttempts = 3

// Errors a retried OAuth write closure returns so the handler can pick the
// response; neither carries secret material.
var (
	errOAuthDecryptClientSecret = errors.New("decrypting client secret failed")
	errOAuthDecryptRefreshToken = errors.New("decrypting refresh token failed")
	errOAuthEncrypt             = errors.New("encryption failed")
	errOAuthNoAccessToken       = errors.New("no existing access token to preserve")
)

type oauthConnectRequest struct {
	Vault            string `json:"vault"`
	Key              string `json:"key"`
	AuthorizationURL string `json:"authorization_url"`
	TokenURL         string `json:"token_url"`
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret,omitempty"`
	Scopes           string `json:"scopes,omitempty"`
	ScopeSeparator   string `json:"scope_separator,omitempty"`
	DisablePKCE      bool   `json:"disable_pkce,omitempty"`
	TokenAuthMethod  string `json:"token_auth_method,omitempty"`
}

func (s *Server) handleOAuthConnect(w http.ResponseWriter, r *http.Request) {
	var req oauthConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}
	if req.Key == "" {
		jsonError(w, http.StatusBadRequest, "\"key\" is required")
		return
	}
	if !broker.CredentialKeyPattern.MatchString(req.Key) {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid credential key %q: must be SCREAMING_SNAKE_CASE (e.g. GITHUB_TOKEN)", req.Key))
		return
	}
	if req.AuthorizationURL == "" {
		jsonError(w, http.StatusBadRequest, "\"authorization_url\" is required for the connect flow")
		return
	}
	if req.TokenURL == "" {
		jsonError(w, http.StatusBadRequest, "\"token_url\" is required")
		return
	}
	if !isValidHTTPURL(req.AuthorizationURL) {
		jsonError(w, http.StatusBadRequest, "\"authorization_url\" must be an https:// or http:// URL")
		return
	}
	if !isValidHTTPURL(req.TokenURL) {
		jsonError(w, http.StatusBadRequest, "\"token_url\" must be an https:// or http:// URL")
		return
	}
	if req.ClientID == "" {
		jsonError(w, http.StatusBadRequest, "\"client_id\" is required")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}
	if !s.assertBuiltinCredentialStore(w, ctx, ns.ID, ns.Name) {
		return
	}

	// Lazily expire old states.
	_, _ = s.store.ExpireCredentialOAuthStates(ctx, time.Now())

	// Handle client_secret: sentinel = keep current, empty = clear, other = set new.
	// Only reuse stored secret when the provider config hasn't changed
	// to prevent exfiltration via a new token_url.
	// The client secret (new or kept) is sealed for the next
	// client_secret_version and written compare-and-set; on a conflict the
	// row is re-read and the secret re-sealed, a bounded number of times.
	scopeSep := req.ScopeSeparator
	if scopeSep == "" {
		scopeSep = " "
	}
	tokenAuthMethod := req.TokenAuthMethod
	if tokenAuthMethod == "" {
		tokenAuthMethod = "client_secret_post"
	}
	err = store.RetryOnVersionConflict(oauthWriteAttempts, func() error {
		existing, _ := s.store.GetCredentialOAuth(ctx, ns.ID, req.Key)
		var csVersion uint64
		if existing != nil {
			csVersion = existing.ClientSecretVersion
		}
		var clientSecret []byte
		if req.ClientSecret == oauthSecretSentinel {
			if existing != nil && existing.TokenURL == req.TokenURL && len(existing.ClientSecretCT) > 0 {
				cs, err := store.OAuthClientSecretAAD(ns.ID, req.Key, csVersion).Open(existing.ClientSecretCT, existing.ClientSecretNonce, s.encKey)
				if err != nil {
					return errOAuthDecryptClientSecret
				}
				clientSecret = cs
			}
		} else if req.ClientSecret != "" {
			clientSecret = []byte(req.ClientSecret)
		}
		row := &store.CredentialOAuth{
			VaultID:          ns.ID,
			CredentialKey:    req.Key,
			AuthorizationURL: req.AuthorizationURL,
			TokenURL:         req.TokenURL,
			ClientID:         req.ClientID,
			Scopes:           req.Scopes,
			ScopeSeparator:   scopeSep,
			DisablePKCE:      req.DisablePKCE,
			TokenAuthMethod:  tokenAuthMethod,
		}
		if clientSecret != nil {
			var err error
			row.ClientSecretVersion = csVersion + 1
			row.ClientSecretCT, row.ClientSecretNonce, err = store.OAuthClientSecretAAD(ns.ID, req.Key, row.ClientSecretVersion).Seal(clientSecret, s.encKey)
			crypto.WipeBytes(clientSecret)
			if err != nil {
				return errOAuthEncrypt
			}
		}
		return s.store.SetCredentialOAuth(ctx, row)
	})
	switch {
	case errors.Is(err, errOAuthDecryptClientSecret):
		jsonError(w, http.StatusInternalServerError, "Failed to decrypt client secret")
		return
	case errors.Is(err, errOAuthEncrypt):
		jsonError(w, http.StatusInternalServerError, "Encryption failed")
		return
	case err != nil:
		jsonError(w, http.StatusInternalServerError, "Failed to save OAuth configuration")
		return
	}

	// Generate PKCE verifier and state.
	codeVerifier, err := oauth.GenerateCodeVerifier()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to generate PKCE verifier")
		return
	}
	codeChallenge := oauth.CodeChallengeS256(codeVerifier)

	stateRaw := oauthPrefixedToken("av_oast_")
	stateHash := hashOAuthState(stateRaw)

	now := time.Now().UTC()
	if err := s.store.CreateCredentialOAuthState(ctx, &store.CredentialOAuthState{
		ID:            oauthPublicID(),
		StateHash:     stateHash,
		CodeVerifier:  codeVerifier,
		VaultID:       ns.ID,
		CredentialKey: req.Key,
		RedirectURL:   "",
		CreatedAt:     now,
		ExpiresAt:     now.Add(oauthStateTTL),
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create OAuth state")
		return
	}

	redirectURI := s.baseURL + "/v1/oauth/callback"
	authURL := oauth.BuildAuthorizationURL(
		req.AuthorizationURL, req.ClientID, redirectURI,
		stateRaw, codeChallenge, req.Scopes, scopeSep, req.DisablePKCE,
	)

	jsonOK(w, map[string]string{"authorization_url": authURL})
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	stateRaw := r.URL.Query().Get("state")

	if code == "" || stateRaw == "" {
		errMsg := r.URL.Query().Get("error_description")
		if errMsg == "" {
			errMsg = r.URL.Query().Get("error")
		}
		if errMsg == "" {
			errMsg = "Missing code or state parameter"
		}
		s.redirectOAuthComplete(w, r, "", "", "error", errMsg)
		return
	}

	ctx := r.Context()
	stateHash := hashOAuthState(stateRaw)

	st, err := s.store.GetCredentialOAuthStateByHash(ctx, stateHash)
	if err != nil {
		s.redirectOAuthComplete(w, r, "", "", "error", "Invalid or expired OAuth state")
		return
	}

	if time.Now().After(st.ExpiresAt) {
		_ = s.store.DeleteCredentialOAuthState(ctx, st.ID)
		s.redirectOAuthComplete(w, r, "", "", "error", "OAuth state expired — please try again")
		return
	}

	_ = s.store.DeleteCredentialOAuthState(ctx, st.ID)

	// Load OAuth config for token exchange.
	oauthCfg, err := s.store.GetCredentialOAuth(ctx, st.VaultID, st.CredentialKey)
	if err != nil {
		s.redirectOAuthComplete(w, r, "", "", "error", "OAuth configuration not found")
		return
	}

	var clientSecret string
	if len(oauthCfg.ClientSecretCT) > 0 {
		cs, err := store.OAuthClientSecretAAD(st.VaultID, st.CredentialKey, oauthCfg.ClientSecretVersion).Open(oauthCfg.ClientSecretCT, oauthCfg.ClientSecretNonce, s.encKey)
		if err != nil {
			s.redirectOAuthComplete(w, r, "", "", "error", "Failed to decrypt client secret")
			return
		}
		clientSecret = string(cs)
	}

	redirectURI := s.baseURL + "/v1/oauth/callback"
	tok, err := oauth.Exchange(ctx, oauth.ExchangeConfig{
		TokenURL:        oauthCfg.TokenURL,
		ClientID:        oauthCfg.ClientID,
		ClientSecret:    clientSecret,
		Code:            code,
		RedirectURI:     redirectURI,
		CodeVerifier:    st.CodeVerifier,
		TokenAuthMethod: oauthCfg.TokenAuthMethod,
	})
	if err != nil {
		// Never put the token endpoint's response in the redirect URL: it
		// lands in browser history and access logs, and providers echo the
		// code and client secret in error bodies.
		s.redirectOAuthComplete(w, r, "", "", "error", "Token exchange failed: "+brokercore.RefreshErrorMessage(err))
		return
	}

	var expiresAt *time.Time
	if !tok.ExpiresAt.IsZero() {
		expiresAt = &tok.ExpiresAt
	}
	err = s.storeOAuthTokens(ctx, st.VaultID, st.CredentialKey, []byte(tok.AccessToken), []byte(tok.RefreshToken), expiresAt)
	if errors.Is(err, errOAuthEncrypt) {
		s.redirectOAuthComplete(w, r, "", "", "error", "Failed to encrypt tokens")
		return
	}
	if err != nil {
		s.redirectOAuthComplete(w, r, "", "", "error", "Failed to store tokens")
		return
	}
	s.scheduleIdentityProbe(st.VaultID, st.CredentialKey)

	// Resolve vault name for the redirect.
	vaultName := ""
	if v, err := s.store.GetVaultByID(ctx, st.VaultID); err == nil && v != nil {
		vaultName = v.Name
	}

	s.redirectOAuthComplete(w, r, vaultName, st.CredentialKey, "success", "")
}

func (s *Server) handleOAuthStatus(w http.ResponseWriter, r *http.Request) {
	vault := r.URL.Query().Get("vault")
	key := r.URL.Query().Get("key")
	if vault == "" {
		vault = store.DefaultVault
	}
	if key == "" {
		jsonError(w, http.StatusBadRequest, "\"key\" query parameter is required")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vault))
		return
	}
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	oauthCfg, err := s.store.GetCredentialOAuth(ctx, ns.ID, key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("OAuth credential %q not found", key))
			return
		}
		jsonError(w, http.StatusInternalServerError, "Failed to read OAuth state")
		return
	}

	type statusResponse struct {
		Connected   bool    `json:"connected"`
		ConnectedAt *string `json:"connected_at,omitempty"`
		LastError   *string `json:"last_error,omitempty"`
	}

	resp := statusResponse{Connected: oauthCfg.ConnectedAt != nil}
	if oauthCfg.ConnectedAt != nil {
		t := oauthCfg.ConnectedAt.Format(time.RFC3339)
		resp.ConnectedAt = &t
	}
	if oauthCfg.LastRefreshError != "" {
		msg := safeRefreshError(oauthCfg.LastRefreshError)
		resp.LastError = &msg
	}

	jsonOK(w, resp)
}

type oauthTokenUploadRequest struct {
	Vault           string `json:"vault"`
	Key             string `json:"key"`
	AccessToken     string `json:"access_token,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	TokenURL        string `json:"token_url,omitempty"`
	ClientID        string `json:"client_id,omitempty"`
	ClientSecret    string `json:"client_secret,omitempty"`
	TokenAuthMethod string `json:"token_auth_method,omitempty"`
}

func (s *Server) handleOAuthTokenUpload(w http.ResponseWriter, r *http.Request) {
	var req oauthTokenUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}
	if req.Key == "" {
		jsonError(w, http.StatusBadRequest, "\"key\" is required")
		return
	}
	if !broker.CredentialKeyPattern.MatchString(req.Key) {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid credential key %q: must be SCREAMING_SNAKE_CASE (e.g. GITHUB_TOKEN)", req.Key))
		return
	}
	if req.AccessToken == "" && req.RefreshToken == "" {
		jsonError(w, http.StatusBadRequest, "\"access_token\" or \"refresh_token\" is required")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}
	if !s.assertBuiltinCredentialStore(w, ctx, ns.ID, ns.Name) {
		return
	}

	// Resolve OAuth config: use request fields, fall back to existing config.
	existing, _ := s.store.GetCredentialOAuth(ctx, ns.ID, req.Key)
	tokenURL := req.TokenURL
	clientID := req.ClientID
	clientSecret := req.ClientSecret
	tokenAuthMethod := req.TokenAuthMethod
	if existing != nil {
		if tokenURL == "" {
			tokenURL = existing.TokenURL
		}
		if clientID == "" {
			clientID = existing.ClientID
		}
		// Only reuse stored secrets when the provider config hasn't changed.
		// If the caller sends a different token_url, don't send stored secrets
		// to the new endpoint (prevents client secret exfiltration).
		providerUnchanged := tokenURL == existing.TokenURL
		if clientSecret == "" && len(existing.ClientSecretCT) > 0 && providerUnchanged {
			cs, err := store.OAuthClientSecretAAD(ns.ID, req.Key, existing.ClientSecretVersion).Open(existing.ClientSecretCT, existing.ClientSecretNonce, s.encKey)
			if err == nil {
				clientSecret = string(cs)
			}
		}
		if tokenAuthMethod == "" {
			tokenAuthMethod = existing.TokenAuthMethod
		}
	}

	// Handle sentinel values for edit mode.
	isAccessSentinel := req.AccessToken == oauthSecretSentinel
	isRefreshSentinel := req.RefreshToken == oauthSecretSentinel
	hasNewRefreshToken := req.RefreshToken != "" && !isRefreshSentinel

	// If a new (non-sentinel) refresh token is provided, validate it by
	// refreshing immediately. This gives confidence the setup works and
	// provides the real expires_at.
	if hasNewRefreshToken && tokenURL != "" && tokenURL != "manual" {
		tok, refreshErr := oauth.Refresh(ctx, oauth.RefreshConfig{
			TokenURL:        tokenURL,
			ClientID:        clientID,
			ClientSecret:    clientSecret,
			RefreshToken:    req.RefreshToken,
			TokenAuthMethod: tokenAuthMethod,
		})
		if refreshErr != nil {
			jsonError(w, http.StatusBadRequest, "Refresh token validation failed: "+brokercore.RefreshErrorMessage(refreshErr))
			return
		}

		// Refresh succeeded — use the fresh tokens. The client secret and the
		// tokens are each sealed for their row's next version and written
		// compare-and-set, re-read and re-sealed on a conflict.
		if tokenURL == "" {
			tokenURL = "manual"
		}
		if clientID == "" {
			clientID = "manual"
		}
		err := store.RetryOnVersionConflict(oauthWriteAttempts, func() error {
			cur, _ := s.store.GetCredentialOAuth(ctx, ns.ID, req.Key)
			oauthRow := &store.CredentialOAuth{
				VaultID:         ns.ID,
				CredentialKey:   req.Key,
				TokenURL:        tokenURL,
				ClientID:        clientID,
				TokenAuthMethod: tokenAuthMethod,
			}
			if existing != nil {
				oauthRow.AuthorizationURL = existing.AuthorizationURL
				oauthRow.Scopes = existing.Scopes
				oauthRow.ScopeSeparator = existing.ScopeSeparator
				oauthRow.DisablePKCE = existing.DisablePKCE
			}
			if clientSecret != "" {
				oauthRow.ClientSecretVersion = 1
				if cur != nil {
					oauthRow.ClientSecretVersion = cur.ClientSecretVersion + 1
				}
				var err error
				oauthRow.ClientSecretCT, oauthRow.ClientSecretNonce, err = store.OAuthClientSecretAAD(ns.ID, req.Key, oauthRow.ClientSecretVersion).Seal([]byte(clientSecret), s.encKey)
				if err != nil {
					return errOAuthEncrypt
				}
			}
			return s.store.SetCredentialOAuth(ctx, oauthRow)
		})
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to save OAuth configuration")
			return
		}

		refreshToken := req.RefreshToken
		if tok.RefreshToken != "" {
			refreshToken = tok.RefreshToken
		}
		var expiresAt *time.Time
		if !tok.ExpiresAt.IsZero() {
			expiresAt = &tok.ExpiresAt
		}
		if err := s.storeOAuthTokens(ctx, ns.ID, req.Key, []byte(tok.AccessToken), []byte(refreshToken), expiresAt); err != nil {
			jsonError(w, http.StatusInternalServerError, "Failed to store tokens")
			return
		}
		s.scheduleIdentityProbe(ns.ID, req.Key)

		now := time.Now().UTC().Format(time.RFC3339)
		jsonOK(w, map[string]interface{}{"connected": true, "connected_at": now})
		return
	}

	// No new refresh token — store access token as-is (edit mode or access-only upload).
	// Kept values are read from the current rows and re-sealed for the next
	// versions on every attempt of the compare-and-set write.
	keptAccess := func(cred *store.Credential) []byte {
		if cred == nil || len(cred.Ciphertext) == 0 {
			return nil
		}
		pt, decErr := store.CredentialValueAAD(ns.ID, req.Key, cred.Version).Open(cred.Ciphertext, cred.Nonce, s.encKey)
		if decErr != nil || len(pt) == 0 {
			return nil
		}
		return pt
	}
	if isAccessSentinel && !hasNewRefreshToken {
		cred, _ := s.store.GetCredential(ctx, ns.ID, req.Key)
		pt := keptAccess(cred)
		if pt == nil {
			jsonError(w, http.StatusBadRequest, "No existing access token to preserve — provide an access_token or refresh_token")
			return
		}
		crypto.WipeBytes(pt)
	}

	// Create credential_oauth row if needed.
	if existing == nil {
		if tokenURL == "" {
			tokenURL = "manual"
		}
		if clientID == "" {
			clientID = "manual"
		}
		_ = s.store.SetCredentialOAuth(ctx, &store.CredentialOAuth{
			VaultID:       ns.ID,
			CredentialKey: req.Key,
			TokenURL:      tokenURL,
			ClientID:      clientID,
		})
	}

	// Preserve existing token_expires_at when not uploading a new refresh token.
	var existingExpiresAt *time.Time
	if existing != nil {
		existingExpiresAt = existing.TokenExpiresAt
	}
	err = s.writeOAuthTokens(ctx, ns.ID, req.Key, existingExpiresAt, func(cred *store.Credential, co *store.CredentialOAuth) ([]byte, []byte, error) {
		var access, refresh []byte
		if isAccessSentinel {
			access = keptAccess(cred)
			if access == nil && !hasNewRefreshToken {
				return nil, nil, errOAuthNoAccessToken
			}
		} else if req.AccessToken != "" {
			access = []byte(req.AccessToken)
		}
		if isRefreshSentinel && co != nil && len(co.RefreshTokenCT) > 0 {
			pt, decErr := store.OAuthRefreshTokenAAD(ns.ID, req.Key, co.Version).Open(co.RefreshTokenCT, co.RefreshTokenNonce, s.encKey)
			if decErr != nil {
				return access, nil, errOAuthDecryptRefreshToken
			}
			refresh = pt
		} else if hasNewRefreshToken {
			refresh = []byte(req.RefreshToken)
		}
		return access, refresh, nil
	})
	switch {
	case errors.Is(err, errOAuthNoAccessToken):
		jsonError(w, http.StatusBadRequest, "No existing access token to preserve — provide an access_token or refresh_token")
		return
	case errors.Is(err, errOAuthDecryptRefreshToken):
		jsonError(w, http.StatusInternalServerError, "Failed to decrypt refresh token")
		return
	case errors.Is(err, errOAuthEncrypt):
		jsonError(w, http.StatusInternalServerError, "Encryption failed")
		return
	case err != nil:
		jsonError(w, http.StatusInternalServerError, "Failed to store tokens")
		return
	}
	s.scheduleIdentityProbe(ns.ID, req.Key)

	now := time.Now().UTC().Format(time.RFC3339)
	jsonOK(w, map[string]interface{}{"connected": true, "connected_at": now})
}

func (s *Server) redirectOAuthComplete(w http.ResponseWriter, r *http.Request, vault, key, status, message string) {
	u := s.baseURL + "/oauth/complete?status=" + url.QueryEscape(status)
	if vault != "" {
		u += "&vault=" + url.QueryEscape(vault)
	}
	if key != "" {
		u += "&key=" + url.QueryEscape(key)
	}
	if message != "" {
		u += "&message=" + url.QueryEscape(message)
	}
	http.Redirect(w, r, u, http.StatusFound)
}

// storeOAuthTokens writes an access token and, when refresh is non-empty, a
// refresh token for vaultID/key (see writeOAuthTokens).
func (s *Server) storeOAuthTokens(ctx context.Context, vaultID, key string, access, refresh []byte, expiresAt *time.Time) error {
	return s.writeOAuthTokens(ctx, vaultID, key, expiresAt, func(*store.Credential, *store.CredentialOAuth) ([]byte, []byte, error) {
		return append([]byte(nil), access...), append([]byte(nil), refresh...), nil
	})
}

// writeOAuthTokens seals the tokens plain returns for the rows' next
// versions and writes them compare-and-set. On a conflict it re-reads both
// rows, calls plain again (so a value kept from the old row is re-read at
// its new version) and re-seals, up to oauthWriteAttempts times. plain gets
// the rows as read (either may be nil) and returns the access token (nil
// stores an empty value) and the refresh token (empty keeps the stored
// one). Both are wiped once sealed.
func (s *Server) writeOAuthTokens(ctx context.Context, vaultID, key string, expiresAt *time.Time,
	plain func(cred *store.Credential, co *store.CredentialOAuth) (access, refresh []byte, err error)) error {
	return store.RetryOnVersionConflict(oauthWriteAttempts, func() error {
		cred, _ := s.store.GetCredential(ctx, vaultID, key)
		co, _ := s.store.GetCredentialOAuth(ctx, vaultID, key)
		access, refresh, err := plain(cred, co)
		defer crypto.WipeBytes(access)
		defer crypto.WipeBytes(refresh)
		if err != nil {
			return err
		}
		u := store.OAuthTokenUpdate{AccessVersion: 1, ExpiresAt: expiresAt}
		if cred != nil {
			u.AccessVersion = cred.Version + 1
		}
		if len(access) > 0 {
			if u.AccessCT, u.AccessNonce, err = store.CredentialValueAAD(vaultID, key, u.AccessVersion).Seal(access, s.encKey); err != nil {
				return errOAuthEncrypt
			}
		}
		if len(refresh) > 0 {
			u.RefreshVersion = 1
			if co != nil {
				u.RefreshVersion = co.Version + 1
			}
			if u.RefreshCT, u.RefreshNonce, err = store.OAuthRefreshTokenAAD(vaultID, key, u.RefreshVersion).Seal(refresh, s.encKey); err != nil {
				return errOAuthEncrypt
			}
		}
		return s.store.UpdateCredentialOAuthTokens(ctx, vaultID, key, u)
	})
}

// credentialVersion returns the current credentials.version of a row, or 0
// when the row does not exist yet.
func (s *Server) credentialVersion(ctx context.Context, vaultID, key string) uint64 {
	c, err := s.store.GetCredential(ctx, vaultID, key)
	if err != nil || c == nil {
		return 0
	}
	return c.Version
}

// safeRefreshError returns a stored last_refresh_error only when it has the
// sanitized shape written by brokercore.RefreshErrorMessage; rows written
// before sanitization may hold a raw token-endpoint body and are replaced
// by a fixed message.
func safeRefreshError(msg string) string {
	if safeRefreshErrorRe.MatchString(msg) {
		return msg
	}
	return "oauth: token request failed"
}

var safeRefreshErrorRe = regexp.MustCompile(`^oauth: token (endpoint returned [0-9]{3}( \([a-z_]+\))?|request failed)$`)


func isValidHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

func hashOAuthState(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func oauthPrefixedToken(prefix string) string {
	var b [32]byte
	if _, err := io.ReadFull(cryptorand.Reader, b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return prefix + hex.EncodeToString(b[:])
}

func oauthPublicID() string {
	var b [10]byte
	if _, err := io.ReadFull(cryptorand.Reader, b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
