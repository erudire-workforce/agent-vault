package store

import (
	"strconv"

	"github.com/Infisical/agent-vault/internal/crypto"
)

// AAD builders for every DEK-encrypted column. The values here are part of
// the stored-data contract (see crypto.AAD and
// internal/crypto/FAILURE_MODES_KMS_AAD.md): changing one needs a migration.

// CredentialValueAAD binds credentials.ciphertext (static value or OAuth
// access token).
func CredentialValueAAD(vaultID, key string, version uint64) crypto.AAD {
	return crypto.AAD{Table: "credentials", Field: "value", VaultID: vaultID, Key: key, Version: version}
}

// OAuthRefreshTokenAAD binds credential_oauth.refresh_token_ct.
func OAuthRefreshTokenAAD(vaultID, key string, version uint64) crypto.AAD {
	return crypto.AAD{Table: "credential_oauth", Field: "refresh_token", VaultID: vaultID, Key: key, Version: version}
}

// OAuthClientSecretAAD binds credential_oauth.client_secret_ct.
func OAuthClientSecretAAD(vaultID, key string, version uint64) crypto.AAD {
	return crypto.AAD{Table: "credential_oauth", Field: "client_secret", VaultID: vaultID, Key: key, Version: version}
}

// ProposalCredentialAAD binds proposal_credentials.ciphertext.
func ProposalCredentialAAD(vaultID string, proposalID int, key string, version uint64) crypto.AAD {
	return crypto.AAD{Table: "proposal_credentials", Field: "value", VaultID: vaultID, Key: strconv.Itoa(proposalID) + ":" + key, Version: version}
}
