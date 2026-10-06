// Package identity computes the canonical credential identity digest that
// the proxy publishes in X-Agent-Vault-Credential-Identity. A relying
// service recomputes the same digest from its own view of the account and
// compares, so the encoding is fixed byte for byte:
//
//	sha256(provider 0x00 field1 0x00 field2 0x00 ...), lowercase hex
//
// The digest identifies the account a credential acts as. It is derived
// from the provider's own identity endpoint, never from the credential
// value, so it carries no secret.
package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// NotionHost is the API host whose credentials get an identity probe.
const NotionHost = "api.notion.com"

// NotionProbePath is the identity endpoint probed with the injected
// credential: it returns the bot user the token belongs to.
const NotionProbePath = "/v1/users/me"

// NotionVersion is sent with the probe; the users/me shape used here is
// stable across Notion API versions.
const NotionVersion = "2022-06-28"

// ErrIncomplete means the provider response lacked a field the digest
// needs. Callers must not record a digest in that case.
var ErrIncomplete = errors.New("identity: provider response is missing a required field")

// Digest returns lowercase hex sha256 over provider and fields joined by
// 0x00. Every component must be non-empty and free of 0x00.
func Digest(provider string, fields ...string) (string, error) {
	parts := append([]string{provider}, fields...)
	for i, p := range parts {
		if p == "" {
			return "", fmt.Errorf("%w: component %d is empty", ErrIncomplete, i)
		}
		if strings.IndexByte(p, 0) >= 0 {
			return "", fmt.Errorf("identity: component %d contains a 0x00 separator", i)
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:]), nil
}

// NotionAccount is the account a Notion token acts as, read from GET
// /v1/users/me, with its identity digest. None of it is secret.
type NotionAccount struct {
	WorkspaceID     string
	WorkspaceName   string
	IntegrationName string // the bot user's name
	Digest          string
}

// ParseNotion parses a Notion GET /v1/users/me response into the account and
// its digest, sha256("notion" 0x00 bot.workspace_id 0x00 bot.workspace_name
// 0x00 name). It refuses (returns an error) when any of the three fields is
// missing, null, empty or contains 0x00, or when the body is not a bot user
// object.
func ParseNotion(usersMe []byte) (NotionAccount, error) {
	var u struct {
		Name *string `json:"name"`
		Bot  *struct {
			WorkspaceID   *string `json:"workspace_id"`
			WorkspaceName *string `json:"workspace_name"`
		} `json:"bot"`
	}
	if err := json.Unmarshal(usersMe, &u); err != nil {
		return NotionAccount{}, fmt.Errorf("identity: notion users/me is not JSON: %w", err)
	}
	if u.Bot == nil || u.Name == nil || u.Bot.WorkspaceID == nil || u.Bot.WorkspaceName == nil {
		return NotionAccount{}, ErrIncomplete
	}
	a := NotionAccount{WorkspaceID: *u.Bot.WorkspaceID, WorkspaceName: *u.Bot.WorkspaceName, IntegrationName: *u.Name}
	d, err := Digest("notion", a.WorkspaceID, a.WorkspaceName, a.IntegrationName)
	if err != nil {
		return NotionAccount{}, err
	}
	a.Digest = d
	return a, nil
}

// NotionDigest returns ParseNotion's digest.
func NotionDigest(usersMe []byte) (string, error) {
	a, err := ParseNotion(usersMe)
	if err != nil {
		return "", err
	}
	return a.Digest, nil
}
