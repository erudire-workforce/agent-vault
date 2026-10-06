// Package kmswrap wraps the master DEK with an AWS KMS key. It implements
// auth.KeyWrapper on top of the KMS Encrypt and Decrypt operations.
//
// The client is built from the standard AWS configuration chain (env, shared
// config, web identity, container or instance role) and honours the
// service-specific endpoint override AWS_ENDPOINT_URL_KMS (used for VPC
// endpoints and by the tests' in-memory fake).
package kmswrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// Environment variables that configure KMS mode.
const (
	EnvKeyID      = "AGENT_VAULT_KMS_KEY_ID"
	EnvContextEnv = "AGENT_VAULT_KMS_ENCRYPTION_CONTEXT_ENV"
	EnvRequire    = "AGENT_VAULT_REQUIRE_KMS"
)

// callTimeout bounds every KMS request so an unreachable endpoint fails the
// startup instead of hanging it.
const callTimeout = 30 * time.Second

// Settings is the KMS configuration read from the environment.
type Settings struct {
	KeyID string            // key id, ARN, alias name or alias ARN ("" = KMS off)
	Ctx   map[string]string // KMS encryption context bound to the wrapped DEK
	// Required refuses any master key record that is not KMS-wrapped and any
	// setup path other than KMS (AGENT_VAULT_REQUIRE_KMS=1).
	Required bool
}

// Enabled reports whether a KMS key is configured.
func (s Settings) Enabled() bool { return s.KeyID != "" }

// SettingsFromEnv reads and validates the KMS environment. A required KMS
// without a key id, or a key id without an encryption-context environment
// name, is a configuration error.
func SettingsFromEnv() (Settings, error) {
	s := Settings{
		KeyID:    strings.TrimSpace(os.Getenv(EnvKeyID)),
		Required: truthy(os.Getenv(EnvRequire)),
	}
	if s.Required && s.KeyID == "" {
		return s, fmt.Errorf("%s is set but %s is empty", EnvRequire, EnvKeyID)
	}
	if s.KeyID == "" {
		return s, nil
	}
	env := strings.TrimSpace(os.Getenv(EnvContextEnv))
	if env == "" {
		return s, fmt.Errorf("%s is set but %s is empty; the wrapped DEK must be bound to a deployment environment", EnvKeyID, EnvContextEnv)
	}
	s.Ctx = EncryptionContext(env)
	return s, nil
}

// EncryptionContext is the KMS encryption context bound to the wrapped DEK:
// exactly {"service":"agent-vault","environment":env}. Every Encrypt,
// Decrypt and GenerateDataKey call carries it unchanged.
func EncryptionContext(env string) map[string]string {
	return map[string]string{"service": "agent-vault", "environment": env}
}

func truthy(v string) bool {
	v = strings.TrimSpace(v)
	return v == "1" || strings.EqualFold(v, "true")
}

// AWS wraps and unwraps the DEK with one configured KMS key.
type AWS struct {
	client *kms.Client
	keyID  string
}

// NewAWS builds a wrapper for keyID from the default AWS configuration.
func NewAWS(ctx context.Context, keyID string) (*AWS, error) {
	if keyID == "" {
		return nil, errors.New("kms: empty key id")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms: loading AWS configuration: %w", err)
	}
	return &AWS{client: kms.NewFromConfig(cfg), keyID: keyID}, nil
}

// Wrap encrypts dek under the configured key with encCtx and returns the
// ciphertext blob and the ARN of the key that KMS used.
func (a *AWS) Wrap(ctx context.Context, dek []byte, encCtx map[string]string) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	out, err := a.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:             aws.String(a.keyID),
		Plaintext:         dek,
		EncryptionContext: encCtx,
	})
	if err != nil {
		return nil, "", fmt.Errorf("kms: encrypt: %w", err)
	}
	if len(out.CiphertextBlob) == 0 || aws.ToString(out.KeyId) == "" {
		return nil, "", errors.New("kms: encrypt returned an empty result")
	}
	return out.CiphertextBlob, aws.ToString(out.KeyId), nil
}

// Unwrap decrypts wrapped with the configured key and encCtx. KMS refuses a
// different key (IncorrectKeyException) or context; the key KMS reports must
// also equal keyID, the key recorded when the DEK was wrapped.
func (a *AWS) Unwrap(ctx context.Context, wrapped []byte, keyID string, encCtx map[string]string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	out, err := a.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob:    wrapped,
		KeyId:             aws.String(a.keyID),
		EncryptionContext: encCtx,
	})
	if err != nil {
		return nil, fmt.Errorf("kms: decrypt: %w", err)
	}
	if got := aws.ToString(out.KeyId); got == "" || got != keyID {
		for i := range out.Plaintext {
			out.Plaintext[i] = 0
		}
		return nil, fmt.Errorf("kms: DEK was unwrapped by key %q but the record names %q", got, keyID)
	}
	return out.Plaintext, nil
}
