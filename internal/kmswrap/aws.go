// Package kmswrap wraps the master DEK with an AWS KMS key. It implements
// auth.KeyWrapper with KMS GenerateDataKey, Decrypt and DescribeKey (never Encrypt).
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
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
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

// CheckKeyEnabled calls DescribeKey and returns an error unless the
// configured key's state is Enabled. Any DescribeKey failure is an error
// too: startup never proceeds on a key whose state it could not read.
func (a *AWS) CheckKeyEnabled(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	out, err := a.client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(a.keyID)})
	if err != nil {
		return fmt.Errorf("kms: describe key %q: %w", a.keyID, err)
	}
	if out.KeyMetadata == nil {
		return fmt.Errorf("kms: describe key %q returned no metadata", a.keyID)
	}
	if state := out.KeyMetadata.KeyState; state != types.KeyStateEnabled {
		return fmt.Errorf("kms: key %q is in state %s, not Enabled; refusing to use it", a.keyID, state)
	}
	return nil
}

// GenerateDataKey asks KMS for a fresh 256-bit DEK under the configured key
// and encCtx. It returns the plaintext DEK (for use in memory only), the
// CiphertextBlob to store, and the ARN of the key KMS used. This is the only
// way the DEK is wrapped: the key policy needs kms:GenerateDataKey,
// kms:Decrypt and kms:DescribeKey, never kms:Encrypt.
func (a *AWS) GenerateDataKey(ctx context.Context, encCtx map[string]string) ([]byte, []byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	out, err := a.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:             aws.String(a.keyID),
		KeySpec:           types.DataKeySpecAes256,
		EncryptionContext: encCtx,
	})
	if err != nil {
		return nil, nil, "", fmt.Errorf("kms: generate data key: %w", err)
	}
	if len(out.Plaintext) == 0 || len(out.CiphertextBlob) == 0 || aws.ToString(out.KeyId) == "" {
		for i := range out.Plaintext {
			out.Plaintext[i] = 0
		}
		return nil, nil, "", errors.New("kms: generate data key returned an empty result")
	}
	return out.Plaintext, out.CiphertextBlob, aws.ToString(out.KeyId), nil
}

// Wrap is never used with AWS KMS: wrapping a caller-made DEK would need
// kms:Encrypt, which the key policy does not grant. auth.SetupWithKMS takes
// the DEK from GenerateDataKey instead. Wrap refuses without calling KMS.
func (a *AWS) Wrap(context.Context, []byte, map[string]string) ([]byte, string, error) {
	return nil, "", errors.New("kms: wrapping a caller-supplied DEK is not supported; the DEK comes from GenerateDataKey")
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
