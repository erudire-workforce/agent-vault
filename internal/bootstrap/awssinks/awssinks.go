// Package awssinks implements the bootstrap source and sinks on AWS:
// the document is read from Secrets Manager, the executor token is
// written to (and read back from) Secrets Manager with PutSecretValue,
// and the MITM CA certificate is published to SSM Parameter Store.
//
// Only the certificate is ever published; the CA private key never
// leaves the vault. The token secret holds {"token","expires_at"} JSON.
package awssinks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// SecretsAPI is the Secrets Manager surface used here.
type SecretsAPI interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	PutSecretValue(ctx context.Context, in *secretsmanager.PutSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
}

// SSMAPI is the Parameter Store surface used here.
type SSMAPI interface {
	PutParameter(ctx context.Context, in *ssm.PutParameterInput, opts ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

// DocumentSource reads the bootstrap document from one secret.
type DocumentSource struct {
	Client   SecretsAPI
	SecretID string
}

// BootstrapDocument implements bootstrap.SecretsSource.
func (s DocumentSource) BootstrapDocument(ctx context.Context) ([]byte, error) {
	out, err := s.Client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(s.SecretID)})
	if err != nil {
		return nil, fmt.Errorf("reading bootstrap document secret: %w", err)
	}
	if out.SecretString != nil {
		return []byte(*out.SecretString), nil
	}
	if out.SecretBinary != nil {
		return out.SecretBinary, nil
	}
	return nil, errors.New("bootstrap document secret is empty")
}

// TokenSink stores the executor token in one secret. The secret must
// already exist (created by infrastructure code with its resource policy
// and KMS key); PutSecretValue only adds a version.
type TokenSink struct {
	Client   SecretsAPI
	SecretID string
}

type tokenSecret struct {
	Agent     string `json:"agent"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

// PutToken implements bootstrap.TokenSink.
func (s TokenSink) PutToken(ctx context.Context, agent, token string, expiresAt time.Time) error {
	b, err := json.Marshal(tokenSecret{Agent: agent, Token: token, ExpiresAt: expiresAt.UTC().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	// The ClientRequestToken is the new session's stored ID (sha256 hex of
	// the raw token, as sessions.id): a retry of the same write is
	// idempotent and two mints never share one. The raw token is never a
	// request parameter, because CloudTrail logs those.
	sum := sha256.Sum256([]byte(token))
	if _, err := s.Client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:           aws.String(s.SecretID),
		SecretString:       aws.String(string(b)),
		ClientRequestToken: aws.String(hex.EncodeToString(sum[:])),
	}); err != nil {
		// The SDK error never carries the request payload.
		return fmt.Errorf("writing token secret: %w", err)
	}
	return nil
}

// GetToken implements bootstrap.TokenSink.
func (s TokenSink) GetToken(ctx context.Context, agent string) (string, time.Time, error) {
	out, err := s.Client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(s.SecretID)})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("reading token secret: %w", err)
	}
	if out.SecretString == nil {
		return "", time.Time{}, errors.New("token secret has no string value")
	}
	var ts tokenSecret
	if err := json.Unmarshal([]byte(*out.SecretString), &ts); err != nil {
		return "", time.Time{}, errors.New("token secret is not valid JSON")
	}
	if ts.Agent != agent || ts.Token == "" {
		return "", time.Time{}, errors.New("token secret belongs to another agent or is empty")
	}
	exp, err := time.Parse(time.RFC3339, ts.ExpiresAt)
	if err != nil {
		return "", time.Time{}, errors.New("token secret has no valid expires_at")
	}
	return ts.Token, exp, nil
}

// CertSink publishes the CA certificate as a String parameter.
type CertSink struct {
	Client SSMAPI
	Name   string
}

// PutCACert implements bootstrap.CertSink.
func (s CertSink) PutCACert(ctx context.Context, certPEM []byte) error {
	if _, err := s.Client.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(s.Name),
		Value:     aws.String(string(certPEM)),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
		Tier:      ssmtypes.ParameterTierStandard,
	}); err != nil {
		return fmt.Errorf("publishing CA certificate: %w", err)
	}
	return nil
}
