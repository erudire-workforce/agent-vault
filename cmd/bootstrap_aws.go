package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/Infisical/agent-vault/internal/bootstrap"
	"github.com/Infisical/agent-vault/internal/bootstrap/awssinks"
	"github.com/Infisical/agent-vault/internal/store"
)

// mitmRootPEM is set by attachMITMIfEnabled to the CA's public
// certificate accessor; nil when the proxy is disabled.
var mitmRootPEM func() []byte

// Declarative bootstrap environment. Setting the document secret turns
// the feature on; the token secret and executor are then required.
const (
	envBootstrapDocSecret      = "AGENT_VAULT_BOOTSTRAP_SECRET_ID"
	envBootstrapTokenSecret    = "AGENT_VAULT_BOOTSTRAP_TOKEN_SECRET_ID"
	envBootstrapExecutor       = "AGENT_VAULT_BOOTSTRAP_EXECUTOR"
	envBootstrapCAParameter    = "AGENT_VAULT_BOOTSTRAP_CA_PARAMETER"
	envBootstrapRotationPeriod = "AGENT_VAULT_BOOTSTRAP_ROTATION_CHECK"
)

// startDeclarativeBootstrapIfConfigured applies the bootstrap document
// from AWS Secrets Manager, delivers the executor token, publishes the
// MITM CA certificate to SSM and starts the timer-driven rotation loop.
// A configured bootstrap that fails stops startup (fail closed).
func startDeclarativeBootstrapIfConfigured(db store.Store, logger *slog.Logger) error {
	docSecret := strings.TrimSpace(os.Getenv(envBootstrapDocSecret))
	if docSecret == "" {
		return nil
	}
	tokenSecret := strings.TrimSpace(os.Getenv(envBootstrapTokenSecret))
	executor := strings.TrimSpace(os.Getenv(envBootstrapExecutor))
	if tokenSecret == "" || executor == "" {
		return fmt.Errorf("%s is set, so %s and %s are required", envBootstrapDocSecret, envBootstrapTokenSecret, envBootstrapExecutor)
	}
	period := bootstrap.RotationTickInterval
	if v := os.Getenv(envBootstrapRotationPeriod); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute || d > 24*time.Hour {
			return fmt.Errorf("%s must be a duration between 1m and 24h", envBootstrapRotationPeriod)
		}
		period = d
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap: loading AWS configuration: %w", err)
	}
	sm := secretsmanager.NewFromConfig(awsCfg)
	opts := bootstrap.Options{
		Store:    db,
		Source:   awssinks.DocumentSource{Client: sm, SecretID: docSecret},
		Tokens:   awssinks.TokenSink{Client: sm, SecretID: tokenSecret},
		Executor: executor,
		Logger:   logger,
	}
	if param := strings.TrimSpace(os.Getenv(envBootstrapCAParameter)); param != "" {
		if mitmRootPEM == nil {
			return errors.New("bootstrap: CA publication requested but the MITM proxy (and its CA) is disabled")
		}
		opts.Certs = awssinks.CertSink{Client: ssm.NewFromConfig(awsCfg), Name: param}
		opts.RootPEM = mitmRootPEM
	}
	if err := bootstrap.Apply(ctx, opts); err != nil {
		return err
	}
	logger.Info("declarative bootstrap applied", slog.String("executor", executor))

	ticker := time.NewTicker(period)
	go func() {
		defer ticker.Stop()
		bootstrap.RunRotationLoop(context.Background(), opts, ticker.C)
	}()
	return nil
}
