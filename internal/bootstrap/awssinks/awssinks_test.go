package awssinks

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

type fakeSecrets struct {
	values map[string]string
	puts   int
}

func (f *fakeSecrets) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	v, ok := f.values[*in.SecretId]
	if !ok {
		return nil, errors.New("ResourceNotFoundException")
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(v)}, nil
}

func (f *fakeSecrets) PutSecretValue(_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	f.values[*in.SecretId] = *in.SecretString
	f.puts++
	return &secretsmanager.PutSecretValueOutput{}, nil
}

type fakeSSM struct{ params map[string]string }

func (f *fakeSSM) PutParameter(_ context.Context, in *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	if in.Overwrite == nil || !*in.Overwrite {
		return nil, errors.New("overwrite required")
	}
	f.params[*in.Name] = *in.Value
	return &ssm.PutParameterOutput{}, nil
}

func TestTokenSinkRoundTrip(t *testing.T) {
	ctx := context.Background()
	fs := &fakeSecrets{values: map[string]string{"doc": `{"vaults":[]}`}}
	sink := TokenSink{Client: fs, SecretID: "tok"}
	if _, _, err := sink.GetToken(ctx, "exec"); err == nil {
		t.Fatal("missing secret must be an error (triggers a re-mint)")
	}
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := sink.PutToken(ctx, "exec", "av_agt_x", exp); err != nil {
		t.Fatal(err)
	}
	tok, got, err := sink.GetToken(ctx, "exec")
	if err != nil || tok != "av_agt_x" || !got.Equal(exp) {
		t.Fatalf("round trip = %q %v %v", tok, got, err)
	}
	if _, _, err := sink.GetToken(ctx, "other"); err == nil {
		t.Fatal("token of another agent accepted")
	}
	fs.values["tok"] = "not json"
	if _, _, err := sink.GetToken(ctx, "exec"); err == nil {
		t.Fatal("unreadable secret accepted")
	}
	doc, err := DocumentSource{Client: fs, SecretID: "doc"}.BootstrapDocument(ctx)
	if err != nil || string(doc) != `{"vaults":[]}` {
		t.Fatalf("document = %q %v", doc, err)
	}
}

func TestCertSink(t *testing.T) {
	fp := &fakeSSM{params: map[string]string{}}
	if err := (CertSink{Client: fp, Name: "/av/ca"}).PutCACert(context.Background(), []byte("-----BEGIN CERTIFICATE-----\n")); err != nil {
		t.Fatal(err)
	}
	if fp.params["/av/ca"] == "" {
		t.Fatal("certificate not written")
	}
}
