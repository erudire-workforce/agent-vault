//go:build kmsaad

package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Runs today (the identity package does not exist yet): pins the golden
// vector published in FAILURE_MODES_KMS_AAD.md against the formula, so the
// relying side and internal/identity both have a checked reference.
func TestKMSAAD_IdentityGoldenVectorIsCorrect(t *testing.T) {
	in := "notion\x00ws-00000000-test\x00Example Workspace\x00example-integration"
	sum := sha256.Sum256([]byte(in))
	if got := hex.EncodeToString(sum[:]); got != "2ef5eef3617ec9f7d8894b36a385469ea039caaf97e100179cb1e70c091edfe1" {
		t.Fatalf("golden vector mismatch: %s", got)
	}
}
