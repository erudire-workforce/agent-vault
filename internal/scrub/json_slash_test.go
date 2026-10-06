package scrub

import (
	"strings"
	"testing"
)

// JSON encoders that escape '/' as "\/" must not hide an echo. A secret
// without '/' gains no extra pattern.
func TestJSONSlashEscapedEcho(t *testing.T) {
	secret := "tok/en/with/slashes-0001"
	sc := New(secret)
	in := `{"error":"bad token ` + strings.ReplaceAll(secret, "/", `\/`) + `"}`
	if got := sc.String(in); strings.Contains(got, "slashes-0001") {
		t.Fatalf(`"\/"-escaped echo survived scrubbing: %s`, got)
	}
	if n, m := len(New("no-slash-secret-0001").patterns), len(New("no-slash-secret-0002").patterns); n != m {
		t.Fatalf("pattern counts differ for slash-free secrets: %d vs %d", n, m)
	}
}
