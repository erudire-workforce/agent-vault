//go:build reviewfix

// Blocker 3 at the bootstrap write path. Run with:
// go test -tags reviewfix ./internal/bootstrap/
//
// Note: docJSON in bootstrap_kmsaad_test.go uses /v1/pages/* which the
// exact allowlist refuses; the implementer moves that fixture to
// /v1/pages/{id} in the same change.
package bootstrap

import (
	"context"
	"strings"
	"testing"
)

func TestReviewFix_Bootstrap_RefusesOutsideExactAllowlist(t *testing.T) {
	svc := `{"vault":"example-integration","name":"notion-read","host":"api.notion.com","path":"PATH","methods":["METHOD"],
     "auth_type":"bearer","credential_key":"NOTION_TOKEN","strict_deny":true}`
	doc := func(method, path string) string {
		s := strings.NewReplacer("PATH", path, "METHOD", method).Replace(svc)
		return `{"vaults":["example-integration"],"services":[` + s + `],
  "agents":[{"name":"example-executor","instance_role":"no-access","vault_roles":{"example-integration":"proxy"},"expires_in":"720h"}]}`
	}
	// Control: an allowed pair applies.
	fx := newFixture(t, newSQLiteTestDB(t).Open(t), doc("GET", "/v1/pages/{id}"))
	if err := Apply(context.Background(), fx.opts); err != nil {
		t.Fatalf("control: GET /v1/pages/{id} refused: %v", err)
	}
	for _, c := range [][2]string{
		{"POST", "/v1/search"},
		{"POST", "/v1/databases/{id}/query"},
		{"POST", "/v1/data_sources/{id}/query"},
		{"GET", "/v1/users"},
		{"GET", "/v1/databases/{id}"},
		{"GET", "/v1/data_sources/{id}"},
		{"GET", "/v1/comments"},
		{"GET", "/v1/pages/*"},
	} {
		fx := newFixture(t, newSQLiteTestDB(t).Open(t), doc(c[0], c[1]))
		if err := Apply(context.Background(), fx.opts); err == nil {
			t.Errorf("bootstrap applied %s %s; only the three allowlisted pairs may be written", c[0], c[1])
		}
	}
}
