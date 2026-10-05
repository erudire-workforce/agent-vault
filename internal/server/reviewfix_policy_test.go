//go:build reviewfix

// Blocker 3 at every API service write path: with the policy mode active,
// any Notion service outside GET /v1/pages/{id}, GET /v1/blocks/{id}/children
// and GET /v1/users/me is refused by the services API and by proposal
// approval. Run with: go test -tags reviewfix ./internal/server/
package server

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/Infisical/agent-vault/internal/servicepolicy"
)

var reviewOutsideAllowlist = map[string]string{
	"POST search":            `{"name":"notion-rf","host":"api.notion.com","path":"/v1/search","methods":["POST"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}`,
	"POST database query":    `{"name":"notion-rf","host":"api.notion.com","path":"/v1/databases/{id}/query","methods":["POST"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}`,
	"POST data source query": `{"name":"notion-rf","host":"api.notion.com","path":"/v1/data_sources/{id}/query","methods":["POST"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}`,
	"GET users list":         `{"name":"notion-rf","host":"api.notion.com","path":"/v1/users","methods":["GET"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}`,
	"GET database":           `{"name":"notion-rf","host":"api.notion.com","path":"/v1/databases/{id}","methods":["GET"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}`,
	"GET data source":        `{"name":"notion-rf","host":"api.notion.com","path":"/v1/data_sources/{id}","methods":["GET"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}`,
	"GET comments":           `{"name":"notion-rf","host":"api.notion.com","path":"/v1/comments","methods":["GET"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}`,
	"GET pages greedy":       `{"name":"notion-rf","host":"api.notion.com","path":"/v1/pages/*","methods":["GET"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}`,
}

const reviewAllowed = `{"name":"notion-rf","host":"api.notion.com","path":"/v1/pages/{id}","methods":["GET"],"auth":{"type":"bearer","token":"NOTION_TOKEN"}}`

func TestReviewFix_PolicyRefusesOutsideAllowlist_ServicesAPI(t *testing.T) {
	t.Setenv(servicepolicy.EnvMode, servicepolicy.ModeReadonlyAllowlist)
	e := newKEnv(t, newSQLiteTestDB(t))
	if rec := e.do(http.MethodPost, "/v1/vaults/default/services", `{"services":[`+reviewAllowed+`]}`, e.ownerToken); rec.Code/100 != 2 {
		t.Fatalf("control: allowed service refused: %d %s", rec.Code, rec.Body.String())
	}
	for name, svc := range reviewOutsideAllowlist {
		for _, m := range []string{http.MethodPost, http.MethodPut} {
			rec := e.do(m, "/v1/vaults/default/services", `{"services":[`+svc+`]}`, e.ownerToken)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s via %s /v1/vaults/default/services = %d, want 403", name, m, rec.Code)
			}
		}
	}
}

func TestReviewFix_PolicyRefusesOutsideAllowlist_ProposalApproval(t *testing.T) {
	t.Setenv(servicepolicy.EnvMode, servicepolicy.ModeReadonlyAllowlist)
	for name, svc := range reviewOutsideAllowlist {
		t.Run(name, func(t *testing.T) {
			e := newKEnv(t, newSQLiteTestDB(t))
			sess, err := e.st.CreateScopedSession(context.Background(), scopedParams(e.vaultID))
			if err != nil {
				t.Fatal(err)
			}
			body := `{"services":[` + svc[:1] + `"action":"set",` + svc[1:] + `],"credentials":[{"action":"set","key":"NOTION_TOKEN"}],"message":"m"}`
			rec := e.do(http.MethodPost, "/v1/proposals", body, sess.ID)
			if rec.Code == http.StatusForbidden {
				return // refused at proposal creation: acceptable
			}
			if rec.Code != http.StatusCreated {
				t.Fatalf("create proposal: %d %s", rec.Code, rec.Body.String())
			}
			rec = e.do(http.MethodPost, fmt.Sprintf("/v1/admin/proposals/%d/approve", 1),
				`{"vault":"default","credentials":{"NOTION_TOKEN":"SENTINEL-RF-0301"}}`, e.ownerToken)
			if rec.Code != http.StatusForbidden {
				t.Errorf("approval of %s = %d, want 403", name, rec.Code)
			}
		})
	}
}
