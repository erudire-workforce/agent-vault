// Blocker 3: the compiled-in Notion allowlist is exactly three method+path
// pairs.
//
// This supersedes TestCheckServiceAllowlist's "ok" list, which still
// accepts /v1/pages/*, POST /v1/search and POST .../query; the implementer
// updates that test as part of the same change.
package servicepolicy

import (
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
)

func TestReviewFix_NotionAllowlistIsExactlyThreePairs(t *testing.T) {
	allowed := []broker.Service{
		notion("/v1/pages/{id}", "GET"),
		notion("/v1/pages/{page_id}", "GET"),
		notion("/v1/blocks/{id}/children", "GET"),
		notion("/v1/blocks/{block_id}/children", "GET"),
		notion("/v1/users/me", "GET"),
	}
	for _, s := range allowed {
		if err := CheckServicesStrict([]broker.Service{s}); err != nil {
			t.Errorf("GET %s refused: %v", s.Path, err)
		}
	}

	refused := map[string]broker.Service{
		"POST search":                notion("/v1/search", "POST"),
		"POST database query":        notion("/v1/databases/{id}/query", "POST"),
		"POST data source query":     notion("/v1/data_sources/{id}/query", "POST"),
		"GET users list":             notion("/v1/users", "GET"),
		"GET user by id":             notion("/v1/users/{id}", "GET"),
		"GET users prefix":           notion("/v1/users/*", "GET"),
		"GET database":               notion("/v1/databases/{id}", "GET"),
		"GET databases prefix":       notion("/v1/databases/*", "GET"),
		"GET data source":            notion("/v1/data_sources/{id}", "GET"),
		"GET comments":               notion("/v1/comments", "GET"),
		"GET pages greedy":           notion("/v1/pages/*", "GET"),
		"GET page property":          notion("/v1/pages/{id}/properties/{pid}", "GET"),
		"GET block":                  notion("/v1/blocks/{id}", "GET"),
		"GET blocks greedy":          notion("/v1/blocks/*", "GET"),
		"GET block children greedy":  notion("/v1/blocks/*/children", "GET"),
		"GET children of a sub-path": notion("/v1/blocks/{id}/children/{x}", "GET"),
		"HEAD on an allowed path":    notion("/v1/pages/{id}", "HEAD"),
		"GET plus POST":              notion("/v1/pages/{id}", "GET", "POST"),
		"literal page id":            notion("/v1/pages/abc", "GET"),
	}
	for name, s := range refused {
		if err := CheckServicesStrict([]broker.Service{s}); err == nil {
			t.Errorf("%s (%v %s) accepted; only GET /v1/pages/{id}, GET /v1/blocks/{id}/children and GET /v1/users/me are allowed", name, s.Methods, s.Path)
		}
	}
}
