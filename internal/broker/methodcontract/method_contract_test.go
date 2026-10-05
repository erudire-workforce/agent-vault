// Package methodcontract_test pins the per-method service rule API.
//
// Intended API:
//
//	Service.Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`
//	    nil  -> any method (upstream behaviour)
//	    set  -> only these methods (case-insensitive); an empty non-nil list denies all
//	func MatchService(method, host string, targetPort int, path string, services []Service) (*Service, MatchScore)
//	func ValidateMethods(methods []string) error // rejects unknown verbs
//
// The proxy (internal/mitm) must turn "host+path matched but method denied"
// into a 403, never into the unmatched-host passthrough; that end-to-end
// behaviour is in internal/mitm/kmsaad_proxy_rules_test.go.
package methodcontract_test

import (
	"encoding/json"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
)

func notion(methods []string) []broker.Service {
	return []broker.Service{{
		Name: "notion-read", Host: "api.notion.com", Path: "/v1/pages/*", Methods: methods,
		Auth: broker.Auth{Type: "bearer", Token: "NOTION_TOKEN"},
	}}
}

func TestKMSAAD_MatchService_MethodAllowlist(t *testing.T) {
	svcs := notion([]string{"GET"})
	if s, _ := broker.MatchService("GET", "api.notion.com", 0, "/v1/pages/abc", svcs); s == nil {
		t.Fatal("GET /v1/pages/{id} must match a GET-only service")
	}
	if s, _ := broker.MatchService("get", "api.notion.com", 0, "/v1/pages/abc", svcs); s == nil {
		t.Fatal("method comparison must be case-insensitive")
	}
	for _, m := range []string{"PATCH", "POST", "PUT", "DELETE"} {
		if s, _ := broker.MatchService(m, "api.notion.com", 0, "/v1/pages/abc", svcs); s != nil {
			t.Errorf("%s /v1/pages/{id} matched a GET-only service", m)
		}
	}
}

func TestKMSAAD_MatchService_NilMethodsKeepsUpstreamBehaviour(t *testing.T) {
	if s, _ := broker.MatchService("PATCH", "api.notion.com", 0, "/v1/pages/abc", notion(nil)); s == nil {
		t.Fatal("a service without methods must keep matching every method")
	}
}

func TestKMSAAD_MatchService_EmptyMethodsDeniesAll(t *testing.T) {
	if s, _ := broker.MatchService("GET", "api.notion.com", 0, "/v1/pages/abc", notion([]string{})); s != nil {
		t.Fatal("an explicitly empty methods list must deny every method")
	}
}

func TestKMSAAD_MethodsRoundTripJSON(t *testing.T) {
	var svcs []broker.Service
	if err := json.Unmarshal([]byte(`[{"name":"n","host":"api.notion.com/v1/pages/*","methods":["GET","HEAD"],"auth":{"type":"bearer","token":"T"}}]`), &svcs); err != nil {
		t.Fatal(err)
	}
	if len(svcs[0].Methods) != 2 {
		t.Fatalf("methods not decoded: %v", svcs[0].Methods)
	}
	b, _ := json.Marshal(svcs[0])
	var back map[string]any
	_ = json.Unmarshal(b, &back)
	if back["methods"] == nil {
		t.Fatalf("methods dropped on marshal: %s", b)
	}
}

func TestKMSAAD_ValidateMethodsRejectsUnknownVerbs(t *testing.T) {
	if err := broker.ValidateMethods([]string{"GET", "FETCH"}); err == nil {
		t.Fatal("unknown verb accepted")
	}
	if err := broker.ValidateMethods([]string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}); err != nil {
		t.Fatalf("standard verbs rejected: %v", err)
	}
}

// The opt-in "{name}" placeholder is exactly one non-empty path segment.
// "*" keeps its upstream greedy meaning (TestMatchServicePathWildcardCrossSlash).
// Encoded "%2F" and ".." are handled by proxy path normalization before
// matching; see TestKMSAAD_Wildcard_SingleSegmentOnly in internal/mitm.
func TestKMSAAD_MatchService_SingleSegmentWildcard(t *testing.T) {
	svcs := []broker.Service{{
		Name: "pages", Host: "api.example.test", Path: "/v1/pages/{id}",
		Auth: broker.Auth{Type: "bearer", Token: "EXAMPLE_TOKEN"},
	}}
	if s, _ := broker.MatchService("GET", "api.example.test", 0, "/v1/pages/abc", svcs); s == nil {
		t.Fatal("/v1/pages/{id} must match /v1/pages/abc")
	}
	for _, p := range []string{"/v1/pages/abc/children", "/v1/pages/", "/v1/pages/a/b", "/v1/pages//abc", "/v1/pages/abc/"} {
		if s, _ := broker.MatchService("GET", "api.example.test", 0, p, svcs); s != nil {
			t.Errorf("/v1/pages/{id} matched %s", p)
		}
	}

	mid := []broker.Service{{
		Name: "children", Host: "api.example.test", Path: "/v1/blocks/{id}/children",
		Auth: broker.Auth{Type: "bearer", Token: "EXAMPLE_TOKEN"},
	}}
	if s, _ := broker.MatchService("GET", "api.example.test", 0, "/v1/blocks/abc/children", mid); s == nil {
		t.Fatal("/v1/blocks/{id}/children must match /v1/blocks/abc/children")
	}
	for _, p := range []string{"/v1/blocks/a/b/children", "/v1/blocks//children", "/v1/blocks/children"} {
		if s, _ := broker.MatchService("GET", "api.example.test", 0, p, mid); s != nil {
			t.Errorf("/v1/blocks/{id}/children matched %s", p)
		}
	}
}
