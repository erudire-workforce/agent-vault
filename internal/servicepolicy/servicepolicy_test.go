package servicepolicy

import (
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
)

func notion(path string, methods ...string) broker.Service {
	var m []string
	if methods != nil {
		m = methods
	}
	return broker.Service{Name: "n", Host: "api.notion.com", Path: path, Methods: m, Auth: broker.Auth{Type: "bearer", Token: "NOTION_TOKEN"}}
}

func TestCheckServiceAllowlist(t *testing.T) {
	// Recorded spec change (review fix, blocker 3): the allowlist is exactly
	// GET /v1/pages/{id}, GET /v1/blocks/{id}/children and GET /v1/users/me.
	// /v1/pages/*, POST /v1/search and POST .../query moved to the refused
	// list, and the refusal cases below that exercise another reason now
	// use an allowed path so that reason is still the only one.
	ok := []broker.Service{
		notion("/v1/pages/{id}", "GET"),
		notion("/v1/blocks/{id}/children", "GET"),
		notion("/v1/users/me", "GET"),
	}
	for _, s := range ok {
		if err := CheckService(s); err != nil {
			t.Errorf("%s %v refused: %v", s.Path, s.Methods, err)
		}
	}
	bad := map[string]broker.Service{
		"pages greedy":       notion("/v1/pages/*", "GET"),
		"POST search":        notion("/v1/search", "POST"),
		"POST query":         notion("/v1/databases/{id}/query", "POST"),
		"PATCH page":         notion("/v1/pages/{id}", "GET", "PATCH"),
		"POST pages":         notion("/v1/pages/{id}", "POST"),
		"methods unset":      notion("/v1/pages/{id}"),
		"methods empty":      {Name: "n", Host: "api.notion.com", Path: "/v1/pages/{id}", Methods: []string{}, Auth: broker.Auth{Type: "bearer", Token: "T"}},
		"catch-all path":     notion("", "GET"),
		"broad prefix":       notion("/v1/*", "GET"),
		"search with suffix": notion("/v1/search*", "POST"),
		"unknown host":       {Name: "n", Host: "api.github.com", Path: "/x", Methods: []string{"GET"}, Auth: broker.Auth{Type: "bearer", Token: "T"}},
		"wrong auth type":    {Name: "n", Host: "api.notion.com", Path: "/v1/pages/{id}", Methods: []string{"GET"}, Auth: broker.Auth{Type: "api-key", Key: "T"}},
		"substitutions": func() broker.Service {
			s := notion("/v1/pages/{id}", "GET")
			s.Substitutions = []broker.Substitution{{Key: "K", Placeholder: "__k__"}}
			return s
		}(),
		"dot segment":  notion("/v1/pages/../users", "GET"),
		"non-443 port": func() broker.Service { s := notion("/v1/pages/{id}", "GET"); p := 8443; s.Port = &p; return s }(),
	}
	for name, s := range bad {
		if err := CheckService(s); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestModeFromEnv(t *testing.T) {
	t.Setenv(EnvMode, "")
	if Active() || ValidateEnv() != nil {
		t.Fatal("unset must be inactive and valid")
	}
	if err := CheckServices([]broker.Service{notion("", "PATCH")}); err != nil {
		t.Fatal("inactive mode must not refuse")
	}
	t.Setenv(EnvMode, ModeReadonlyAllowlist)
	if !Active() || CheckServices([]broker.Service{notion("", "PATCH")}) == nil {
		t.Fatal("readonly-allowlist must refuse")
	}
	t.Setenv(EnvMode, "readonly")
	if !Active() || ValidateEnv() == nil {
		t.Fatal("a misspelt mode must fail closed at runtime and be rejected at startup")
	}
}
