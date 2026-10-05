package broker

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

func pageSvc(path string, methods []string) []Service {
	return []Service{{Name: "n", Host: "api.notion.com", Path: path, Methods: methods, Auth: Auth{Type: "bearer", Token: "T"}}}
}

// {name} is the opt-in single-segment placeholder; "*" keeps its
// upstream greedy meaning.
func TestPlaceholderMatchesExactlyOneSegment(t *testing.T) {
	svcs := pageSvc("/v1/pages/{id}", nil)
	for path, want := range map[string]bool{
		"/v1/pages/abc":          true,
		"/v1/pages/abc/children": false,
		"/v1/pages/":             false,
		"/v1/pages":              false,
		"/v1/pages/a/b":          false,
	} {
		got, _ := MatchService("GET", "api.notion.com", 0, path, svcs)
		if (got != nil) != want {
			t.Errorf("/v1/pages/{id} vs %s: matched=%v want %v", path, got != nil, want)
		}
	}
	mid := pageSvc("/v1/blocks/{id}/children", nil)
	if s, _ := MatchService("GET", "api.notion.com", 0, "/v1/blocks/abc/children", mid); s == nil {
		t.Error("middle placeholder did not match one segment")
	}
	if s, _ := MatchService("GET", "api.notion.com", 0, "/v1/blocks/a/b/children", mid); s != nil {
		t.Error("middle placeholder matched two segments")
	}
	// "*" in a placeholder pattern stays greedy.
	mixed := pageSvc("/v1/blocks/{id}/*", nil)
	if s, _ := MatchService("GET", "api.notion.com", 0, "/v1/blocks/abc/children/x/y", mixed); s == nil {
		t.Error("greedy * after a placeholder did not match")
	}
	// Upstream "*" is unchanged.
	if s, _ := MatchService("GET", "api.notion.com", 0, "/v1/pages/a/b", pageSvc("/v1/pages/*", nil)); s == nil {
		t.Error("upstream greedy * changed")
	}
}

func TestPlaceholderLiteralLenScoresBeforePlaceholder(t *testing.T) {
	svcs := []Service{
		{Name: "broad", Host: "api.notion.com", Path: "/v1/*", Auth: Auth{Type: "bearer", Token: "T"}},
		{Name: "page", Host: "api.notion.com", Path: "/v1/pages/{id}", Methods: []string{"GET"}, Auth: Auth{Type: "bearer", Token: "T"}},
	}
	s, score := MatchService("GET", "api.notion.com", 0, "/v1/pages/abc", svcs)
	if s == nil || s.Name != "page" || score.PathLiteralLen != len("/v1/pages/") {
		t.Fatalf("got %+v score %+v, want the more specific placeholder rule", s, score)
	}
	// The most specific rule decides the method; the broad rule is not a
	// fallback for a refused method.
	if s, _, denied := MatchServiceDetail("PATCH", "api.notion.com", 0, "/v1/pages/abc", svcs); s != nil || !denied {
		t.Fatalf("PATCH fell through to the broad rule: %+v denied=%v", s, denied)
	}
}

func TestValidatePathPlaceholders(t *testing.T) {
	for _, p := range []string{"/v1/pages/{id}", "/v1/blocks/{block_id}/children", "/v1/{a}/{b}"} {
		if err := ValidatePath(p); err != nil {
			t.Errorf("%s rejected: %v", p, err)
		}
	}
	for _, p := range []string{"/v1/pages/{id", "/v1/pages/x{id}", "/v1/pages/{}", "/v1/pages/{id}x", "/v1/{a/b}", "/v1/pages/{1d}", "/v1/}"} {
		if err := ValidatePath(p); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}

// An explicitly empty methods list (deny all) must survive JSON and YAML
// round trips; dropping it would turn the rule into "any method".
func TestEmptyMethodsSurviveRoundTrip(t *testing.T) {
	svc := Service{Name: "n", Host: "api.notion.com", Methods: []string{}, Auth: Auth{Type: "bearer", Token: "T"}}
	b, err := json.Marshal(svc)
	if err != nil {
		t.Fatal(err)
	}
	var back Service
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Methods == nil || len(back.Methods) != 0 {
		t.Fatalf("JSON round trip lost methods: [] (%s)", b)
	}
	y, err := yaml.Marshal(svc)
	if err != nil {
		t.Fatal(err)
	}
	var yback Service
	if err := yaml.Unmarshal(y, &yback); err != nil {
		t.Fatal(err)
	}
	if yback.Methods == nil || len(yback.Methods) != 0 {
		t.Fatalf("YAML round trip lost methods: [] (%s)", y)
	}
	// nil stays absent.
	svc.Methods = nil
	b, _ = json.Marshal(svc)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["methods"]; ok {
		t.Fatalf("nil methods marshalled: %s", b)
	}
	if err := ValidateMethods([]string{"GET", "get"}); err == nil {
		t.Fatal("duplicate method accepted")
	}
}
