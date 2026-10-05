// Package servicepolicy holds compiled-in limits on broker services.
//
// In readonly-allowlist mode (AGENT_VAULT_SERVICE_POLICY=readonly-allowlist)
// every service write, whoever makes it (owner UI, API, proposal approval,
// declarative bootstrap), must describe a known provider and stay inside
// that provider's compiled-in method+path read allowlist, with the
// provider's fixed auth type and no substitutions. The proxy re-checks
// the matched service at request time, so a row written behind the API's
// back is refused too.
//
// The table is code, not configuration: widening it needs a reviewed
// release, which is the point.
package servicepolicy

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Infisical/agent-vault/internal/broker"
)

// EnvMode selects the policy mode.
const EnvMode = "AGENT_VAULT_SERVICE_POLICY"

// ModeReadonlyAllowlist is the only non-default mode.
const ModeReadonlyAllowlist = "readonly-allowlist"

// ErrRefused wraps every policy refusal.
var ErrRefused = errors.New("service policy")

// Rule allows one method on a path. Exactly one of Prefix and Exact is
// set. A Prefix rule covers a service path whose literal part (before the
// first '*' or '{') starts with Prefix. An Exact rule covers only that
// exact path pattern.
type Rule struct {
	Method string
	Prefix string
	Exact  string
}

// Provider is the compiled-in template for one upstream API.
type Provider struct {
	Name     string
	Host     string
	AuthType string
	Rules    []Rule
}

// Providers is the compiled-in table, keyed by host.
var Providers = map[string]Provider{
	"api.notion.com": {
		Name:     "notion",
		Host:     "api.notion.com",
		AuthType: "bearer",
		Rules: []Rule{
			{Method: "GET", Exact: "/v1/users"},
			{Method: "GET", Prefix: "/v1/users/"},
			{Method: "GET", Prefix: "/v1/pages/"},
			{Method: "GET", Prefix: "/v1/blocks/"},
			{Method: "GET", Prefix: "/v1/databases/"},
			{Method: "GET", Prefix: "/v1/data_sources/"},
			{Method: "GET", Exact: "/v1/comments"},
			// Read operations Notion exposes only as POST.
			{Method: "POST", Exact: "/v1/search"},
			{Method: "POST", Exact: "/v1/databases/{database_id}/query"},
			{Method: "POST", Exact: "/v1/data_sources/{data_source_id}/query"},
		},
	},
}

// Active reports whether readonly-allowlist mode is on. Any non-empty
// value other than "off" turns it on, so a misspelt mode fails closed.
func Active() bool {
	v := strings.TrimSpace(os.Getenv(EnvMode))
	return v != "" && !strings.EqualFold(v, "off")
}

// ValidateEnv reports an unrecognised mode so startup can refuse it
// rather than run with a policy the operator did not mean.
func ValidateEnv() error {
	v := strings.TrimSpace(os.Getenv(EnvMode))
	switch {
	case v == "", strings.EqualFold(v, "off"), v == ModeReadonlyAllowlist:
		return nil
	default:
		return fmt.Errorf("%s=%q is not a recognised mode (use %q or leave unset)", EnvMode, v, ModeReadonlyAllowlist)
	}
}

// CheckServices applies CheckService to every service when the mode is
// active and is a no-op otherwise.
func CheckServices(svcs []broker.Service) error {
	if !Active() {
		return nil
	}
	return CheckServicesStrict(svcs)
}

// CheckServicesStrict applies CheckService regardless of the mode.
func CheckServicesStrict(svcs []broker.Service) error {
	for i := range svcs {
		if err := CheckService(svcs[i]); err != nil {
			name := svcs[i].Name
			if name == "" {
				name = fmt.Sprintf("#%d", i)
			}
			return fmt.Errorf("service %s: %w", name, err)
		}
	}
	return nil
}

// CheckService enforces the compiled-in limits on one service.
func CheckService(s broker.Service) error {
	host, path, port := broker.SplitInlineHost(s.Host, s.Path)
	if s.Port != nil {
		port = s.Port
	}
	prov, ok := Providers[strings.ToLower(host)]
	if !ok {
		return fmt.Errorf("%w: host %q has no compiled-in provider template", ErrRefused, host)
	}
	if port != nil && *port != 443 {
		return fmt.Errorf("%w: %s services must use port 443", ErrRefused, prov.Name)
	}
	if s.Auth.Type != prov.AuthType {
		return fmt.Errorf("%w: %s services must use %q auth, not %q", ErrRefused, prov.Name, prov.AuthType, s.Auth.Type)
	}
	if len(s.Substitutions) > 0 {
		return fmt.Errorf("%w: substitutions are not allowed", ErrRefused)
	}
	if s.Methods == nil || len(s.Methods) == 0 {
		return fmt.Errorf("%w: %s services must list their methods explicitly", ErrRefused, prov.Name)
	}
	if path == "" {
		return fmt.Errorf("%w: %s services must name a path; a catch-all is not a read allowlist", ErrRefused, prov.Name)
	}
	if err := broker.ValidatePath(path); err != nil {
		return fmt.Errorf("%w: %v", ErrRefused, err)
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("%w: path %q contains a dot segment", ErrRefused, path)
		}
	}
	for _, m := range s.Methods {
		if !covered(prov, strings.ToUpper(strings.TrimSpace(m)), path) {
			return fmt.Errorf("%w: %s %s is outside the %s read allowlist", ErrRefused, strings.ToUpper(m), path, prov.Name)
		}
	}
	return nil
}

// erasePlaceholderNames maps "/v1/x/{id}/q" to "/v1/x/{}/q" so a rule
// matches whatever the operator called the placeholder.
func erasePlaceholderNames(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '{' {
			if j := strings.IndexByte(p[i:], '}'); j > 0 {
				b.WriteString("{}")
				i += j
				continue
			}
		}
		b.WriteByte(p[i])
	}
	return b.String()
}

func covered(p Provider, method, path string) bool {
	literal := path
	if i := strings.IndexAny(path, "*{"); i >= 0 {
		literal = path[:i]
	}
	for _, r := range p.Rules {
		if r.Method != method {
			continue
		}
		if r.Exact != "" && erasePlaceholderNames(path) == erasePlaceholderNames(r.Exact) {
			return true
		}
		if r.Prefix != "" && strings.HasPrefix(literal, r.Prefix) {
			return true
		}
	}
	return false
}
