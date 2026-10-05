package brokercore

import (
	"context"
	"net/url"
	"strings"
)

type methodCtxKey struct{}

// WithRequestMethod records the HTTP method of the request being brokered
// so CredentialProvider.Inject can enforce per-method service rules
// without changing the provider interface.
func WithRequestMethod(ctx context.Context, method string) context.Context {
	return context.WithValue(ctx, methodCtxKey{}, strings.ToUpper(method))
}

// RequestMethod returns the method set by WithRequestMethod, or "" when
// none was set. A service with a Methods allowlist refuses "".
func RequestMethod(ctx context.Context) string {
	m, _ := ctx.Value(methodCtxKey{}).(string)
	return m
}

// CanonicalRequestPath returns the decoded path that both the service
// matcher and the upstream will see, or ErrNonCanonicalPath when the two
// could disagree. Refused: percent-encoded '/', '\', '.', NUL or '%'
// (a double-encoding vector); empty segments ("//"); "." and ".."
// segments; backslashes and control characters. Rejecting instead of
// normalising keeps the forwarded bytes identical to the matched ones.
func CanonicalRequestPath(u *url.URL) (string, error) {
	raw := strings.ToLower(u.EscapedPath())
	for _, bad := range []string{"%2f", "%5c", "%2e", "%00", "%25"} {
		if strings.Contains(raw, bad) {
			return "", ErrNonCanonicalPath
		}
	}
	p := u.Path
	if p == "" {
		return "/", nil
	}
	if !IsCanonicalPath(p) {
		return "", ErrNonCanonicalPath
	}
	return p, nil
}

// IsCanonicalPath reports whether a decoded path is absolute and free of
// empty, "." and ".." segments, backslashes and control characters.
func IsCanonicalPath(p string) bool {
	if p == "" || p[0] != '/' {
		return false
	}
	for i := 0; i < len(p); i++ {
		if c := p[i]; c < 0x20 || c == 0x7f || c == '\\' {
			return false
		}
	}
	segs := strings.Split(p[1:], "/")
	for i, s := range segs {
		switch s {
		case ".", "..":
			return false
		case "":
			// Only a single trailing slash ("/a/") or the root ("/") may
			// leave an empty segment.
			if i != len(segs)-1 {
				return false
			}
		}
	}
	return true
}
