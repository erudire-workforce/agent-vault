package brokercore

import (
	"net/http"
	"testing"
)

// Method-override headers are stripped when the matched service restricts
// methods, and kept when it does not (no methods listed means every method
// is allowed anyway).
func TestApplyInjection_MethodOverrideHeaders(t *testing.T) {
	names := []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"}
	src := http.Header{}
	for _, h := range names {
		src.Set(h, "DELETE")
	}

	dst := http.Header{}
	ApplyInjection(src, dst, &InjectResult{MethodsRestricted: true})
	for _, h := range names {
		if v := dst.Get(h); v != "" {
			t.Errorf("restricted service: %s = %q forwarded", h, v)
		}
	}

	dst = http.Header{}
	ApplyInjection(src, dst, &InjectResult{})
	for _, h := range names {
		if dst.Get(h) == "" {
			t.Errorf("unrestricted service: %s dropped", h)
		}
	}
}
