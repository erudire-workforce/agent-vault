package mitm

import (
	"encoding/json"
	"net/http"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ratelimit"
)

// whoamiPaths are the origin-form paths the proxy listener answers
// itself. Everything else on origin-form stays a 400.
var whoamiPaths = map[string]bool{
	"/v1/whoami":          true,
	"/agent-vault/whoami": true,
}

func isWhoamiRequest(r *http.Request) bool {
	return r.Method == http.MethodGet && r.URL != nil && r.URL.Host == "" && whoamiPaths[r.URL.Path]
}

// handleWhoami answers GET /v1/whoami on the proxy listener for the token
// presented in Proxy-Authorization: instance role, vault grants and
// expiry. It never returns a credential or the token. A missing or
// invalid token is a 407, and failures count against the same per-IP
// auth budget as CONNECT.
func (p *Proxy) handleWhoami(w http.ResponseWriter, r *http.Request) {
	if p.rateLimit != nil && !isLoopbackPeer(r) {
		if d := p.rateLimit.Check(ratelimit.TierAuth, mitmIPKey(r)); !d.Allow {
			ratelimit.WriteDenial(w, d, "Too many proxy requests")
			return
		}
	}
	wr, ok := p.sessions.(brokercore.WhoamiResolver)
	if !ok {
		http.Error(w, "whoami is not available", http.StatusNotFound)
		return
	}
	token, _, err := brokercore.ParseProxyAuth(r)
	if err != nil {
		p.recordAuthFailure(r)
		writeProxyAuthChallenge(w, "Proxy-Authorization required")
		return
	}
	who, err := wr.Whoami(r.Context(), token)
	if err != nil {
		p.recordAuthFailure(r)
		writeProxyAuthChallenge(w, "invalid or expired session")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(who)
}
