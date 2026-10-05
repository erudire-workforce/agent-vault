package brokercore

import "errors"

var (
	// ErrInvalidSession means the supplied session token is missing, unknown,
	// or expired. The MITM ingress maps this to a 407 challenge.
	ErrInvalidSession = errors.New("brokercore: invalid or expired session")

	// ErrNoVaultContext means the session carries no vault scope and no hint
	// was provided (e.g. an agent token with zero vault grants).
	ErrNoVaultContext = errors.New("brokercore: session has no vault context")

	// ErrAgentVaultAmbiguous means an instance-level agent token with access
	// to multiple vaults did not specify which vault to use. Callers should
	// tell the user to set vault via the token:vault Basic auth form.
	ErrAgentVaultAmbiguous = errors.New("brokercore: agent has multiple vault grants; vault hint required")

	// ErrVaultHintMismatch means a scoped session was accompanied by a vault
	// hint that does not match the session's bound vault. Never silently
	// retarget a scoped session to a different vault.
	ErrVaultHintMismatch = errors.New("brokercore: vault hint does not match scoped session")

	// ErrVaultNotFound means the requested vault name does not exist.
	ErrVaultNotFound = errors.New("brokercore: vault not found")

	// ErrVaultAccessDenied means the actor exists but has no grant on the
	// requested vault.
	ErrVaultAccessDenied = errors.New("brokercore: actor has no access to vault")

	// ErrServiceNotFound means no configured broker service in the resolved
	// vault matches the target host. Callers surface 403 with a proposal hint.
	ErrServiceNotFound = errors.New("brokercore: no broker service matches target host")

	// ErrCredentialMissing means a credential referenced by the matched
	// service's auth config is not set or could not be decrypted. Callers
	// surface 502 so agents retry only after the credential is provisioned.
	ErrCredentialMissing = errors.New("brokercore: referenced credential missing or undecryptable")

	// ErrServiceDisabled means a configured broker service matched the
	// target host but has been toggled off by an operator. Distinct from
	// ErrServiceNotFound so agents can tell "configured but off" from "not
	// configured". Callers surface 403 with error code "service_disabled".
	ErrServiceDisabled = errors.New("brokercore: broker service is disabled")

	// ErrMethodNotAllowed means a service matched host+port+path but its
	// Methods allowlist does not include the request method. Callers
	// surface 403 and never fall through to the unmatched-host policy.
	ErrMethodNotAllowed = errors.New("brokercore: method not allowed by the matched broker service")

	// ErrNonCanonicalPath means the request path carries an encoded
	// slash, a dot segment, an empty segment or another form that would
	// make the matched path differ from what the upstream interprets.
	// Callers surface 400.
	ErrNonCanonicalPath = errors.New("brokercore: request path is not in canonical form")

	// ErrServicePolicy means the matched service violates the
	// compiled-in service policy (servicepolicy). Callers surface 403.
	ErrServicePolicy = errors.New("brokercore: matched broker service is outside the compiled-in service policy")

	// ErrOAuthNotConnected means the credential is an OAuth type but
	// the consent flow hasn't completed yet (no access token stored).
	ErrOAuthNotConnected = errors.New("brokercore: oauth credential not yet connected")

	// ErrOAuthRefreshFailed means the credential's access token expired
	// and the automatic refresh attempt failed.
	ErrOAuthRefreshFailed = errors.New("brokercore: oauth token refresh failed")
)
