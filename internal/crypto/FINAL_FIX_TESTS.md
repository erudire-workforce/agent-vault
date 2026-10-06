# Final-review tests (test-first)

Base: `claude/fork-review-fixes` at `e0afcd864b8bbd537b16a2e159b73d08c858fb6c`. Every new test file
carries `//go:build finalfix`, so the default build and CI stay green until the fixes land. Run them
with:

```
go test -tags finalfix ./...
```

The implementer removes the tag from a file in the change that makes its tests pass.

| # | Test | Why it fails at e0afcd86 |
|---|---|---|
| 1 | `mitm` `TestFinalFix_PolicyMode_CredentialOnlyOverTLSOn443` | in policy mode, `http://api.notion.com/...` and `https://api.notion.com:8443/...` match the service, are dialled, and receive the bearer; `http://api.notion.com:443/...` is dialled. Required: 403, no dial, no credential sent. The control, TLS on 443, returns 200 |
| 2 | `mitm` `TestFinalFix_PolicyMode_UnmatchedRequestsRefused` | with `unmatched_host_policy` absent or `passthrough`, `POST /v1/search`, `GET /v1/users` and `GET https://example.com/` are forwarded (200). The `deny` subtest already passes |
| 2 | `server` `TestFinalFix_PolicyMode_PassthroughSettingRefused` | `PATCH /v1/vaults/{name}/settings` sets `passthrough` (200) in policy mode |
| 2 | `bootstrap` `TestFinalFix_ValidateRequiresStrictDenyInPolicyMode` | `Validate` accepts a service with `strict_deny: false` in policy mode |
| 3 | `bootstrap` `TestFinalFix_EveryRunCapsOlderExecutorTokens` | a run that does not mint leaves an older full-TTL executor token at its full expiry |
| 3 | `bootstrap` `TestFinalFix_AmbiguousSinkFailureKeepsDeliveredTokenValid` | when `PutToken` stores the token and then returns an error, the run deletes the session, so the token in the sink no longer authenticates |
| 4 | `cmd` `TestFinalFix_HardenedStartupRefusesKMSEnabledWithoutPolicyMode` | `requirePolicyModeForHardenedDeployments` returns nil with `AGENT_VAULT_KMS_KEY_ID` set and `AGENT_VAULT_REQUIRE_KMS` unset |
| 5 | `crypto` `TestFinalFix_NoNilAADSealInNonTestCode` | the source scan finds `internal/infisical/sync.go:226`, which calls `crypto.Encrypt` (nil AAD) |
| 5 | `crypto` `TestFinalFix_NilAADScanCatchesPlantedCases` | passes: this is the known-positive check, showing the scanner finds all five planted cases (aliased import, nil, `[]byte{}`, `[]byte(nil)`) and none in a clean file |
