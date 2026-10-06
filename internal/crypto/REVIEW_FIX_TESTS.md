# Review-fix tests (test-first)

Base: `claude/fork-integration` at `9075022a39d9b56d1d7a47c101d1ad04ab5b6786`. Every new test file
carries `//go:build reviewfix`, so the default build and CI stay green until the fixes land.

```
go test -tags reviewfix ./...
```

When a group passes, the implementer removes the build tag from its files in the same change. The
only test that does not compile yet is `internal/bootstrap/ticktimeout`, which needs the new
`bootstrap.RotationTickTimeout` variable; it lives in its own directory so the compile failure does
not hide the other bootstrap tests.

## Blockers

| # | Test | Why it fails at 9075022a |
|---|---|---|
| 1 | `store` `TestReviewFix_ApplyProposalDeleteClearsIdentity` | `ApplyProposal` deletes the credential row but leaves `credential_identity:<key>` |
| 1 | `server` `TestReviewFix_Identity_ProposalDeleteThenRecreate` | after a proposal delete, the key recreated at version 1 with a new value reports the old value's digest |
| 1 | `server` `TestReviewFix_Identity_InFlightProbeAfterDeleteAndRecreate` | a probe still in flight across a delete and recreate writes its stale digest onto the new row |
| 1 | `server` `TestReviewFix_Identity_BusyProbeRequeuesNext` | a probe requested while one is running is dropped as busy; the new value never gets its identity |
| 1 | `server` `TestReviewFix_Identity_RecordBindsRowIDAndVersion` | the record is `<version>:<digest>` and does not contain the row ID |
| 2 | `cmd` `TestReviewFix_KMSEncryptionContextShape` | KMS calls send `{"app","env"}`; the required context is exactly `{"service":"agent-vault","environment":<env>}` |
| 3 | `servicepolicy` `TestReviewFix_NotionAllowlistIsExactlyThreePairs` | the table still allows users, databases, data_sources, comments, the POST searches and queries, and greedy prefixes |
| 3 | `server` `TestReviewFix_PolicyRefusesOutsideAllowlist_ServicesAPI` | POST and PUT `/v1/vaults/{name}/services` accept those services in policy mode |
| 3 | `server` `TestReviewFix_PolicyRefusesOutsideAllowlist_ProposalApproval` | proposal approval applies them (200) |
| 3 | `bootstrap` `TestReviewFix_Bootstrap_RefusesOutsideExactAllowlist` | `Apply` writes them |
| 3 | `cmd` `TestReviewFix_StartupRefusesKMSWithoutPolicyMode` | startup with KMS required and no policy mode returns nil |
| 3 | `cmd` `TestReviewFix_StartupRefusesBootstrapWithoutPolicyMode` | startup goes on to call Secrets Manager instead of refusing |
| 4 | `mitm` `TestReviewFix_WebSocketRefusedInPolicyMode` (credential injected, passthrough) | with the policy mode active, a 101 is relayed and the upstream is dialled; required is 403 and no upstream contact |
| 4 | `mitm` `TestReviewFix_WebSocketLimitationDocumented` | no paragraph in README.md, SECURITY.md or docs/ says WebSocket frames are not echo-scrubbed when `AGENT_VAULT_SERVICE_POLICY` is off |
| 4 | `mitm` `TestReviewFix_WebSocketUnchangedWithoutPolicyMode` | passes (guard): with the mode off, upstream WebSocket credential injection is unchanged |
| 5 | `store` `TestReviewFix_OAuthTokenRefreshCompareAndSet` | needs the `OAuthTokenUpdate` API specified in `reviewfix_oauth_cas_test.go`; the second refresh sealed for the same next versions must return `ErrVersionConflict` and leave both tokens decrypting |
| 5 | `store` `TestReviewFix_OAuthClientSecretCompareAndSet` | `SetCredentialOAuth` ignores `ClientSecretVersion`; the second write sealed for the same version must return `ErrVersionConflict` |

**WebSocket decision.** Upgrades are refused only while the service-policy mode is active. With
the mode off, the fork keeps upstream's WebSocket credential injection, and its frames are not
echo-scrubbed; the documentation must say so.

**OAuth compare-and-set API.** `UpdateCredentialOAuthTokens(ctx, vaultID, key, OAuthTokenUpdate)`,
where each ciphertext travels with the version it was sealed for (`AccessVersion`,
`RefreshVersion`), as `SetCredentialVersion` does. `SetCredentialOAuth` treats
`co.ClientSecretVersion` (and `co.Version` when a refresh token is set) the same way. Changing
the interface also changes these test call sites, which the implementer updates in the same
commit:
- `internal/aadmigrate/aadmigrate_kmsaad_test.go` `legacyOAuth`, which becomes
  `OAuthTokenUpdate{AccessVersion: 1, RefreshVersion: 1, ...}`;
- `internal/brokercore/kmsaad_oauth_swap_test.go` `fakeOAuthStore.UpdateCredentialOAuthTokens`;
- `internal/server/server_test.go` `mockStore.UpdateCredentialOAuthTokens`.

## Non-blocking

| Test | Status at 9075022a |
|---|---|
| `mitm` `TestReviewFix_MethodOverrideHeadersStripped` | Fails: all three override headers reach the upstream |
| `cmd` `TestReviewFix_StartupRefusesExternalCredentialStoreRows` | Fails: startup succeeds with a `vault_credential_stores` row |
| `bootstrap/ticktimeout` `TestReviewFix_RotationTickHasTimeout` | Does not compile (`bootstrap.RotationTickTimeout`). With the timeout lines removed it fails because a hung sink keeps the lock (checked) |
| `mitm` `TestReviewFix_EchoScrub_JSONSlashEscape` | Fails: a `\/`-escaped echo reaches the client |
| `mitm` `TestReviewFix_EchoScrub_GzipResponse` | Passes (guard): gzip is decoded and scrubbed |
| `mitm` `TestReviewFix_EchoScrub_BrotliRefused` | Passes (guard): `br` is refused with 502 |
| identity after a proposal delete | Covered by the first two blocker-1 tests |

## Existing tests the fixes will contradict

These are expected to change in the fix commits, as recorded spec changes:

- **`servicepolicy` `TestCheckServiceAllowlist`** accepts `/v1/pages/*`, `POST /v1/search` and
  `POST .../query`.
- **`bootstrap` `docJSON`** (`bootstrap_kmsaad_test.go`) uses `/v1/pages/*`; move it to
  `/v1/pages/{id}`.
- **`cmd` `TestKMSAAD_Startup_FreshStore_WrapsDEKWithKMS_AndUnwrapsOnRestart`** looks for
  `Ctx["env"]`; it becomes `Ctx["environment"]`. The `kmscontract` fixtures already use the
  canonical shape.
