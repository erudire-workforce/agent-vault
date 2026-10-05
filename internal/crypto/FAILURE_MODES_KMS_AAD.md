# Failure modes: KMS-wrapped DEK, row-bound AAD, secret-free logs, and the fork policy set

Base: `v0.40.0` = `872578e4cdf9e03d5e3bcb5512023a70bf90ed65`. Branch: `claude/kms-wrap-aad-tests`.
This file and every test it names were written before the implementation (test-first). No production
file was changed.

The tests cover the fork's security changes: a KMS-wrapped data key, row-bound AAD on every
DEK-encrypted value, no secrets in logs or URLs, write-only stored keys, per-method service rules,
proxy header hygiene and response echo scrubbing, executor token policy, declarative bootstrap with
token delivery and rotation, and a canonical credential identity digest. The target store is
Postgres; SQLite is tested as a second backend because upstream still ships it. All fixtures are
placeholders (`example-integration`, `ws-00000000-test`, `*.example.test`, `SENTINEL-AV-TEST-*`).

## How to run

Every new test file carries `//go:build kmsaad`, so the default build is untouched.

```
go vet ./... && go test ./...                         # default build: must stay green
AGENT_VAULT_TEST_POSTGRES_URL='postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable' \
  go test -tags kmsaad ./...                          # new tests: must fail until the patch lands
```

Each store-backed test runs as a `postgres` and a `sqlite` subtest. Each postgres subtest creates and
drops its own database through the admin URL. Without `AGENT_VAULT_TEST_POSTGRES_URL` the postgres
subtests skip with a log line; CI should set `AGENT_VAULT_TEST_REQUIRE_POSTGRES=1` so a missing
database is a failure, not a skip. Upstream CI has no Postgres service today, so one has to be added
to the workflow that runs the tagged suite.

**Removing the tag.** When a package's tests pass, the implementer deletes the `//go:build kmsaad`
line from that package's `kmsaad` files in the same PR. Tests in the contract packages
(`internal/crypto/aadcontract`, `internal/auth/kmscontract`, `internal/aadmigrate`,
`internal/bootstrap`, `internal/identity`, `internal/broker/methodcontract`) compile only once the
API below exists; those directories hold only test files today and are skipped by `./...` on the
default build. Fixtures that write v0.40.0-format ciphertexts with `crypto.Encrypt` (for example
`encOAuthField` in `internal/brokercore/kmsaad_oauth_swap_test.go`) switch to the AAD form when the
patch lands, so their control assertions keep passing; the swap assertions must not be loosened.

## What the code does today (read at 872578e4)

| Fact | Where |
|---|---|
| AES-256-GCM with nil additional data on both seal and open | `internal/crypto/crypto.go:29`, `:45` |
| Master key table on Postgres: `dek_ciphertext`, `dek_nonce`, `dek_plaintext`, `salt`, `kdf_*`, `sentinel`, `sentinel_nonce` | `internal/store/20260617143022_postgres_baseline.go:84-96` |
| Same columns on SQLite (KEK/DEK rebuild; `002_master_key.go` is the original password-only schema, both return early unless SQLite) | `internal/store/038_master_key_kek_dek.go:10-27` |
| Unwrapped DEK stored when no password is given | `internal/auth/auth.go:72-87`, `cmd/server.go:457-519` |
| Startup unlock: env password, then `--password-stdin`, then interactive prompt; a `dek_plaintext` row unlocks with no secret at all | `cmd/server.go:344-415`, `:381-388`, `:430-437` |
| DEK sentinel and password-KEK wrap sealed with nil AAD | `internal/auth/auth.go:96`, `:149` |
| `master-password remove` writes the DEK back to `dek_plaintext` | `cmd/master_password.go:217` |
| Credential value encrypted before the row exists; upsert keeps the old `id` but returns a fresh UUID | `internal/server/handle_credentials.go:66-71`, `internal/store/sql_store.go:860-881` |
| OAuth refresh token and client secret ciphertexts | `internal/store/048_credential_oauth.go:16-38`; written at `internal/server/handle_oauth.go:104,237,245,416,425,433,493,505` and `internal/brokercore/credential.go:304,311` |
| Proposal ciphertexts, decrypted and re-encrypted on approval | `internal/server/handle_proposals.go:201`, `:482`, `:499` |
| CA root key: file `ca.key.enc` on SQLite, `ca_state` on Postgres | `internal/ca/soft.go:276`, `:363`; `cmd/server.go:211-214` |
| Infisical sync writes credentials with nil AAD | `internal/infisical/sync.go:226` |
| Token-endpoint error body (may echo request secrets) is put in the callback redirect URL, in `last_refresh_error`, and in the token-upload error response | `internal/oauth/oauth.go:56-58`, `internal/server/handle_oauth.go:229-232`, `:404-407`; `internal/brokercore/credential.go:298` |
| Agent create and rotate always pass a nil token expiry; rotate deletes the old session first | `internal/server/handle_agents.go:115`, `:351`; `internal/store/sql_store.go:3186` |
| `MatchService` ignores the method; `*` is greedy across `/` | `internal/broker/broker.go:555-583`, `:620-623` |
| Upstream response headers copied with `Add`; only hop-by-hop stripped | `internal/mitm/forward.go:392-397`, `internal/mitm/websocket.go:85-90` |
| `169.254.170.2` (ECS/Fargate credentials) only in the private link-local range | `internal/netguard/netguard.go:99-115` |
| `POST /v1/auth/register` creates an inactive user for anyone once an owner exists (unless invite-only) | `internal/server/handle_auth.go:67-130`, `internal/server/server.go:811` |

## Contract the patch must provide

These names are what the contract tests compile against. Changing a name is fine if the test changes
with it and a reviewer agrees; changing the semantics is not.

**AAD (`internal/crypto`).**
`type AAD struct{ Table, Field, VaultID, Key string; Version uint64 }`,
`func (AAD) Bytes() ([]byte, error)` producing `table 0x00 field 0x00 vault_id 0x00 key 0x00 decimal(version)`
and rejecting empty table/field or any component containing `0x00`,
`EncryptAAD(plaintext, key, aad)` and `DecryptAAD(ciphertext, nonce, key, aad)`.
Field map: `credentials.ciphertext` = `{"credentials","value",vault_id,key,v}`;
`credential_oauth.refresh_token_ct` = `{"credential_oauth","refresh_token",vault_id,credential_key,v}`;
`credential_oauth.client_secret_ct` = `{"credential_oauth","client_secret",…}`;
`proposal_credentials.ciphertext` = `{"proposal_credentials","value",vault_id,"<proposal_id>:<key>",v}`;
CA root key = `{"ca_root_key","root_key","","",v}`; sentinel = `{"master_key","sentinel","","",1}`;
password-wrapped DEK = `{"master_key","dek","","",1}`. `version` is a new monotonic integer column on
`credentials`, `credential_oauth` and `proposal_credentials` (`store.Credential.Version`,
`store.CredentialOAuth.Version`, `store.EncryptedCredential.Version`), bumped on every write and
checked on read. Credential id is not used: it does not exist when the value is encrypted, and the
upsert returns a wrong one.

**KMS (`internal/auth`, `internal/store`).** `KeyWrapper` with
`Wrap(ctx, dek, encCtx) (wrapped, keyID, err)` and `Unwrap(ctx, wrapped, keyID, encCtx) (dek, err)`;
`SetupWithKMS(ctx, w, encCtx)` and `UnlockWithKMS(ctx, w, rec, encCtx)`; `VerificationRecord` and
`store.MasterKeyRecord` gain `KMSWrappedDEK []byte` and `KMSKeyID string`, persisted on Postgres and
SQLite. Startup reads `AGENT_VAULT_KMS_KEY_ID`, `AGENT_VAULT_KMS_ENCRYPTION_CONTEXT_ENV` and
`AGENT_VAULT_REQUIRE_KMS`; the AWS implementation must honour `AWS_ENDPOINT_URL_KMS` (the tests point
it at an in-memory fake that speaks the KMS JSON 1.1 protocol).

**Migration (`internal/aadmigrate`).** `Run(ctx, store, dek) (Result{Rewrapped, AlreadyBound}, error)`,
`IsComplete(ctx, store)`, `RunCAKeyFile(dir, dek)`. After completion the production read path refuses
nil-AAD values.

**Methods (`internal/broker`).** `Service.Methods []string` (json/yaml `methods`; nil = any method,
empty list = deny all, case-insensitive), `MatchService(method, host, port, path, services)`,
`ValidateMethods`. A host+path match with a denied method is a 403 at the proxy, never the
unmatched-host passthrough.

**Bootstrap (`internal/bootstrap`).** `Document`, `SecretsSource`, `TokenSink{PutToken, GetToken}`,
`CertSink{PutCACert}`, `Options`, `Apply`, `RotateIfDue`, `RunRotationLoop`; constants
`RotateBefore = 7*24h`, `RotationOverlap = 10m`. Full shape in the test file header.

**Identity (`internal/identity`).** `NotionDigest(usersMe []byte) (hexDigest string, err error)`.

**Other fork behaviour pinned at the HTTP surface:** `AGENT_VAULT_REQUIRE_TOKEN_EXPIRY=1`; `GET
/v1/whoami` on the proxy listener returning exactly `{"instance_role","vaults":[{"vault","role"}],"expires_at"}`;
one `X-Agent-Vault-Credential-Identity` set by the proxy after dropping any upstream header with that
exact name or the `X-Agent-Vault-` prefix, describing the credential used on the final attempt
(including the OAuth 401 retry); service path matching on the same normalized path that is
forwarded; every raw, base64, base64url and percent-encoded occurrence of the injected credential
replaced with `[REDACTED]` in response headers, body, logs and request-log entries; stored keys
write-only for every role (403 or metadata only: name, masked hint, version, identity digest,
timestamps).

The swap tests observe the result through the real `CredentialProvider` (what the proxy injects),
not through reveal, because reveal is removed by the write-only rule and a 403 would make the swap
assertions vacuous.

## Identity digest golden vector

`sha256("notion" 0x00 bot.workspace_id 0x00 bot.workspace_name 0x00 name)`, lowercase hex.

| Input | Value |
|---|---|
| `bot.workspace_id` | `ws-00000000-test` |
| `bot.workspace_name` | `Example Workspace` |
| `name` | `example-integration` |
| bytes hashed | `notion\x00ws-00000000-test\x00Example Workspace\x00example-integration` |
| digest | `2ef5eef3617ec9f7d8894b36a385469ea039caaf97e100179cb1e70c091edfe1` |

Checked independently with `shasum -a 256` and by `TestKMSAAD_IdentityGoldenVectorIsCorrect`, which
runs today.

## Failure modes and the tests that cover them

Status is what `go test -tags kmsaad` reports at 872578e4. "Compile" means the package fails to build
because the contract API does not exist; that is the expected reason. "Guard" means the test already
passes and protects current behaviour from regressing.

### KMS-wrapped DEK

| # | Failure mode | Test | Status today |
|---|---|---|---|
| K1 | Fresh store in KMS mode stores the DEK unwrapped, password-wrapped, or prompts | `cmd` `TestKMSAAD_Startup_FreshStore_WrapsDEKWithKMS_AndUnwrapsOnRestart` (postgres, sqlite) | Fails: prompts for a password |
| K2 | Raw DEK bytes persisted anywhere in `master_key` (or the SQLite file/WAL) | same test; `kmscontract` `TestKMSAAD_StorePersistsKMSFields` | Fails / Compile |
| K3 | Restart does not unwrap through KMS or yields a different DEK | same test; `TestKMSAAD_SetupWithKMS_WrapsAndUnlocks` | Fails / Compile |
| K4 | Encryption context changed (prod to staging) and startup still succeeds | `TestKMSAAD_Startup_EncryptionContextChanged_Refused`; `TestKMSAAD_UnlockWithKMS_WrongEncryptionContextRefused` | Fails at setup / Compile |
| K5 | Configured key id differs from the wrapping key, or the record's key id is tampered | `TestKMSAAD_Startup_KeyIDChanged_Refused`; `TestKMSAAD_UnlockWithKMS_KeyIDMismatchRefused` | Fails at setup / Compile |
| K6 | KMS unreachable on a fresh store and startup falls back to the password or passwordless path, persisting a record | `TestKMSAAD_Startup_KMSUnavailableOnFreshStore_NoFallback`; `TestKMSAAD_KMSUnavailable_FailsClosed` | Fails: password record persisted |
| K7 | KMS unreachable on restart and startup still succeeds | `TestKMSAAD_Startup_KMSDownOnRestart_FailsClosed` | Fails at setup |
| K8 | `dek_plaintext` record accepted while KMS is required (both unlock entry points) | `TestKMSAAD_Startup_UnwrappedDEKRecord_RefusedWhenKMSRequired`; `TestKMSAAD_UnlockWithKMS_RefusesNonKMSRecords` | Fails |
| K9 | Password-wrapped record accepted while KMS is required | `TestKMSAAD_Startup_PasswordWrappedDEKRecord_RefusedWhenKMSRequired` | Fails |
| K10 | The fake KMS itself does not enforce context or key id (tests above would pass vacuously) | `TestKMSAAD_FakeAWSKMS_KnownPositive`, `TestKMSAAD_FakeKMSEnforcesContextAndKeyID` | Guard (passes) / Compile |
| K11 | DEK sentinel or password-wrapped DEK sealed without AAD; a credential-path ciphertext of the sentinel string verifies | `internal/auth` `TestKMSAAD_SentinelIsAADBound`, `TestKMSAAD_SentinelSwapFromCredentialRefused`, `TestKMSAAD_PasswordWrappedDEKIsAADBound` | Fails |

Not covered by a test, must be handled in the patch: `master-password set/change/remove` on a KMS
instance (remove would write `dek_plaintext`, `cmd/master_password.go:217`); `migrate-db` copying the
KMS columns between backends.

### Row-bound AAD

| # | Failure mode | Test | Status today |
|---|---|---|---|
| A1 | AAD encoding ambiguous or not pinned byte for byte | `aadcontract` `TestKMSAAD_AADEncodingIsExact`, `TestKMSAAD_AADRejectsSeparatorInComponents` | Compile |
| A2 | A component of the AAD is not load-bearing | `TestKMSAAD_EveryComponentIsBound` | Compile |
| A3 | Legacy and bound ciphertexts open under each other's path | `TestKMSAAD_LegacyAndBoundAreMutuallyExclusive` | Compile |
| A4 | Nonce reuse; zero-length or 4 MiB values mishandled; tampered ciphertext, nonce or DEK accepted | `TestKMSAAD_NonceUniqueness`, `TestKMSAAD_ZeroLengthAndLargeValues`, `TestKMSAAD_TamperedCiphertextOrNonceFails` | Compile |
| A5 | Row swap, same vault | `server` `TestKMSAAD_API_RowSwapSameVaultRefused` | Fails: the proxy would inject the other row's secret |
| A6 | Cross-vault swap, same key name | `TestKMSAAD_API_CrossVaultSwapRefused`; `brokercore` `TestKMSAAD_OAuthRefresh_CrossVaultRefreshTokenSwapRefused` | Fails |
| A7 | Ciphertext-only rollback to an earlier version | `TestKMSAAD_API_OldCiphertextReplayRefused`; `TestKMSAAD_OAuthRefresh_OldVersionReplayRefused` | Fails |
| A8 | OAuth refresh token moved into the access-token slot | `TestKMSAAD_API_OAuthRefreshIntoAccessSlotRefused` | Fails |
| A9 | OAuth refresh token of credential A sent to credential B's token endpoint | `TestKMSAAD_OAuthRefresh_CrossRowRefreshTokenSwapRefused` | Fails: A's token posted to B's endpoint |
| A10 | `client_secret_ct` copied into `refresh_token_ct` | `TestKMSAAD_OAuthRefresh_ClientSecretIntoRefreshTokenRefused` | Fails |
| A11 | Proposal ciphertext swapped from another proposal, or from a credentials row, then approved | `TestKMSAAD_API_ProposalCiphertextSwapRefused` (two cases) | Fails: approval applies the swapped secret |
| A12 | CA root key replaced by a credential-path ciphertext (file on SQLite, `ca_state` on Postgres); new CA key unbound | `internal/ca` `TestKMSAAD_CAKeyFileSwapFromCredentialCiphertextRefused`, `TestKMSAAD_CAStateSwapFromCredentialCiphertextRefused`, `TestKMSAAD_NewCAKeyIsAADBound` | Fails: attacker root loaded |
| A13 | Migration misses a table or field (static, OAuth access/refresh/client secret, proposals) | `aadmigrate` `TestKMSAAD_Migration_RewrapsAllLegacyRows`, `TestKMSAAD_Migration_CoversProposalCredentials` | Compile |
| A14 | Migration not idempotent | `TestKMSAAD_Migration_Idempotent` | Compile |
| A15 | Crash mid-migration leaves a mixed state that a rerun double-wraps or loses | `TestKMSAAD_Migration_ResumesAfterCrash` | Compile |
| A16 | An undecryptable row is skipped or deleted and the migration marked complete | `TestKMSAAD_Migration_UndecryptableRowFailsLoudly` | Compile |
| A17 | After completion, a planted legacy value is accepted by the production read path | `TestKMSAAD_PostMigration_LegacyReadRefused` | Compile |
| A18 | CA key file not migrated | `TestKMSAAD_Migration_CAKeyFile` | Compile |

Not claimed: a full-row rollback that restores the ciphertext and the version together. AAD cannot
detect it; it needs an external monotonic anchor. Infisical sync (`sync.go:226`) is closed by
disabling credential-store switching (P5) rather than by AAD. `POST /v1/vaults` with a
`credential_store` block is a second switching path the patch must close as well; it has no test
because exercising it reaches out to an Infisical endpoint.

### Secrets in logs and URLs

| # | Failure mode | Test | Status today |
|---|---|---|---|
| L1 | The scanner cannot see one of the channels (server logger, `slog.Default`, `log`, stderr, request-log sink, HTTP responses) | `server` `TestKMSAAD_LogScanner_KnownPositive` | Guard (passes) |
| L2 | Credential create, update, invalid key, malformed body or OAuth token upload body logged | `TestKMSAAD_NoSecretInLogs_CredentialCreateUpdate` | Guard (passes) |
| L3 | OAuth callback code, client secret or tokens logged (success path) | `TestKMSAAD_NoSecretInLogs_OAuthCallback/token-endpoint-ok` | Guard (passes) |
| L4 | Token endpoint error body that echoes the code and client secret is put into the callback redirect URL | `TestKMSAAD_NoSecretInLogs_OAuthCallback/token-endpoint-error-echoes-request` | Fails |
| L5 | Token endpoint error body persisted in `last_refresh_error` and carried in the Inject error | `brokercore` `TestKMSAAD_OAuthRefresh_ErrorBodyNotPersisted` | Fails |
| L6 | Executor token appears in bootstrap logs | `bootstrap` `TestKMSAAD_Bootstrap_TokenDeliveredWithExpiry_NotLogged` | Compile |

Not covered: the token-upload validation error echoes the token endpoint body back to the caller
(`handle_oauth.go:404-407`).

### Fork policy

| # | Failure mode | Test | Status today |
|---|---|---|---|
| P1 | Anyone can register once an owner exists | `server` `TestKMSAAD_RegisterRefusedOnceAUserExists` | Fails: 201, inactive user row |
| P2 | Executor token (no-access, proxy on default, finite expiry) can reveal, change vault settings, upsert services, create vaults or agents | `TestKMSAAD_ExecutorTokenPrivilegeChecks` | Guard (passes: all 403) |
| P3 | A token with no expiry is minted (create, rotate) under `AGENT_VAULT_REQUIRE_TOKEN_EXPIRY=1` | `TestKMSAAD_RequireTokenExpiry_MintingRefusesNilExpiry` | Fails |
| P4 | An existing no-expiry token is accepted by the API or the proxy under that setting | `TestKMSAAD_RequireTokenExpiry_AuthRefusesExistingNoExpiryToken` | Fails |
| P5 | Credential-store switching still enabled | `TestKMSAAD_CredentialStoreSwitchingDisabled` | Fails: 200 (builtin), 503 (infisical) |
| P6 | Proxy-port whoami missing, wrong shape, leaks a credential, works without a token, or is reachable unauthenticated on the API port | `TestKMSAAD_ProxyWhoami` | Fails: 400 |
| P7 | `PATCH /v1/pages/{id}` forwarded with the credential when the service allows only GET, under both deny and passthrough policy | `mitm` `TestKMSAAD_WriteHold_PatchPagesRefused_GetAllowed` | Fails |
| P8 | `methods: []` fails open | `TestKMSAAD_WriteHold_EmptyMethodsDeniesAll`; `methodcontract` `TestKMSAAD_MatchService_EmptyMethodsDeniesAll` | Fails / Compile |
| P9 | Method API missing or not case-insensitive; unknown verbs accepted; methods dropped on JSON round trip | `methodcontract` tests | Compile |
| P10 | `*` matches across `/` | `mitm` `TestKMSAAD_Wildcard_SingleSegmentOnly`, `TestKMSAAD_Wildcard_MiddleSegment`; `TestKMSAAD_MatchService_SingleSegmentWildcard` | Fails / Compile |
| P11 | Upstream-spoofed `X-Agent-Vault-*` reaches the client; identity header missing or duplicated (plain forward and HTTPS MITM) | `TestKMSAAD_HeaderHygiene_SpoofedIdentityStripped` | Fails |
| P12 | `169.254.170.2` reachable with `AGENT_VAULT_ALLOW_PRIVATE_RANGES` or an allowlist entry | `netguard` `TestKMSAAD_FargateCredentialsEndpointAlwaysBlocked`, `TestKMSAAD_FargateEndpointBlockedViaEnv` | Fails |
| P13 | Identity digest wrong, or recorded when a field is missing, empty, null or contains `0x00` | `identity` tests; golden check in `internal/crypto` | Compile / Guard |
| P14 | After an OAuth 401 retry the identity header describes the first credential, or is missing or duplicated | `mitm` `TestKMSAAD_RetryPath_IdentityDescribesFinalCredential` | Fails: no identity header |
| P15 | Path match runs on a different form than the forwarded path: `%2F`, `%2f`, `..`, `%2e%2e`, `//` let a single-segment GET rule forward deeper paths with the credential | `TestKMSAAD_PathNormalization_MatchesWhatIsForwarded` | Fails: forwarded with the credential |

P14 note: the test first checks that the identity header differs for two different credentials
(a plain request with each). If the identity is derived from a field the fake provider does not
fill (for example a new `InjectResult` field), the test fails with "does not distinguish two
different credentials" and the fake in `seqCredProvider`/`credResult` must be extended to set it;
that is a fixture change, not a loosening.

### Write-only stored keys

| # | Failure mode | Test | Status today |
|---|---|---|---|
| W1 | Owner session reads a stored value via `GET /v1/credentials?reveal=true` (list and single key, static and OAuth) | `server` `TestKMSAAD_WriteOnly_OwnerRevealRefusedOrMetadataOnly` | Fails |
| W2 | Any read endpoint or UI page returns a stored value (credentials list/reveal, OAuth status, proposal detail and list for owner and agent, admin proposals, vault context, services, credential usage, logs, settings, SPA pages); sentinel scan over every response body | `TestKMSAAD_WriteOnly_NoStoredValueInAnyResponseBody` | Fails (reveal) |

Not covered: dynamic-credential reveal (`revealDynamicCredential`, `enumerateDynamicCredentials`),
which needs an Infisical dynamic secret to exercise.

### Response echo scrubbing

| # | Failure mode | Test | Status today |
|---|---|---|---|
| E1 | Upstream echoes the injected bearer in a JSON error body and response headers (raw, base64, raw base64, base64url, raw base64url, query- and path-escaped, base64 of `Bearer <token>`) and it reaches the client, proxy logs or the request log | `mitm` `TestKMSAAD_EchoScrub_ResponseHeadersBodyAndLogs` | Fails |
| E2 | Same on the OAuth 401 retry path, for both the first and the final credential | `TestKMSAAD_EchoScrub_RetryPath` | Fails |

### Bootstrap and token delivery

| # | Failure mode | Test | Status today |
|---|---|---|---|
| B1 | Second Apply duplicates vaults, services or agents, or re-mints a valid token | `TestKMSAAD_Bootstrap_ApplyIsIdempotent` | Compile |
| B2 | Token reaches the sink without a bounded expiry or does not authenticate | `TestKMSAAD_Bootstrap_TokenDeliveredWithExpiry_NotLogged` | Compile |
| B3 | Rotation outside the 7-day window, or none inside it | `TestKMSAAD_Bootstrap_RotationInsideWindow_SinkBeforeRevoke_Overlap` | Compile |
| B4 | Old session revoked before the new token reaches the sink (executor cut off) | same | Compile |
| B5 | Old token refused at once, or kept longer than the 10-minute overlap | same | Compile |
| B6 | Rotation only at startup | `TestKMSAAD_Bootstrap_RotationRunsFromTimer` | Compile |
| B7 | Two concurrent bootstraps both mint (Postgres advisory lock) | `TestKMSAAD_Bootstrap_ConcurrentBootstrapsMintOnce` (postgres only) | Compile |
| B8 | Unreadable delivered secret does not trigger a re-mint | `TestKMSAAD_Bootstrap_MintsWhenSecretUnreadable` | Compile |
| B9 | Crash between DB commit and sink write leaves the executor without a valid token | `TestKMSAAD_Bootstrap_ReMintAfterCrashBetweenCommitAndSink` | Compile |
| B10 | Compiled-in limits bypassed: executor vault role member/admin, agent instance role owner/member, Notion method other than GET or unset | `TestKMSAAD_Bootstrap_CompiledInLimitsRefused` (7 cases) | Compile |
| B11 | CA private key published, or anything but the certificate | `TestKMSAAD_Bootstrap_CACertPublished_PrivateKeyNever` | Compile |

## Decisions the implementer cannot make alone

1. **Wildcard semantics conflict with an upstream test.** `internal/broker/broker_test.go:87-96`
   (`TestMatchServicePathWildcardCrossSlash`) asserts that `/api/*` matches `/api/foo/bar/baz`.
   P10 requires the opposite. Making P10 pass breaks that test, and the rules forbid editing a failing
   test to get green. Somebody has to decide: either `*` becomes single-segment for every service
   (and the upstream test is rewritten as a recorded semantics change, perhaps with `**` for the old
   greedy behaviour), or single-segment applies only to services that opt in (for example
   `strict_deny` or `methods` set), in which case P10's fixtures need that flag.
2. **Notion GET-only blocks Notion reads that use POST.** `POST /v1/search` and
   `POST /v1/databases/{id}/query` are read operations. B10 refuses any non-GET Notion method as the
   fork requires; if a deployment needs search or database queries, the limit has to become a path-and-method
   allowlist instead.
3. **Open registration (P1) is an upstream feature.** Refusing it changes product behaviour for
   self-hosted users; in the fork it is the intended hardening.

## Command output

Filled from the final run on this branch.

```
$ go vet ./...
vet rc=0

$ go test -count=1 ./...   (default build)
ok  	github.com/Infisical/agent-vault/cmd	1.643s
ok  	github.com/Infisical/agent-vault/internal/auth	1.004s
ok  	github.com/Infisical/agent-vault/internal/broker	0.376s
ok  	github.com/Infisical/agent-vault/internal/brokercore	0.525s
ok  	github.com/Infisical/agent-vault/internal/ca	0.433s
ok  	github.com/Infisical/agent-vault/internal/catalog	0.522s
ok  	github.com/Infisical/agent-vault/internal/crypto	0.585s
ok  	github.com/Infisical/agent-vault/internal/infisical	0.606s
ok  	github.com/Infisical/agent-vault/internal/isolation	4.488s
ok  	github.com/Infisical/agent-vault/internal/mitm	3.157s
ok  	github.com/Infisical/agent-vault/internal/netguard	0.454s
ok  	github.com/Infisical/agent-vault/internal/notify	0.096s
ok  	github.com/Infisical/agent-vault/internal/oauth	0.117s
ok  	github.com/Infisical/agent-vault/internal/pidfile	0.070s
ok  	github.com/Infisical/agent-vault/internal/proposal	0.066s
ok  	github.com/Infisical/agent-vault/internal/ratelimit	0.256s
ok  	github.com/Infisical/agent-vault/internal/server	2.983s
ok  	github.com/Infisical/agent-vault/internal/session	0.081s
ok  	github.com/Infisical/agent-vault/internal/store	22.388s
test rc=0

$ AGENT_VAULT_TEST_POSTGRES_URL=... go test -tags kmsaad -count=1 ./...   (Postgres 16 + SQLite)
FAIL	github.com/Infisical/agent-vault/cmd	4.325s
FAIL	github.com/Infisical/agent-vault/internal/aadmigrate [build failed]
FAIL	github.com/Infisical/agent-vault/internal/auth	1.536s
FAIL	github.com/Infisical/agent-vault/internal/auth/kmscontract [build failed]
FAIL	github.com/Infisical/agent-vault/internal/bootstrap [build failed]
ok  	github.com/Infisical/agent-vault/internal/broker	0.111s
FAIL	github.com/Infisical/agent-vault/internal/broker/methodcontract [build failed]
FAIL	github.com/Infisical/agent-vault/internal/brokercore	0.326s
FAIL	github.com/Infisical/agent-vault/internal/ca	0.195s
ok  	github.com/Infisical/agent-vault/internal/catalog	0.265s
ok  	github.com/Infisical/agent-vault/internal/crypto	0.359s
FAIL	github.com/Infisical/agent-vault/internal/crypto/aadcontract [build failed]
FAIL	github.com/Infisical/agent-vault/internal/identity [build failed]
ok  	github.com/Infisical/agent-vault/internal/infisical	0.397s
ok  	github.com/Infisical/agent-vault/internal/isolation	4.189s
FAIL	github.com/Infisical/agent-vault/internal/mitm	2.953s
FAIL	github.com/Infisical/agent-vault/internal/netguard	0.459s
ok  	github.com/Infisical/agent-vault/internal/notify	0.123s
ok  	github.com/Infisical/agent-vault/internal/oauth	0.145s
ok  	github.com/Infisical/agent-vault/internal/pidfile	0.104s
ok  	github.com/Infisical/agent-vault/internal/proposal	0.074s
ok  	github.com/Infisical/agent-vault/internal/ratelimit	0.253s
FAIL	github.com/Infisical/agent-vault/internal/server	10.006s
ok  	github.com/Infisical/agent-vault/internal/session	0.086s
ok  	github.com/Infisical/agent-vault/internal/store	22.325s
tagged rc=1

Top-level kmsaad results in the packages that compile today:
--- PASS: TestKMSAAD_FakeAWSKMS_KnownPositive
--- FAIL: TestKMSAAD_Startup_FreshStore_WrapsDEKWithKMS_AndUnwrapsOnRestart
--- FAIL: TestKMSAAD_Startup_EncryptionContextChanged_Refused
--- FAIL: TestKMSAAD_Startup_KeyIDChanged_Refused
--- FAIL: TestKMSAAD_Startup_KMSDownOnRestart_FailsClosed
--- FAIL: TestKMSAAD_Startup_KMSUnavailableOnFreshStore_NoFallback
--- FAIL: TestKMSAAD_Startup_UnwrappedDEKRecord_RefusedWhenKMSRequired
--- FAIL: TestKMSAAD_Startup_PasswordWrappedDEKRecord_RefusedWhenKMSRequired
--- FAIL: TestKMSAAD_SentinelIsAADBound
--- FAIL: TestKMSAAD_SentinelSwapFromCredentialRefused
--- FAIL: TestKMSAAD_PasswordWrappedDEKIsAADBound
--- PASS: TestKMSAAD_OAuthRefresh_Control
--- FAIL: TestKMSAAD_OAuthRefresh_CrossRowRefreshTokenSwapRefused
--- FAIL: TestKMSAAD_OAuthRefresh_CrossVaultRefreshTokenSwapRefused
--- FAIL: TestKMSAAD_OAuthRefresh_ClientSecretIntoRefreshTokenRefused
--- FAIL: TestKMSAAD_OAuthRefresh_OldVersionReplayRefused
--- FAIL: TestKMSAAD_OAuthRefresh_ErrorBodyNotPersisted
--- FAIL: TestKMSAAD_CAKeyFileSwapFromCredentialCiphertextRefused
--- FAIL: TestKMSAAD_CAStateSwapFromCredentialCiphertextRefused
--- FAIL: TestKMSAAD_NewCAKeyIsAADBound
--- PASS: TestKMSAAD_IdentityGoldenVectorIsCorrect
--- FAIL: TestKMSAAD_RetryPath_IdentityDescribesFinalCredential
--- FAIL: TestKMSAAD_PathNormalization_MatchesWhatIsForwarded
--- FAIL: TestKMSAAD_EchoScrub_ResponseHeadersBodyAndLogs
--- FAIL: TestKMSAAD_EchoScrub_RetryPath
--- FAIL: TestKMSAAD_WriteHold_PatchPagesRefused_GetAllowed
--- FAIL: TestKMSAAD_WriteHold_EmptyMethodsDeniesAll
--- FAIL: TestKMSAAD_Wildcard_SingleSegmentOnly
--- FAIL: TestKMSAAD_Wildcard_MiddleSegment
--- FAIL: TestKMSAAD_HeaderHygiene_SpoofedIdentityStripped
--- FAIL: TestKMSAAD_FargateCredentialsEndpointAlwaysBlocked
--- FAIL: TestKMSAAD_FargateEndpointBlockedViaEnv
--- FAIL: TestKMSAAD_RegisterRefusedOnceAUserExists
--- PASS: TestKMSAAD_ExecutorTokenPrivilegeChecks
--- FAIL: TestKMSAAD_RequireTokenExpiry_MintingRefusesNilExpiry
--- FAIL: TestKMSAAD_RequireTokenExpiry_AuthRefusesExistingNoExpiryToken
--- FAIL: TestKMSAAD_CredentialStoreSwitchingDisabled
--- FAIL: TestKMSAAD_ProxyWhoami
--- PASS: TestKMSAAD_LogScanner_KnownPositive
--- PASS: TestKMSAAD_NoSecretInLogs_CredentialCreateUpdate
--- FAIL: TestKMSAAD_NoSecretInLogs_OAuthCallback
--- FAIL: TestKMSAAD_API_RowSwapSameVaultRefused
--- FAIL: TestKMSAAD_API_CrossVaultSwapRefused
--- FAIL: TestKMSAAD_API_OldCiphertextReplayRefused
--- FAIL: TestKMSAAD_API_OAuthRefreshIntoAccessSlotRefused
--- FAIL: TestKMSAAD_API_ProposalCiphertextSwapRefused
--- FAIL: TestKMSAAD_WriteOnly_OwnerRevealRefusedOrMetadataOnly
--- FAIL: TestKMSAAD_WriteOnly_NoStoredValueInAnyResponseBody

First failure line per assertion site (postgres and sqlite subtests report the same line):
        kms_startup_kmsaad_test.go:331: first startup in KMS mode (AGENT_VAULT_KMS_KEY_ID set, AGENT_VAULT_REQUIRE_KMS=1, no password) failed; expected a new DEK wrapped by KMS: password input: reading password: operation not supp
        kms_startup_kmsaad_test.go:386: first startup in KMS mode (AGENT_VAULT_KMS_KEY_ID set, AGENT_VAULT_REQUIRE_KMS=1, no password) failed; expected a new DEK wrapped by KMS: password input: reading password: operation not supp
        kms_startup_kmsaad_test.go:400: first startup in KMS mode (AGENT_VAULT_KMS_KEY_ID set, AGENT_VAULT_REQUIRE_KMS=1, no password) failed; expected a new DEK wrapped by KMS: password input: reading password: operation not supp
        kms_startup_kmsaad_test.go:414: first startup in KMS mode (AGENT_VAULT_KMS_KEY_ID set, AGENT_VAULT_REQUIRE_KMS=1, no password) failed; expected a new DEK wrapped by KMS: password input: reading password: operation not supp
        kms_startup_kmsaad_test.go:438: startup succeeded with AGENT_VAULT_REQUIRE_KMS=1 and KMS unreachable (fell back to another unlock mode)
        kms_startup_kmsaad_test.go:445: a master key record was persisted without KMS (dek_plaintext=false, password-wrapped=true)
        kms_startup_kmsaad_test.go:467: unlockOrSetup started from a dek_plaintext record although AGENT_VAULT_REQUIRE_KMS=1
        kms_startup_kmsaad_test.go:471: unlockOrSetupWithPassword started from a dek_plaintext record although AGENT_VAULT_REQUIRE_KMS=1
        kms_startup_kmsaad_test.go:492: unlockOrSetup started from a password-wrapped DEK although AGENT_VAULT_REQUIRE_KMS=1
        kms_startup_kmsaad_test.go:496: unlockOrSetupWithPassword started from a password-wrapped DEK although AGENT_VAULT_REQUIRE_KMS=1
    kmsaad_sentinel_test.go:24: sentinel opens with nil AAD ("agent-vault-master-key-check"); it is not bound to master_key/sentinel
    kmsaad_sentinel_test.go:43: a nil-AAD ciphertext of the sentinel string was accepted as the master_key sentinel
    kmsaad_sentinel_test.go:57: password-wrapped DEK opens with nil AAD; it is not bound to master_key/dek
    kmsaad_oauth_swap_test.go:196: credential A's refresh token was decrypted from credential B's row and sent to B's token endpoint
    kmsaad_oauth_swap_test.go:214: vault-1's refresh token was accepted from vault-2's row and sent to vault-2's token endpoint
    kmsaad_oauth_swap_test.go:237: client_secret_ct decrypted as refresh_token_ct (cross-field swap accepted)
    kmsaad_oauth_swap_test.go:267: restored (older-version) refresh_token_ct was accepted and sent to the token endpoint
    kmsaad_oauth_swap_test.go:291: last_refresh_error persisted a secret from the token endpoint body: "oauth: token endpoint returned 400: {\"error\":\"invalid_grant\",\"error_description\":\"refresh_token SENTINEL-AV-TEST-0351-r
    kmsaad_oauth_swap_test.go:294: Inject error carries a secret from the token endpoint body: brokercore: referenced credential missing or undecryptable: brokercore: oauth token refresh failed: oauth: token endpoint returned 400:
    kmsaad_ca_swap_test.go:74: CA loaded an attacker root whose key is a credential-path ciphertext (root CN "attacker root SENTINEL-AV-TEST-0501")
    kmsaad_ca_swap_test.go:98: DB-backed CA loaded an attacker root whose key is a credential-path ciphertext (root CN "attacker root SENTINEL-AV-TEST-0501")
    kmsaad_ca_swap_test.go:110: new CA root key opens with nil AAD
    kmsaad_proxy_echo_test.go:123: no X-Agent-Vault-Credential-Identity on a plain proxied response
    kmsaad_proxy_echo_test.go:170: dot-dot escape (/v1/pages/abc/../../users/me): forwarded with the credential as "GET /v1/pages/abc/../../users/me auth=Bearer SENTINEL-AV-TEST-0601-notion"; the single-segment match must run on t
    kmsaad_proxy_echo_test.go:173: dot-dot escape (/v1/pages/abc/../../users/me): status 200, want 403 or 400
    kmsaad_proxy_echo_test.go:256: single attempt: bearer base64 form of the injected credential present in response body
    kmsaad_proxy_echo_test.go:266: 401 retry: bearer base64 form of the injected credential present in response body
        kmsaad_proxy_rules_test.go:153: PATCH /v1/pages/{id} reached the upstream ("PATCH /v1/pages/abc123 auth=Bearer SENTINEL-AV-TEST-0601-notion") although the service allows only GET
        kmsaad_proxy_rules_test.go:156: PATCH /v1/pages/{id} through the proxy = 200, want 403
    kmsaad_proxy_rules_test.go:167: GET with methods=[] = 200 (upstream saw GET: true); an explicitly empty allowlist must deny
    kmsaad_proxy_rules_test.go:180: /v1/pages/* matched a multi-segment path and forwarded it with the credential ("GET /v1/pages/abc/children/secret auth=Bearer SENTINEL-AV-TEST-0601-notion")
    kmsaad_proxy_rules_test.go:183: GET /v1/pages/abc/children/secret = 200, want 403 under deny policy
    kmsaad_proxy_rules_test.go:193: /v1/blocks/*/children matched /v1/blocks/a/b/children (status 200)
        kmsaad_proxy_rules_test.go:239: X-Agent-Vault-Credential-Identity has 2 values ["spoofed-by-upstream" "spoofed-twice"], want exactly 1
        kmsaad_proxy_rules_test.go:259: X-Agent-Vault-Credential-Identity has 2 values ["spoofed-by-upstream" "spoofed-twice"], want exactly 1
    kmsaad_fargate_test.go:28: allow private ranges: 169.254.170.2 (ECS/Fargate credentials endpoint) is not blocked
    kmsaad_fargate_test.go:31: allow private ranges: dial to 169.254.170.2:80 permitted
    kmsaad_fargate_test.go:44: 169.254.170.2 reachable with AGENT_VAULT_ALLOW_PRIVATE_RANGES=true
        kmsaad_policy_test.go:57: POST /v1/auth/register with an existing owner = 201, want 403: {"email":"intruder@example.test","email_sent":false,"message":"Account created. Ask your Agent Vault instance owner for the verificat
        kmsaad_policy_test.go:60: a user row was created by open registration (active=false)
        kmsaad_policy_test.go:101: POST /v1/agents minted a token with no expiry under AGENT_VAULT_REQUIRE_TOKEN_EXPIRY=1 (status 201)
        kmsaad_policy_test.go:104: agent row created although minting must be refused
        kmsaad_policy_test.go:111: POST /v1/agents/{name}/rotate minted a token with no expiry under AGENT_VAULT_REQUIRE_TOKEN_EXPIRY=1 (status 200)
        kmsaad_policy_test.go:125: API accepted a token with no expiry under AGENT_VAULT_REQUIRE_TOKEN_EXPIRY=1 (status 200)
        kmsaad_policy_test.go:128: proxy accepted a token with no expiry under AGENT_VAULT_REQUIRE_TOKEN_EXPIRY=1 (scope &{AgentID:33b8f7f1-83d1-4706-8368-c7dd27f43901 UserID: VaultID:00000000-0000-0000-0000-000000000000 VaultName
        kmsaad_policy_test.go:141: PATCH /v1/vaults/default/credential-store {"kind":"builtin"} as owner = 200, want 403 or 404
        kmsaad_policy_test.go:196: proxy-port whoami with a valid proxy token = 400: this endpoint is an HTTP forward proxy; non-CONNECT requests must use absolute-form URLs (http://host/path). Use CONNECT for https:// upstreams.
            kmsaad_policy_test.go:343: callback redirect Location carries secret material (lands in browser history and access logs): http://127.0.0.1:14321/oauth/complete?status=error&message=Token+exchange+failed%3A+oauth%3A+tok
        kmsaad_swap_test.go:73: same-vault row swap: default/B_KEY injects the swapped-in secret into upstream requests
        kmsaad_swap_test.go:87: cross-vault swap (same key name): default/SAME_KEY injects the swapped-in secret into upstream requests
        kmsaad_swap_test.go:103: ciphertext-only rollback to an earlier version: default/ROTATED_KEY injects the swapped-in secret into upstream requests
        kmsaad_swap_test.go:122: cross-table/field swap refresh_token_ct -> credentials.ciphertext: default/GH_OAUTH injects the swapped-in secret into upstream requests
            kmsaad_swap_test.go:176: approval applied a swapped proposal ciphertext: P_TWO now injects "SENTINEL-AV-TEST-0742-p1" (approve status 200)
            kmsaad_swap_test.go:179: approve of a proposal with a tampered ciphertext returned 200
        kmsaad_writeonly_test.go:47: owner GET /v1/credentials?vault=default&reveal=true returned stored field "value"="SENTINEL-AV-TEST-1302-access"; keys are write-only
        kmsaad_writeonly_test.go:99: stored values returned by read endpoints to an owner session: [http responses: SENTINEL-AV-TEST-1311-static http responses: SENTINEL-AV-TEST-1312-access]

Compile errors in the contract packages (distinct):
internal/aadmigrate/aadmigrate_kmsaad_test.go: c.Version undefined (type *store.Credential has no field or method Version)
internal/aadmigrate/aadmigrate_kmsaad_test.go: o.Version undefined (type *store.CredentialOAuth has no field or method Version)
internal/aadmigrate/aadmigrate_kmsaad_test.go: undefined: IsComplete
internal/aadmigrate/aadmigrate_kmsaad_test.go: undefined: Run
internal/aadmigrate/aadmigrate_kmsaad_test.go: undefined: crypto.AAD
internal/aadmigrate/aadmigrate_kmsaad_test.go: undefined: crypto.DecryptAAD
internal/auth/kmscontract/kms_contract_test.go: undefined: auth.SetupWithKMS
internal/auth/kmscontract/kms_contract_test.go: undefined: auth.UnlockWithKMS
internal/bootstrap/bootstrap_kmsaad_test.go: undefined: Apply
internal/bootstrap/bootstrap_kmsaad_test.go: undefined: Options
internal/bootstrap/bootstrap_kmsaad_test.go: undefined: RotateIfDue
internal/bootstrap/bootstrap_kmsaad_test.go: undefined: RunRotationLoop
internal/broker/methodcontract/method_contract_test.go: svcs[0].Methods undefined (type broker.Service has no field or method Methods)
internal/broker/methodcontract/method_contract_test.go: undefined: broker.ValidateMethods
internal/broker/methodcontract/method_contract_test.go: unknown field Methods in struct literal of type broker.Service
internal/crypto/aadcontract/aad_contract_test.go: undefined: crypto.AAD
internal/crypto/aadcontract/aad_contract_test.go: undefined: crypto.DecryptAAD
internal/crypto/aadcontract/aad_contract_test.go: undefined: crypto.EncryptAAD
internal/identity/identity_kmsaad_test.go: undefined: NotionDigest
```

## Related

- `internal/crypto/crypto.go`, the nil-AAD seal and open this patch replaces.
- `cmd/server.go`, the unlock entry points the KMS tests drive.
- `internal/store/20260617143022_postgres_baseline.go`, the deployment schema.
