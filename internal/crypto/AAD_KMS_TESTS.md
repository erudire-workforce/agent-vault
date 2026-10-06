# Synced-value AAD and KMS key-state tests (test-first)

Base: `claude/fork-review-fixes` at `25b1605b6880aa6967167efca02a8ceeff899722`. The new tests carry
`//go:build aadkms`, so CI stays green until the fixes land. Run them with:

```
go test -tags aadkms ./internal/infisical/ ./cmd/
```

The implementer removes the tag from a file in the change that makes its tests pass.

| Test | Why it fails at 25b1605b |
|---|---|
| `infisical` `TestEncryptSecrets_RoundTripWithRowAAD` | does not compile: `EncryptSecrets` has no `vaultID` argument. Against today's nil-AAD seal (checked through a local adapter) the value does not open with `CredentialValueAAD(vault, key, 0)` |
| `infisical` `TestEncryptSecrets_ValueBoundToVaultKeyAndVersion` | same compile failure. A value sealed for vault A, key K must not open as vault B, as key K2, at version 1, or as another table. A local mutant sealed at the wrong version was shown to be flagged |
| `cmd` `TestAADKMS_FreshStartupRefusesKeyNotEnabled` | startup never calls DescribeKey. A key in the `Disabled`, `PendingDeletion` or `PendingImport` state sets up and persists a master key record |
| `cmd` `TestAADKMS_RestartRefusesKeyNotEnabled` | a restart unwraps the DEK although the key is no longer Enabled |
| `cmd` `TestAADKMS_DescribeKeyFailureRefusesStartup` | startup proceeds although DescribeKey fails (`AccessDeniedException`) |
| `cmd` `TestAADKMS_FakeDescribeKeyReportsState` | passes: this is the known-positive check, showing the fake reports each state and fails on request |

**Superseded test.** `TestEncryptSecrets_RoundTrip` (formerly `internal/infisical/sync_test.go:259`)
decrypted with nil AAD. It is replaced by the stricter `TestEncryptSecrets_RoundTripWithRowAAD`.

**Call sites to update with the new signature.** `EncryptSecrets(vaultID, secs, dek)` changes
these, without changing any assertion:
- `TestEncryptSecrets_RejectsEmptyKey` and `TestEncryptSecrets_RejectsNonUpperSnakeKey` in
  `sync_test.go`;
- the caller in `sync.go`.
