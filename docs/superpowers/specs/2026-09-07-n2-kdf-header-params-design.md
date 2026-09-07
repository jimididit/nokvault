# N2: Persist KDF parameters in on-disk format + apply config

**Date:** 2026-09-07  
**Status:** Draft for review  
**Roadmap:** N2 (NV-002, NV-003, NV-012 deferred, NV-027)  
**Branch (planned):** `feat/kdf-header-params`

---

## Problem

Today’s `.nokvault` header stores magic, version, salt, metadata size, and data offset only (`CurrentVersion = 1`). Decrypt always derives with process-local `DefaultArgon2Params()`. Config `key_derivation` is loaded in `Execute` but discarded - never applied via `KeyManager.SetParams`. Changing defaults or config would silently break decrypt of existing files (or leave config as a lie).

## Goals

1. New files record Argon2id memory / time / parallelism / key length in the header.
2. Decrypt uses **header** params (v1 → historical defaults), never live config.
3. Encrypt / rotate / watch / schedule apply loaded config KDF params for **new** keys only.
4. Keep v1 files decryptable forever.
5. Update the docs site where usage/config claims change.

## Non-goals (this PR)

- Compress flag or cipher/KDF algorithm IDs in the header (NV-012 / alg IDs → later bump).
- Authenticating header params as AEAD AAD.
- Changing default Argon2 strength.
- Adding `key_length` to TOML schema (keep crypto default 32).
- Wiring dead `encryption.algorithm` / `chacha20` (X4).

---

## Format design

### Version policy

| Version | Behavior |
|---------|----------|
| **1** | Existing layout. Decrypt derives with `DefaultArgon2Params()` (64 MiB / t=3 / p=4 / keylen=32). |
| **2** | Extended header (below). Decrypt derives with params from header. |
| **other** | Reject with clear “unsupported version” error. |

`CurrentVersion` becomes **2**. All new writes (encrypt, rotate-key rewrite, watch, directory encrypt) emit v2.

### Binary layout (little-endian)

**v1** (unchanged size; `binary.Size` of current struct):

```
Magic[8] | Version u16 | Salt[16] | MetadataSize u32 | DataOffset u64
```

**v2** appends after those fields:

```
Memory u32 | Time u32 | Parallelism u8 | _pad[3] | KeyLength u32
```

- `_pad[3]` keeps natural alignment for `KeyLength` and stable `binary.Size`.
- `DataOffset` continues to mean “byte offset of ciphertext from start of file” (= sizeof(header for this version) + MetadataSize).
- Readers: peek/read `Version` first (or read common prefix), then parse the rest for that version. Do **not** decode a v1 file with a v2 struct (would consume metadata/ciphertext as params).

### Semantics

- Params in the header are **not** secret; they must be known to derive the key. Integrity still depends on AES-GCM over the payload (wrong params → auth failure / garbage), not on MAC of the header itself.
- Reject obviously unsafe params on read/write (e.g. memory 0, time 0, parallelism 0, keylen ≠ 32 for now) with a clear error - avoid DoS via absurd memory if we later allow larger values; for this PR, allow values in a documented sane range matching config (at minimum: non-zero; optionally cap memory).

---

## Config wiring

### Load once, apply for encrypt-side

- `Execute` already calls `config.NewConfigManager().Load()` but drops the result.
- Introduce a small package-level (or passed) handle: after load, store `*config.Config` accessible to CLI commands (pattern: `cli.SetRuntimeConfig` / `GetRuntimeConfig`, reset in tests via existing `ResetCLIStateForTest`).
- When constructing `KeyManager` / `EncryptionService` for encrypt, rotate, watch, schedule: call `SetParams(cfg.KeyDerivation.MemoryCost, TimeCost, Parallelism, crypto.DefaultKeyLength)`.
- Decrypt paths: after `ReadHeaderWithMetadata`, build params from header (or defaults for v1), then `DeriveKeyFromPasswordAndSalt` with those params - **do not** use runtime config for decrypt.

### Config schema

Keep existing TOML:

```toml
[key_derivation]
algorithm = "argon2id"
memory_cost = 65536
time_cost = 3
parallelism = 4
```

Docs site currently invents `[argon2]` / `argon2.iterations` - fix docs to match real keys (see Documentation).

---

## Code touch points (expected)

| Area | Change |
|------|--------|
| `internal/core/file_handler.go` | Versioned header types; WriteHeader writes v2 + params; ReadHeader supports v1+v2 |
| `internal/core/key_manager.go` | Optional helper to apply `Argon2Params`; decrypt helpers take params |
| `internal/core/encryption.go` / directory / CLI encrypt·decrypt·rotate·watch | Pass params; write/read correctly |
| `internal/cli/root.go` (+ testing reset) | Retain loaded config; apply on encrypt-side |
| Tests | Header unit tests; integration encrypt-with-custom-params; v1 fixture still decrypts |
| `CHANGELOG.md`, `ROADMAP.md` | N2 status; Unreleased notes |
| `docs/src/...` | Configuration + security/FAQ as needed |

---

## Documentation policy (repo rule for this and future PRs)

**Prefer: update `/docs` in the same PR, in a final docs pass after behavior is stable** - not mid-implementation thrash, and not a separate forgotten PR.

For N2 specifically, before merge update:

1. **`docs/src/pages/docs/configuration.astro`** - Align TOML/`--set` examples with real `key_derivation.*` keys; state that KDF settings apply to **new** encryptions only; decrypt always uses params stored in the file.
2. **`docs/src/pages/docs/security.astro`** (and FAQ if it claims “configurable” without caveats) - Note that Argon2 params are persisted in the file header (v2); older files use built-in defaults.
3. **`docs/src/pages/docs/changelog.astro`** - Mirror Unreleased/CHANGELOG entry if that page is manually maintained.
4. Root **`CHANGELOG.md`** + short format note (README or `HELP_DOCS` format sketch) for contributors.

Also fix any **false** config examples already on the site (they currently do not match `internal/config/settings.go`).

---

## Testing

1. **Unit:** WriteHeader/ReadHeader v2 round-trip; v1 bytes still parse; unsupported version errors.
2. **Unit/integration:** Encrypt with non-default memory/time → file header carries them → decrypt succeeds; decrypt forcing wrong params fails closed (GCM/auth).
3. **Compat:** Keep or add a tiny v1 ciphertext fixture; decrypt with current code.
4. **Config:** Load custom `key_derivation` and assert encrypt path uses it (CLI or core-level).
5. **`go test ./...`** green; docs build job still passes.

## Risks & mitigations

| Risk | Mitigation |
|------|------------|
| `binary.Size` / DataOffset mismatch | Version-specific sizeof; tests assert DataOffset |
| Breaking v1 | Explicit dual-path reader; fixture test |
| Config applied to decrypt | Code review + test that config change doesn’t affect existing file decrypt |
| Docs drift again | Same-PR docs pass + examples matching `DefaultConfig()` |

## Success criteria

- [ ] New `.nokvault` files are version 2 and carry KDF params.
- [ ] v1 files still decrypt.
- [ ] Config `key_derivation` affects new encrypts.
- [ ] Decrypt ignores config, uses header/defaults.
- [ ] Docs site configuration/security text matches reality.
- [ ] CI green; N2 marked done on roadmap after merge.
