# Vault extension `.nokv` + trailing-slash default output (design)

**Date:** 2026-09-10  
**Status:** Approved for implementation  
**Target release:** 0.4.1  
**Branch:** `fix/nokv-ext-and-trailing-slash`

## Goal

1. New encrypted outputs use the `.nokv` suffix (files and directory trees).
2. Readers accept both `.nokv` and legacy `.nokvault`.
3. Default output path no longer treats a trailing slash as “inside the tree” (`encrypt test/` must yield sibling `test.nokv`, not `test/.nokvault`).
4. Leave config as `.nokvault.toml`. Leave wire magic as `NOKVAULT`.

## Non-goals

- Renaming `.nokvault.toml`
- Format / header bump
- Deleting plaintext after encrypt
- Forced migration/rename of existing on-disk files

## Design

### Shared helpers (`internal/utils/vault_path.go`)

| Symbol | Behavior |
| --- | --- |
| `VaultExt` | `".nokv"` (write default) |
| `LegacyVaultExt` | `".nokvault"` (read accept) |
| `IsVaultPath(path)` | true if base name ends with either ext |
| `StripVaultExt(path)` | remove either suffix; error/empty if neither |
| `HasVaultExt(name)` | suffix check for walk filters |
| `WithVaultExt(path)` | append `VaultExt` to cleaned base (no double-append) |
| `DefaultVaultOutput(input)` | `filepath.Clean(input)` then append `VaultExt`; if Clean is `.` or `..`, return error asking for a concrete path or `-o` |

### Call sites

- `encrypt` / `watch` / `schedule`: default output via `DefaultVaultOutput`
- `decrypt`: default strip via `StripVaultExt` when input is a vault path; directory walk via `IsVaultPath` / `HasVaultExt`
- `directory.go` encrypt: join with `VaultExt`; decrypt: recognize both
- `path_policy.go`: map relative paths with current write ext; recognize both on decrypt preflight

Explicit `--output` / `-o` is never rewritten by these helpers.

### Docs / site

Update examples to `.nokv`. One short note that `.nokvault` remains readable. Do not rename config docs.

### Tests

- `DefaultVaultOutput("test/")` → `test.nokv` (OS-correct separator)
- `DefaultVaultOutput(".")` errors
- Encrypt default writes `.nokv`
- Decrypt accepts legacy `.nokvault` file/dir layout
- Config name still `.nokvault`

## Success

`encrypt test/` creates sibling `test.nokv/`; new files end in `.nokv`; old `.nokvault` still decrypts; docs match; green tests.
