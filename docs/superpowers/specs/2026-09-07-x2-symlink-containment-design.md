# X2: Symlink and output-containment policy

**Date:** 2026-09-07  
**Status:** Approved  
**Roadmap:** X2 (NV-017, NV-030)  
**Branch:** `feat/x2-symlink-containment`

## Goals

1. Fail closed when any file operation encounters a symlink, including a symlinked root or existing parent component.
2. Prevent directory output paths from escaping their selected output root.
3. Apply one shared policy across encrypt, decrypt, rotate-key, secure-delete, watch, schedule, and keyfiles.
4. Add cross-platform tests and update all affected documentation in the same PR.

## Non-goals

- A `--follow-symlinks` opt-in.
- Silently skipping symlinks.
- Resolving symlinks and allowing those whose targets appear contained.
- OS-specific descriptor traversal (`openat` / `O_NOFOLLOW`) against hostile concurrent path replacement.
- Archive extraction policy (`protect` remains separate X3 work).

## Decisions

| Topic | Choice |
|-------|--------|
| Input symlink | Abort the entire operation and report the symlink path |
| Root symlink | Reject |
| Nested symlink | Reject; do not skip or follow |
| Output symlink | Reject the output leaf and every existing parent component |
| Follow opt-in | None in X2 |
| Containment | Lexical `filepath.Rel` verification after cleaning; never string-prefix matching |
| Architecture | Shared `internal/utils` path-safety helpers used by core and CLI |

## Design

### Shared path safety (`internal/utils/path_safety.go`)

Add:

- `ValidateNoSymlinkComponents(path string) error`
  - Convert to an absolute, cleaned path.
  - Walk upward with `os.Lstat` from the leaf to the volume/root.
  - Missing components are allowed for future output paths; continue checking existing ancestors.
  - Return `SYMLINK_DISALLOWED` naming the first symlink encountered.
  - Propagate permission and unexpected filesystem errors.
- `SafeJoin(root, relative string) (string, error)`
  - Reject absolute `relative` values.
  - Clean the relative path.
  - Reject `..` and any cleaned path beginning with `..` plus a separator.
  - Join to an absolute, cleaned root.
  - Re-check with `filepath.Rel(root, joined)` and reject escape.
  - Run `ValidateNoSymlinkComponents` on the root and joined output.
  - Return `PATH_ESCAPE` for containment failures.

Add common `ErrSymlinkDisallowed` and `ErrPathEscape` error codes and actionable hints.

### Directory traversal

`FileHandler.WalkDirectory`:

1. Validate all existing components of the root before walking.
2. `filepath.Walk` already obtains entries with `Lstat`; if an entry has `ModeSymlink`, return `SYMLINK_DISALLOWED` before invoking the caller callback.
3. An encountered symlink aborts counting, preflight, encryption, decryption, or secure deletion consistently.

`CountFiles` and `GetTotalSize` inherit the same behavior through `WalkDirectory`.

### Output construction

Replace directory-output `filepath.Join(outputRoot, relativePath)` calls with `utils.SafeJoin` in:

- CLI directory encrypt preflight.
- `core.DirectoryEncryptor`.
- CLI directory decrypt.
- `core.DirectoryDecryptor`.

Validate an output root before `MkdirAll`; after directory creation, validate it again before writing. This prevents an existing symlink component from redirecting output. Atomic no-replace/force policy from X1 remains unchanged.

### Single-path commands

Before any read, overwrite, or deletion:

- Encrypt/decrypt validate input and output path components.
- Rotate-key validates its input path components.
- Secure-delete validates root path components; nested traversal is covered by `WalkDirectory`.
- Schedule validates the configured path on each run.
- Watch validates the watched root and uses `Lstat` plus component validation for every event; symlink events are rejected and never encrypted.
- Keyfile reads use the shared component validator, strengthening the existing leaf-only symlink rejection.

Errors are fail-closed. Verbose watch mode reports rejected symlink events; non-verbose mode remains quiet.

### Race boundary

X2 prevents following symlinks present during validation and walking. Fully preventing a privileged local attacker from replacing path components between validation and open requires descriptor-relative OS-specific APIs and is explicitly outside this cross-platform change. X1 atomic no-replace commits still protect output-file replacement races.

## Testing

### Unit

- `ValidateNoSymlinkComponents`: regular path, symlink leaf, symlink parent, missing output leaf, filesystem error.
- `SafeJoin`: normal nested path, absolute path, `..`, nested `../`, sibling prefix trap, symlinked root, symlinked parent.
- `WalkDirectory`: root symlink and nested file/directory symlink abort with the symlink path.

### Integration

- Single-file encrypt rejects a symlink input.
- Directory encrypt aborts on a nested file symlink and creates no ciphertext for it.
- Directory decrypt rejects a symlinked output parent.
- Secure-delete rejects a symlink and leaves both link and target untouched.
- Watch callback ignores/rejects symlink events.

On Windows, tests attempt `os.Symlink`; if the environment lacks symlink privilege/support, only those tests skip with the OS error. Containment tests run everywhere.

## Documentation

- README command/security notes.
- Command reference and security/best-practices pages.
- CHANGELOG Unreleased.
- Local ignored ROADMAP: mark X2 done after merge.

## Acceptance

- [ ] No supported command follows a symlink input or writes through a symlinked output component.
- [ ] Directory output construction rejects absolute and parent-escaping relative paths.
- [ ] Errors identify the rejected path and policy.
- [ ] Tests pass on Windows, Linux, and macOS; unsupported Windows symlink creation skips only symlink-specific tests.
- [ ] Docs and CHANGELOG accurately describe default-deny behavior and the concurrent-replacement boundary.
