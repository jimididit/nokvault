# N3: Stop password-on-argv & harden keyfiles

**Date:** 2026-09-07  
**Status:** Approved  
**Roadmap:** N3 (NV-004, NV-005)  
**Branch:** `feat/n3-password-keyfile`

## Goals

1. Refuse `--password` / `-p` and rotate `--old-password` / `--new-password` when non-empty, with a clear error.
2. Keep prompt, `--keyfile`, and `NOKVAULT_PASSWORD` (document env process-visibility risk).
3. Harden keyfile reads: reject symlinks; on Unix reject group/world-readable modes; document 0600.
4. Migrate tests off argv passwords; update docs in the same PR.
5. Include ROADMAP X9 (docs UI overhaul) note already drafted.

## Non-goals

- Remove `NOKVAULT_PASSWORD`.
- General encrypt-path symlink policy (X2).
- Windows ACL enforcement beyond symlink refusal.

## Design

### GetPassword

Order: keyfile → (refuse if passwordFlag set) → env → prompt.

If `passwordFlag != ""`: return error recommending keyfile / `NOKVAULT_PASSWORD` / interactive prompt.

### Keyfile

`Lstat` first; reject `ModeSymlink`. On non-Windows, reject `mode&0o077 != 0`. Then `ReadFile`; trim trailing `\n` (and `\r\n` if present).

### CLI flags

Leave Cobra flags registered so help can mark them removed/unsafe; runtime refusal in `GetPassword` covers all callers.

### Tests

Unit tests for refusal + keyfile mode/symlink. Integration: `NOKVAULT_PASSWORD` or temp 0600 keyfile.

### Docs

README, security/usage pages: no argv password examples; keyfile 0600; env caveat.
