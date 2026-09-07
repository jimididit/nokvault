# X1: Destructive-op UX & overwrite safety

**Date:** 2026-09-07  
**Status:** Approved  
**Roadmap:** X1 (NV-014, NV-015, NV-016)  
**Branch:** `feat/x1-destructive-op-ux`

## Goals

1. Gate `secure-delete` behind interactive confirmation or `--yes` (fail closed when non-interactive).
2. Add `secure-delete --dry-run` that lists paths that would be deleted without touching disk (no `--yes` required).
3. Refuse encrypt/decrypt when the output path already exists unless `--force`.
4. Add decrypt `--strict` to abort directory decrypt on the first failure (no rollback).
5. Share helpers so policy stays consistent; cover with unit + integration tests; update docs/CHANGELOG in the same PR.

## Non-goals

- `rotate-key` `--force` (in-place vault rewrite stays as today).
- Watch/schedule overwrite policy changes.
- True transactional rollback / secure-wipe of partial decrypt outputs.
- Symlink / path-containment policy (X2).

## Decisions (locked)

| Topic | Choice |
|-------|--------|
| Non-interactive `secure-delete` | Require `--yes`; refuse otherwise |
| Interactive `secure-delete` | Prompt; accept exact `yes` (case-insensitive, trimmed) |
| `secure-delete --dry-run` | List target file path(s) that would be overwritten/deleted; exit 0; never write/unlink; **does not** require `--yes` or TTY confirm |
| Overwrite | Refuse if target exists unless `--force` (no prompt) |
| Directory decrypt errors | Default continue-on-error; `--strict` stop on first failure; leave already-written files |
| Approach | Shared CLI helpers (not duplicated per-command, not Cobra PreRun middleware) |

## Design

### Shared helpers (`internal/cli/safety.go`)

- `isInteractive()` — `term.IsTerminal(int(os.Stdin.Fd()))` (already depend on `golang.org/x/term`).
- `confirmDestructive(r io.Reader, w io.Writer, prompt string) error` — print prompt; read one line; require `yes`.
- `requireConfirmation(yesFlag bool, r io.Reader, w io.Writer) error` — if `yesFlag` OK; else if interactive confirm; else return `CONFIRMATION_REQUIRED` with hint to pass `--yes`.
- `refuseIfExists(path string, force bool) error` — if path exists (`os.Stat`) and `!force`, return `OUTPUT_EXISTS` with hint to pass `--force`. Missing path is OK.

Inject `io.Reader`/`io.Writer` for unit tests; production callers use `os.Stdin`/`os.Stderr` (or stdout for prompts — match existing `PrintInfo` style on stderr/stdout consistently with other CLI messages).

### Flags

| Command | Flag | Default |
|---------|------|---------|
| `secure-delete` | `--yes` / `-y` | false |
| `encrypt` | `--force` / `-f` | false |
| `decrypt` | `--force` / `-f` | false |
| `decrypt` | `--strict` | false |

Note: `secure-delete` already uses `-p` for `--passes`; `-y` is free for `--yes`. Encrypt/decrypt `-f` must not collide with existing short flags (verify at implement time; use long-only if needed).

### Call sites

1. **`runSecureDelete`** — after path exists check, before any overwrite/delete: `requireConfirmation(secureDeleteYes, ...)`.
2. **`encryptFileWithCompression`** — `refuseIfExists(outputPath, encryptForce)` before `AtomicWriteFunc`.
3. **Directory encrypt** — for each output `.nokvault` path (or once per file before write in the encryptor callback / CLI loop): refuse unless `--force`. Prefer checking in CLI/walk layer so core stays flag-agnostic; if encryptor writes internally, pass a `force` bool or preflight walk.
4. **`decryptFile`** — `refuseIfExists(outputPath, decryptForce)` before `AtomicWrite`.
5. **`decryptDirectory` / `decryptSingleFile`** — refuse each output plaintext path unless `--force`. On failure under `--strict`, abort walk (return error from walk callback) instead of `return nil`. Default path unchanged (continue, collect `failedFiles`).

### Errors (`internal/utils/errors.go`)

- `ErrConfirmationRequired` — code `CONFIRMATION_REQUIRED`
- `ErrOutputExists` — code `OUTPUT_EXISTS`

Messages must name the path and the flag to unblock.

### Testing

- Unit (`safety_test.go`): confirm accepts/rejects; non-yes without flag fails when “non-interactive” (inject terminal check or separate `requireConfirmation` with fake `isInteractive`); `refuseIfExists` with/without force.
- Integration: secure-delete without `--yes` fails in CI (non-TTY); with `--yes` deletes; encrypt/decrypt to existing path fails without `--force`, succeeds with `--force`; directory decrypt with a planted bad vault + `--strict` stops early (fewer successes than continue mode).

Update existing integration helpers that re-encrypt to the same `.nokvault` path to pass `--force` where needed.

### Docs

- Site: secure-delete, encrypt/decrypt command pages, advanced/security as needed.
- README: brief bullets for `--yes` / `--force` / `--strict`.
- CHANGELOG: Unreleased Added/Changed.
- Local `ROADMAP.md` (gitignored): mark X1 DONE after merge.

## Acceptance

- [ ] Non-TTY `secure-delete` without `--yes` exits non-zero and does not delete.
- [ ] TTY path prompts; `yes` proceeds; other input aborts.
- [ ] Encrypt/decrypt refuse existing outputs without `--force`.
- [ ] Decrypt `--strict` aborts on first directory failure without deleting prior successes.
- [ ] Docs + CHANGELOG updated; `go test ./...` green.
