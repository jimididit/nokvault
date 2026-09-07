# X1 Destructive-op UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Gate `secure-delete` with TTY confirm/`--yes`/`--dry-run`, refuse encrypt/decrypt overwrites without `--force`, and add decrypt `--strict` abort-on-first-error.

**Architecture:** Shared helpers in `internal/cli/safety.go` (`requireConfirmation`, `refuseIfExists`, confirm reader). Wire flags into `secure_delete.go`, `encrypt.go`, `decrypt.go`. Directory encrypt preflights output paths in the CLI before calling `DirectoryEncryptor`. Docs + CHANGELOG in the same PR.

**Tech Stack:** Go, Cobra, `golang.org/x/term`, testify, Astro docs.

**Spec:** `docs/superpowers/specs/2026-09-07-x1-destructive-op-ux-design.md`

## Global Constraints

- Non-TTY `secure-delete` requires `--yes` (fail closed).
- `--dry-run` lists file paths only; no disk mutation; no `--yes` required.
- Confirm accepts exact `yes` (trim, case-insensitive).
- Overwrite: refuse if output exists unless `--force` (encrypt + decrypt; not rotate-key/watch/schedule).
- `--strict`: abort directory decrypt on first failure; leave already-written files.
- Branch: `feat/x1-destructive-op-ux` (already created).
- After Go changes: `graphify update .`.
- Docs site updates in the same PR.
- Commit at task boundaries while executing this plan.

## File map

| File | Responsibility |
|------|----------------|
| `internal/utils/errors.go` | `CONFIRMATION_REQUIRED`, `OUTPUT_EXISTS` |
| `internal/utils/atomic_write.go` | Atomic no-replace commit; force replaces regular files only |
| `internal/utils/atomic_write_test.go` | Existing/concurrent target and directory safety regressions |
| `internal/cli/safety.go` | Helpers |
| `internal/cli/safety_test.go` | Unit tests |
| `internal/cli/secure_delete.go` | `--yes`, `--dry-run` |
| `internal/cli/encrypt.go` | `--force` + preflight |
| `internal/cli/decrypt.go` | `--force`, `--strict` |
| `tests/integration/*` | Flags + force on re-encrypt paths |
| Docs / CHANGELOG / ROADMAP (local) | Usage + notes |

---

### Task 1: Error codes + safety helpers (TDD)

**Files:** Create `internal/cli/safety.go`, `internal/cli/safety_test.go`; modify `internal/utils/errors.go`

**Produces:**
- `func confirmDestructive(r io.Reader, w io.Writer, prompt string) error`
- `func requireConfirmation(yesFlag, interactive bool, r io.Reader, w io.Writer) error`
- `func refuseIfExists(path string, force bool) error`
- `func isInteractive() bool`

- [ ] Write failing unit tests for confirm / requireConfirmation / refuseIfExists
- [ ] Add error vars + hints
- [ ] Implement helpers
- [ ] `go test ./internal/cli/ -count=1` pass
- [ ] Commit: `feat(cli): add destructive-op safety helpers`

### Task 2: secure-delete `--yes` / `--dry-run`

**Files:** `internal/cli/secure_delete.go`; integration test

- [ ] Flags `--yes`/`-y`, `--dry-run`
- [ ] Dry-run path listing; else `requireConfirmation`
- [ ] Integration: no `--yes` fails; `--yes` deletes; `--dry-run` preserves
- [ ] Commit: `feat(cli): gate secure-delete with --yes and --dry-run`

### Task 3: encrypt/decrypt `--force`

**Files:** `encrypt.go`, `decrypt.go`; fix integration tests that overwrite

- [ ] `--force`/`-f` on both
- [ ] `refuseIfExists` before single-file writes
- [ ] Directory encrypt: preflight all `*.nokvault` outputs
- [ ] Directory decrypt: refuse each plaintext output
- [ ] Use atomic no-replace commits when `--force` is absent; reject non-regular targets even with `--force`
- [ ] Commit: `feat(cli): require --force to overwrite encrypt/decrypt outputs`

### Task 4: decrypt `--strict`

**Files:** `decrypt.go`; integration test

- [ ] Flag `--strict`; abort walk on first failure
- [ ] Commit: `feat(cli): add decrypt --strict abort-on-error`

### Task 5: Docs + CHANGELOG + graphify

**Files:** README, docs usage/security pages, CHANGELOG, local ROADMAP, `graphify update .`

- [ ] Document flags; Unreleased CHANGELOG
- [ ] Mark X1 DONE in local ROADMAP
- [ ] Commit: `docs: document X1 --yes/--dry-run/--force/--strict`

---

## Spec coverage

- NV-014 confirm/`--yes` → Task 2  
- `--dry-run` → Task 2  
- NV-015 `--force` → Task 3  
- NV-016 `--strict` → Task 4  
- Shared helpers → Task 1  
- Docs → Task 5  
