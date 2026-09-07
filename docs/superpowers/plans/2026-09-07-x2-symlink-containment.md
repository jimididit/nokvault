# X2 Symlink and Output-Containment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every supported file operation fail closed on symlinks and ensure generated directory outputs remain beneath their selected output root.

**Architecture:** Put reusable validation in `internal/utils/path_safety.go`, then enforce it in `FileHandler.WalkDirectory`, core directory output construction, and CLI single-path entry points. `SafeJoin` uses cleaned absolute paths plus `filepath.Rel`; output component checks use `Lstat`.

**Tech Stack:** Go 1.25, standard library `os`/`filepath`, Cobra, testify, Astro docs.

**Spec:** `docs/superpowers/specs/2026-09-07-x2-symlink-containment-design.md`

## Global Constraints

- Any input symlink—root, nested file, nested directory, or existing parent component—aborts the operation and names the rejected path.
- Reject output leaf and existing output-parent symlinks.
- No `--follow-symlinks` flag and no silent skip behavior.
- Containment uses `filepath.Clean`, `filepath.Abs`, and `filepath.Rel`; never string-prefix matching.
- Missing output components are valid, but all existing ancestors must be checked.
- Descriptor-relative hostile concurrent replacement is outside scope and must be documented.
- Symlink-specific Windows tests may skip only when `os.Symlink` itself reports unavailable privilege/support.
- Run `graphify update .` after Go changes.
- Docs and CHANGELOG ship in this PR.

---

### Task 1: Shared path-safety primitives

**Files:**
- Create: `internal/utils/path_safety.go`
- Create: `internal/utils/path_safety_test.go`
- Modify: `internal/utils/errors.go`

**Interfaces:**
- Produces: `func ValidateNoSymlinkComponents(path string) error`
- Produces: `func SafeJoin(root, relative string) (string, error)`
- Produces: `ErrSymlinkDisallowed` (`SYMLINK_DISALLOWED`) and `ErrPathEscape` (`PATH_ESCAPE`)

- [ ] **Step 1: Write failing table tests**

Tests must cover a regular existing path, missing leaf under regular parents, symlink leaf, symlink parent, normal safe join, absolute relative path, `..`, `../sibling`, sibling-prefix trap, and symlinked output parent. Use a helper that calls `os.Symlink`; skip only when creation fails.

- [ ] **Step 2: Verify RED**

Run: `go test ./internal/utils -run "TestValidateNoSymlinkComponents|TestSafeJoin" -count=1`

Expected: build failure because both functions are undefined.

- [ ] **Step 3: Add errors and implementation**

`ValidateNoSymlinkComponents` must:

```go
absolute, err := filepath.Abs(filepath.Clean(path))
for current := absolute; ; current = filepath.Dir(current) {
    info, statErr := os.Lstat(current)
    if statErr == nil && info.Mode()&os.ModeSymlink != 0 {
        return NewErrorWithHint(ErrSymlinkDisallowed.Code, fmt.Sprintf("Symlink paths are not allowed: %s", current), nil, "Use a regular file or directory path.")
    }
    if statErr != nil && !os.IsNotExist(statErr) { return statErr }
    parent := filepath.Dir(current)
    if parent == current { break }
}
```

`SafeJoin` must reject absolute/escaping relatives, verify containment via `filepath.Rel`, validate root and joined components, and return the cleaned absolute joined path.

- [ ] **Step 4: Verify GREEN and commit**

Run: `go test ./internal/utils -count=1`

Commit: `feat(utils): add symlink and containment guards`

---

### Task 2: Harden directory traversal and core output construction

**Files:**
- Modify: `internal/core/file_handler.go`
- Modify: `internal/core/file_handler_test.go`
- Modify: `internal/core/directory.go`
- Modify: `internal/core/directory_test.go`

**Interfaces:**
- Consumes: `utils.ValidateNoSymlinkComponents`, `utils.SafeJoin`
- Produces: `WalkDirectory` that rejects root/nested symlinks before callbacks

- [ ] **Step 1: Add failing traversal tests**

Create root-symlink and nested file/directory-symlink cases. Assert `WalkDirectory` returns `SYMLINK_DISALLOWED`, includes the link path, and never invokes the callback for that link.

- [ ] **Step 2: Verify RED**

Run: `go test ./internal/core -run "TestFileHandler_WalkDirectory.*Symlink" -count=1`

Expected: current walk accepts file symlinks.

- [ ] **Step 3: Enforce traversal policy**

Validate the root before `filepath.Walk`. In its callback, propagate walk errors, reject `info.Mode()&os.ModeSymlink != 0`, then call the supplied callback.

- [ ] **Step 4: Replace generated output joins**

Use `utils.SafeJoin` in `DirectoryEncryptor` and `DirectoryDecryptor`. Validate output roots before and after `EnsureDirectory`. Return errors with source-relative context.

- [ ] **Step 5: Verify and commit**

Run: `go test ./internal/core -count=1`

Commit: `feat(core): reject symlink traversal and contain directory outputs`

---

### Task 3: Apply policy to CLI file operations

**Files:**
- Modify: `internal/cli/encrypt.go`
- Modify: `internal/cli/decrypt.go`
- Modify: `internal/cli/rotate_key.go`
- Modify: `internal/cli/secure_delete.go`
- Modify: `internal/cli/schedule.go`
- Modify: `internal/cli/watch.go`
- Modify: `internal/utils/password.go`
- Modify tests beside affected packages

**Interfaces:**
- Consumes: Task 1 validators and Task 2 hardened walk

- [ ] **Step 1: Add failing CLI/unit tests**

Cover single encrypt symlink input, secure-delete symlink preserving link+target, keyfile with symlink parent, watch callback symlink event, schedule root symlink validation, and rotate-key root symlink validation.

- [ ] **Step 2: Verify RED**

Run: `go test ./internal/cli ./internal/utils ./tests/integration -run "Symlink" -count=1`

- [ ] **Step 3: Validate command roots and outputs**

Before dry-run, password prompts, reads, creates, overwrite checks, or deletes:

```go
if err := utils.ValidateNoSymlinkComponents(inputPath); err != nil { return err }
if err := utils.ValidateNoSymlinkComponents(outputPath); err != nil { return err }
```

Use `os.Lstat` rather than `os.Stat` when classifying input roots. Replace CLI directory output joins with `utils.SafeJoin`.

- [ ] **Step 4: Harden watch, schedule, and keyfiles**

Validate watch root at startup. For each event, use `Lstat` and component validation before scheduling and again inside delayed encryption. Validate schedule path each execution. Call shared validation before keyfile `Lstat`.

- [ ] **Step 5: Verify and commit**

Run: `go test ./internal/cli ./internal/utils ./tests/integration -count=1`

Commit: `feat(cli): enforce default-deny symlink policy`

---

### Task 4: Integration coverage, docs, review, and merge

**Files:**
- Create/modify: `tests/integration/symlink_containment_test.go`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify relevant `docs/src/pages/docs/*.astro`
- Modify locally only: `ROADMAP.md`

- [ ] **Step 1: Add end-to-end containment tests**

Verify directory encrypt aborts on nested symlinks without producing ciphertext for them, directory decrypt rejects a symlinked output parent, and `SafeJoin` escape cases remain covered.

- [ ] **Step 2: Update documentation**

Document default-deny input/output symlink behavior, no follow opt-in, actionable remediation, and the concurrent replacement boundary. Add an Unreleased CHANGELOG entry. Mark X2 done locally after merge.

- [ ] **Step 3: Full verification**

Run:

```powershell
gofmt -w internal/utils/path_safety.go internal/utils/path_safety_test.go internal/utils/errors.go internal/utils/password.go internal/utils/password_test.go internal/core/file_handler.go internal/core/file_handler_test.go internal/core/directory.go internal/core/directory_test.go internal/cli/encrypt.go internal/cli/decrypt.go internal/cli/rotate_key.go internal/cli/secure_delete.go internal/cli/schedule.go internal/cli/watch.go internal/cli/watch_test.go tests/integration/symlink_containment_test.go
go test ./... -count=1 -timeout 2m
go vet ./...
cd docs; npm run build
git diff --check
graphify update .
```

- [ ] **Step 4: Review and integration**

Run task and whole-branch review, fix all blocking/important findings, push, create PR, wait for every CI check, merge to `main`, delete local/remote branch, and prune.

Commit docs/tests: `docs: document default-deny symlink policy`

## Spec coverage

- Root/nested/input/output symlink rejection: Tasks 1–3.
- Lexical output containment: Tasks 1–2.
- Watch/schedule/keyfile coverage: Task 3.
- Cross-platform integration tests and docs: Task 4.
