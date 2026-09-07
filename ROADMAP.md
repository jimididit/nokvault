# NokVault Roadmap

**Derived solely from:** `AUDIT_REPORT.md` (2026-09-07)  
**Rule:** No new unverified claims — every item maps to audit finding IDs (NV-*).

---

## Now (0–2 weeks) — Critical / High security & integrity

### N1. Fix `rotate-key` salt/key mismatch (NV-001, NV-010) — DONE (merged)
- **Problem:** Rotated files store a salt that does not match the derived key; ciphertext is unrecoverable with the new password. Plaintext also lingers unzeroized.
- **Approach:** Derive with `DeriveKeyFromPasswordAndSalt(newPassword, newSalt)`; zeroize plaintext after successful rewrite; add encrypt→rotate→decrypt integration test that fails today.
- **Effort:** S  
- **Risk if deferred:** Data-loss / trust-breaking for anyone using `rotate-key`.  
- **Depends on:** None (blocker for any release that advertises rotation).

### N2. Persist KDF parameters in on-disk format + apply config (NV-002, NV-003, NV-012, NV-027) — DONE (merged)
- **Problem:** Header stores salt only; config KDF is display-only; compression inferred by magic.
- **Approach:** Bump `CurrentVersion`; extend header (or authenticated AAD metadata) with Argon2 memory/time/parallelism/keylen, algorithm IDs, compress flag; decrypt reads header params; encrypt writes them; wire `KeyManager.SetParams` from config for *new* encryptions only.
- **Effort:** M  
- **Risk if deferred:** Silent decrypt failures after config/default changes; format dead-end vs age/restic-class tools.  
- **Depends on:** Spec sketch in-repo (can be short RFC-style section); unlocks Later format-spec publication.

### N3. Stop password-on-argv & harden keyfiles (NV-004, NV-005) — DONE (PR pending)
- **Problem:** `--password` exposes secrets via process list/history; keyfiles have no permission checks.
- **Approach:** Hard-deprecate/refuse `--password` outside tests; keep prompt / keyfile / env; `Stat` keyfile and reject group/world-readable (and optionally symlinks).
- **Effort:** S  
- **Risk if deferred:** Trivial credential theft on shared hosts.  
- **Depends on:** None.

### N4. Atomic encrypt writes; clamp decrypt permissions (NV-006, NV-007)
- **Problem:** Crash mid-write corrupts `.nokvault`; metadata restore can make plaintext world-readable.
- **Approach:** Reuse temp+rename pattern from rotate-key / wire `SafeWrite` (or delete dead recovery code if unused); clamp restored modes to ≤0600/0700 unless explicit `--preserve-mode`.
- **Effort:** S–M  
- **Risk if deferred:** Corrupt vaults; accidental plaintext exposure after “secure” decrypt.  
- **Depends on:** None; Graphify shows `SafeWrite` currently orphaned.

### N5. Correct docs that oversell rotation (NV-008) — DONE (merged)
- **Problem:** README/CHANGELOG claim rotation without re-encryption.
- **Approach:** Rewrite to “re-key (decrypt + re-encrypt)”; note plaintext briefly in memory/temp file semantics after N1/N4.
- **Effort:** S  
- **Risk if deferred:** Users make threat-model mistakes.  
- **Depends on:** N1 preferred first so docs match working behavior.

### N6. Unblock CI confidence — fix Cobra flag isolation (NV-009)
- **Problem:** Integration suite fails; wrong `-o` leakage observed; CHANGELOG coverage claims are stale.
- **Approach:** Fresh command tree per test or reset package-level flag vars; assert round-trip; make `go test ./...` green in CI.
- **Effort:** S  
- **Risk if deferred:** Regressions (including N1) ship unnoticed.  
- **Depends on:** None; should land with N1 tests.

---

## Next (1–2 months) — Hardening, completeness, packaging

### X1. Destructive-op UX & overwrite safety (NV-014, NV-015, NV-016)
- **Problem:** `secure-delete` lacks confirm/`--yes`; outputs overwrite silently; directory decrypt partial trees.
- **Approach:** TTY confirm + `--yes`; `--force` for overwrites; `--strict` decrypt mode.
- **Effort:** S  
- **Risk if deferred:** Operator accidents; DFIR workflow footguns.  
- **Depends on:** None.

### X2. Symlink / path containment policy (NV-017, NV-030)
- **Problem:** Symlink files followed; no output-root containment check.
- **Approach:** `--no-follow-symlinks` default-deny option; `Clean` + prefix check on relative outputs.
- **Effort:** S  
- **Risk if deferred:** Encrypt/read outside intended tree.  
- **Depends on:** None.

### X3. Finish or hide `protect`; fix README exclude docs (NV-018, NV-023)
- **Problem:** Stub command and false `encrypt --exclude` docs.
- **Approach:** Either implement tar/zip+encrypt archive *or* remove from default help; implement exclude on encrypt or delete README example.
- **Effort:** M (implement) / S (hide+docs)  
- **Risk if deferred:** Broken user journeys; trust erosion.  
- **Depends on:** N2 if archive needs format flags.

### X4. Wire or delete dead config surface (NV-019, NV-013; Graphify orphans)
- **Problem:** `chacha20`, KeyCache, RecoveryHandler unused — false sense of completeness.
- **Approach:** Remove dead options **or** implement with tests; zeroize on KeyCache clear if kept.
- **Effort:** S–M  
- **Risk if deferred:** Audit/marketing mismatch.  
- **Depends on:** Product choices from open questions in audit.

### X5. CI security pipeline (NV-020, NV-021, NV-029)
- **Problem:** No govulncheck/SAST/Dependabot; Go 1.21 vs 1.24.2 mismatch; checksums only.
- **Approach:** Align Go pin; add `govulncheck`, `staticcheck`/`gosec`, Dependabot; keep multi-OS matrix; add cosign or GitHub artifact attestations.
- **Effort:** M  
- **Risk if deferred:** Supply-chain and toolchain drift.  
- **Depends on:** N6 (green tests) for meaningful CI gates.

### X6. Packaging that actually installs (NV-022)
- **Problem:** Formula/Scoop stubs point at `v1.0.0` with empty hashes.
- **Approach:** Publish manifests for real `v0.1.x` (or next) tags with hashes; document APT as later if needed.
- **Effort:** S–M  
- **Risk if deferred:** “Coming soon” forever; broken community packaging.  
- **Depends on:** Signed/checksummed release (X5).

### X7. Coverage & fuzz on format parser (audit §5; NV-028)
- **Problem:** `utils` 0% coverage; no fuzz; adversarial headers untested.
- **Approach:** Unit tests for recovery/password/security; fuzz `ReadHeaderWithMetadata` + decrypt against truncated/garbage inputs.
- **Effort:** M  
- **Risk if deferred:** Parser panics / DoS / logic bugs in the field.  
- **Depends on:** N2 header changes (fuzz the new format).

### X8. `--json` output for scripting/SOAR (NV-024; competitive gap)
- **Problem:** No stable machine-readable API for DFIR automation.
- **Approach:** `--json` on encrypt/decrypt/watch events/secure-delete results; schema version field.
- **Effort:** M  
- **Risk if deferred:** Loses differentiator vs restic/sops-style ops tooling.  
- **Depends on:** Stable exit codes + N6 tests.

### X9. Documentation website UI overhaul (product / UX — not from AUDIT_REPORT)
- **Problem:** The Astro docs site at `/docs` needs a **serious UI overhaul** — layout, typography, navigation, and visual hierarchy do not match a security-tool-grade product page (current pages are functional but dated/generic).
- **Approach:** Redesign information architecture and visual system (brand-first landing + docs chrome); keep content accurate while upgrading components; do **not** couple to Astro major bumps beyond what’s required for the redesign (Dependabot Astro majors can land in the same effort or immediately after).
- **Effort:** M–L  
- **Risk if deferred:** Docs remain a weak first impression vs. age/restic-class tools; trust/marketing mismatch even when core crypto improves.
- **Depends on:** Content already being corrected by Now/Next work (config, security, format); prefer after N3/N4 usage-doc updates so the redesign starts from accurate copy.

---

## Later (3–6+ months) — Best-in-class expansion

### L1. Formal versioned vault format spec (NV-002 follow-through; competitive gap)
- **Problem:** Format lives only as Go structs.
- **Approach:** Standalone `docs/format-v2.md` (endianness, AAD, KDF fields, version negotiation); compatibility matrix.
- **Effort:** M  
- **Risk if deferred:** Cannot invite external crypto review cleanly.  
- **Depends on:** N2.

### L2. True streaming AEAD for large files (NV-011; vs age/restic)
- **Problem:** Entire file loaded into RAM.
- **Approach:** Chunked nonce construction (explicit counter||random policy documented) or external stream framing; constant memory.
- **Effort:** L  
- **Risk if deferred:** Unusable on large forensic images/backups.  
- **Depends on:** L1.

### L3. age-style recipients / asymmetric options (competitive gap; open Q1)
- **Problem:** Password/keyfile only — no multi-recipient share model.
- **Approach:** Optional X25519 recipients (age interop or subset); keep passphrase path.
- **Effort:** L  
- **Risk if deferred:** Remains single-user tool only.  
- **Depends on:** L1; threat-model decision.

### L4. Hardware-backed keys (FIDO2/YubiKey/TPM) (competitive gap)
- **Problem:** No hardware root of trust.
- **Approach:** Plugin or age-plugin-compatible path; document attestation limits.
- **Effort:** L  
- **Risk if deferred:** Weaker posture for high-assurance DFIR kits.  
- **Depends on:** L3 or separate HMAC challenge design.

### L5. DFIR chain-of-custody / audit log mode (audit open Q6; NV-024)
- **Problem:** No append-only operation history for evidence handling.
- **Approach:** Optional signed JSONL audit events (who/when/hash/action); verify subcommand.
- **Effort:** M–L  
- **Risk if deferred:** Misses maintainer’s DFIR differentiator.  
- **Depends on:** X8; optional L4 for signing keys.

### L6. Remote targets for schedule (S3/SFTP) (competitive gap vs restic)
- **Problem:** Schedule encrypts locally only.
- **Approach:** Pluggable backends after local encrypt; never invent backup-dedup — stay complementary to restic/borg.
- **Effort:** L  
- **Risk if deferred:** Scope creep if attempted too early; **defer until core crypto format is solid**.  
- **Depends on:** N2, N4, X5.

### L7. Memguard / locked-memory high-assurance mode (NV-026)
- **Problem:** Best-effort zeroize only.
- **Approach:** Optional build tag or runtime flag; document when still insufficient (hibernation, crash dumps).
- **Effort:** M  
- **Risk if deferred:** Acceptable if SECURITY.md stays honest.  
- **Depends on:** None.

### Explicit non-goals / simplify (anti-bloat)
- Do **not** chase full restic/borg backup semantics or VeraCrypt volume mounts — NokVault’s edge is local encrypt + watch/schedule/secure-delete.
- Remove or hide unfinished surfaces (`protect` stub, unwired `chacha20`, dead KeyCache) rather than advertising them (NV-018, NV-019).

---

## Vision: best-in-class NokVault 2.0

NokVault 2.0 is a **boring-correct** local encryption CLI: a published v2 container format with KDF/alg fields, crash-safe writes, no secrets on argv, streaming for large artifacts, and CI that proves `govulncheck` + fuzz + multi-OS tests on every commit. Differentiating features (watch, schedule, secure-delete, DFIR `--json`/audit log) sit *on top of* that core — not instead of it. Asymmetric recipients and hardware keys are optional modules for sharing and high-assurance kits; remote backends remain thin “push ciphertext” helpers, not a second backup product. Anything that cannot meet the format + test bar stays out of `main` help text.

---

## Definition of done — external security-audit ready

- [ ] NV-001 fixed and regression-tested (rotate round-trip).
- [ ] Format v2 with persisted KDF/alg/compress fields; migration notes for v1 (NV-002/N2).
- [ ] No password-on-argv in released binaries; keyfile permission checks enforced (NV-004/005).
- [ ] All encrypt paths atomic; decrypt permission clamp documented and tested (NV-006/007).
- [ ] `go test ./...` green on Windows/Linux/macOS CI; fuzz job on header/decrypt (NV-009, X7).
- [ ] `govulncheck` + Dependabot/Renovate clean or explicitly waived; Go toolchain pins match (NV-020/021/029).
- [ ] Release artifacts: checksums **and** signatures/attestations (X5).
- [ ] SECURITY.md threat model section (assets, attackers, non-goals) matching actual code.
- [ ] Standalone format spec checked into repo (L1).
- [ ] Dead/stub features removed from UX or clearly experimental (protect/chacha20/KeyCache).
- [ ] Maintainer package of known residual risks (SSD wipe theater, swap, env password) — no surprises for reviewers.

When the checklist above is complete, NokVault is in shape for a formal third-party review (Trail of Bits / NCC-style community audit or private pen test), not before.
