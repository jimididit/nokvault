# SECURITY.md Threat Model + Residual Risks (design)

**Date:** 2026-09-10  
**Status:** Approved for implementation planning  
**Roadmap:** Audit-ready checklist — SECURITY.md threat model; residual-risk package  
**Approach:** A — append self-contained sections to root `SECURITY.md` (no docs-site rewrite)

## Goal

Add an honest **Threat Model** and **Residual Risks** section to root `SECURITY.md` so external reviewers know assets, attackers, trust boundaries, non-goals, and known residual risks without reading the codebase. Content must match actual behavior (including empty GCM AAD and format facts in `docs/format-v2.md`).

## Non-goals

- Changing Go crypto or CLI behavior
- Rewriting the Astro docs security page (optional one-line pointer later, out of scope)
- Full security whitepaper / diagrams
- Closing format gaps (bound AAD, compress flag) — document only
- Implementing L2 streaming or L7 memguard

## Decisions (locked)

| Topic | Choice |
| --- | --- |
| Location | Root `SECURITY.md` only |
| Depth | Checklist-minimum threat model **plus** residual-risk package |
| Structure | Approach A: append sections; lightly dedupe existing Known Security Considerations |
| Tone | Reviewer-honest; no new marketing claims |
| Format cross-link | Point to `docs/format-v2.md` for wire/AAD details |

## Deliverables

1. Updated `SECURITY.md` with Threat Model + Residual Risks (primary)
2. Trim/fold overlapping bullets in **Known Security Considerations** so residual risks are not duplicated at length
3. Optional: one sentence under Security Audit pointing to the Threat Model section
4. Docs-only PR on branch `docs/security-threat-model`

## Placement in `SECURITY.md`

Current order (approximate): Supported Versions → Reporting → Best Practices → Security Features → Known Security Considerations → Security Audit → Acknowledgments.

**Target order after change:**

1. Supported Versions *(unchanged)*
2. Reporting *(unchanged)*
3. Best Practices *(unchanged)*
4. Security Features *(unchanged; may add link to Threat Model / format spec)*
5. **Threat Model** *(new)*
6. **Residual Risks** *(new — absorbs and supersedes most of Known Security Considerations)*
7. Known Security Considerations *(short stub or removed if fully absorbed — prefer absorb into Residual Risks and delete the old heading to avoid dual lists)*
8. Security Audit *(add pointer to Threat Model)*
9. Acknowledgments *(unchanged)*

## Threat Model section outline

### Product scope

NokVault is a local CLI for encrypting files and directories (watch/schedule/secure-delete included). It is not a backup product, network sync service, or multi-recipient sharing system.

### Assets

- User plaintext (source files; transient plaintext during encrypt/decrypt/rotate)
- Secrets: passwords, keyfile bytes, `NOKVAULT_PASSWORD`
- Derived AES keys and salts in process memory
- On-disk `.nokvault` containers (ciphertext + header + optional plaintext metadata)
- Release binaries and provenance metadata

### Attackers / environments (in scope to discuss)

| Class | Intent of model |
| --- | --- |
| Offline vault thief | Has `.nokvault` file(s) only; no password/keyfile |
| Same-user local process | Can read env, process list, open files user can open |
| Hostile directory tree | Symlinks, junctions, path escape attempts |
| Supply-chain / wrong binary | Unverified download or tampered artifact |
| Operator mistake | Overwrite, weak password, world-readable keyfile |

**Explicitly not claimed as solved:** attacker with full live memory access, cold-boot, compromised OS kernel, or hardware implants.

### Trust boundaries

- OS user account and filesystem permissions
- Interactive terminal vs automation (`NOKVAULT_PASSWORD`, keyfiles)
- Local config files
- GitHub Releases + checksums + build attestations

### In-scope protections (claims that match code)

- AES-256-GCM confidentiality + authenticity of **payload** ciphertext
- Argon2id KDF; v2 persists params in header; v1 uses defaults
- `--password` / `-p` refused; keyfile permission and symlink checks
- Atomic encrypt/rotate writes (temp + fsync + rename)
- Decrypt restores modes clamped unless `--preserve-mode`
- Default-deny symlink/junction/reparse policy; lexical output containment
- Release checksums and GitHub OIDC attestations

Cross-reference: [`docs/format-v2.md`](../format-v2.md) (path from repo root: `docs/format-v2.md`).

### Non-goals

- Full-disk / volume encryption
- Remote backup / dedup semantics
- Cryptographic author identity or multi-recipient age-style sharing (future L3)
- Race-proof protection against privileged concurrent path replacement (TOCTOU)
- Guaranteed erasure on SSD/flash/TRIM
- Locked memory / hibernation immunity (future L7)
- AEAD binding of header or metadata (AAD is empty today)

## Residual Risks section outline

Document each honestly (one short paragraph or bullet + “what this means”):

1. **Memory / swap / hibernation / crash dumps** — best-effort zeroize only  
2. **`NOKVAULT_PASSWORD`** — visible to other local processes; prefer keyfile  
3. **Secure deletion** — multi-pass overwrite is weak/irrelevant on many SSDs  
4. **Empty GCM AAD** — header (version, salt, KDF fields) and metadata are not AEAD-bound; see format spec  
5. **Unauthenticated plaintext metadata** — JSON sits adjacent to ciphertext  
6. **Whole-file-in-RAM** — encrypt/decrypt load entire file (streaming is L2)  
7. **Compression sniff** — post-decrypt gzip magic may mis-handle plaintext that starts with `1f 8b`  
8. **Path policy timing** — validate-then-open; not a claim of race-proof concurrent replacement  
9. **`rotate-key`** — re-encrypts; plaintext briefly in memory  
10. **Weak passwords** — Argon2id slows guessing; does not fix short human passwords  

No invented mitigations; “future work” only where already on roadmap (L2, L7, format bump) and labeled as such.

## Deduping Known Security Considerations

Merge existing items (key storage, memory, secure deletion, KDF speed, symlink policy, path timing) into Residual Risks / Threat Model. Remove the old **Known Security Considerations** heading once content is migrated, **or** leave a one-line pointer: “See Residual Risks below.” Prefer full absorb + delete heading for a single source of truth.

## Success criteria

- A reviewer can answer from `SECURITY.md` alone: what is protected, against whom, what is explicitly out of scope, and what residual risks remain.
- No contradiction with `docs/format-v2.md` or README security bullets.
- Audit checklist items can be marked for: threat model section **and** maintainer residual-risk package.
- Docs-only PR; no `.go` changes.

## Implementation plan expectations

1. Draft Threat Model + Residual Risks prose in `SECURITY.md` from this outline.  
2. Absorb/remove Known Security Considerations duplication.  
3. Add Security Audit pointer.  
4. Self-check honesty vs code and format spec.  
5. PR from `docs/security-threat-model`.

## Open risks (accepted)

- Docs site security page will temporarily be slightly less complete than `SECURITY.md` until a later optional sync.  
- Checklist item “persisted compress fields” remains open; residual risks document the gap rather than closing it.
