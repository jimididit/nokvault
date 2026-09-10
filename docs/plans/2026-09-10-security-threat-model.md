# SECURITY.md Threat Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an honest Threat Model and Residual Risks section to root `SECURITY.md`, absorbing Known Security Considerations, matching actual code and `docs/format-v2.md`.

**Architecture:** Docs-only edit on branch `docs/security-threat-model`. Replace the Known Security Considerations block with Threat Model + Residual Risks; add a Security Audit pointer. No Go or Astro site changes.

**Tech Stack:** Markdown (`SECURITY.md`); verification against `docs/format-v2.md` and existing SECURITY wording.

**Design spec:** `docs/specs/2026-09-10-security-threat-model-design.md`  
**Path note:** Plans live under `docs/plans/` because `docs/superpowers/` is gitignored.  
**Worktree:** `E:\repos\nokvault\.worktrees\security-threat-model`

## Global Constraints

- Root `SECURITY.md` only (no docs-site rewrite)
- Checklist threat model **plus** residual-risk package
- Approach A: append/replace in place; absorb Known Security Considerations (delete old heading)
- Reviewer-honest tone; no new marketing claims
- Cross-link `docs/format-v2.md` for wire/AAD details
- Empty AAD and unauthenticated metadata must be stated explicitly
- Docs-only PR; no `.go` changes
- Do not invent mitigations; label future work only for L2/L7/format bump

---

## File Structure

| File | Responsibility |
| --- | --- |
| Modify: `SECURITY.md` | Insert Threat Model + Residual Risks; remove Known Security Considerations; Audit pointer |
| Reference: `docs/format-v2.md` | AAD empty, metadata plaintext, compression sniff |
| Reference: `docs/specs/2026-09-10-security-threat-model-design.md` | Approved outline |

---

### Task 1: Rewrite `SECURITY.md` sections

**Files:**
- Modify: `SECURITY.md` (from Security Features through Security Audit)

**Interfaces:**
- Consumes: Design outline in `docs/specs/2026-09-10-security-threat-model-design.md`
- Produces: Updated `SECURITY.md` with Threat Model + Residual Risks as single source of truth

- [ ] **Step 1: Confirm current section anchors**

Open `SECURITY.md` and locate:

- `## Security Features` (keep)
- `## Known Security Considerations` (remove after absorb)
- `## Security Audit` (add pointer)

- [ ] **Step 2: Optionally add one format-spec link under Security Features**

After the Path policy bullet in Security Features, ensure authenticity claim stays payload-scoped. Add this bullet if not already present:

```markdown
- **Format documentation**: On-disk layout and AEAD binding limits are documented in [`docs/format-v2.md`](docs/format-v2.md)
```

Also soften Secure Deletion feature bullet if it overclaims — change:

```markdown
- **Secure Deletion**: Multiple overwrite passes make file recovery difficult
```

To:

```markdown
- **Secure Deletion**: Multi-pass overwrite before unlink (effectiveness depends on storage media; see Residual Risks)
```

And clarify authenticated encryption bullet:

```markdown
- **Authenticated Encryption**: AES-256-GCM provides confidentiality and authenticity for the encrypted **payload** (header/metadata are not AEAD-bound; see Threat Model and [`docs/format-v2.md`](docs/format-v2.md))
```

- [ ] **Step 3: Replace Known Security Considerations with the following two sections**

Delete the entire `## Known Security Considerations` section (all six numbered items) and insert this content in its place (between Security Features and Security Audit):

```markdown
## Threat Model

This section describes what NokVault protects, against whom, and what it explicitly does not claim. It matches the current implementation. Wire-format details live in [`docs/format-v2.md`](docs/format-v2.md).

### Product scope

NokVault is a local CLI for encrypting files and directories, with optional watch, schedule, and secure-delete helpers. It is **not** a backup system, network sync service, full-disk encryptor, or multi-recipient sharing tool.

### Assets

- User plaintext (source files and transient plaintext during encrypt, decrypt, and `rotate-key`)
- Secrets: interactive passwords, keyfile bytes, and `NOKVAULT_PASSWORD`
- Derived AES-256 keys and salts in process memory
- On-disk `.nokvault` containers (header, optional plaintext JSON metadata, ciphertext payload)
- Released binaries and their checksum / attestation metadata

### Attackers and environments

| Class | What we model |
| --- | --- |
| Offline vault thief | Possesses `.nokvault` file(s) but not the password or keyfile |
| Same-user local process | Can read environment variables, process listings, and files the user can open |
| Hostile directory tree | Symlinks, Windows junctions, other reparse points, and path-escape attempts |
| Supply-chain / wrong binary | Unverified download or tampered artifact |
| Operator mistake | Accidental overwrite, weak passwords, world-readable keyfiles |

NokVault does **not** claim to defeat attackers with full live memory access, cold-boot attacks, a compromised OS kernel, or hardware implants.

### Trust boundaries

- The OS user account and filesystem permissions
- Interactive terminal prompts versus automation (`NOKVAULT_PASSWORD`, keyfiles)
- Local configuration files
- GitHub Releases, published checksums, and GitHub OIDC build attestations

### In-scope protections

Claims that match current code:

- AES-256-GCM confidentiality and authenticity of the **payload** ciphertext (nonce prepended; GCM tag verifies the sealed blob)
- Argon2id key derivation; format v2 persists KDF parameters in the header; v1 files use built-in defaults
- CLI refuses `--password` / `-p`; keyfiles must not be group/world-readable and must not be symlinks
- Encrypt and `rotate-key` use atomic writes (temp file, fsync, rename)
- Decrypt restores modes clamped to owner-only unless `--preserve-mode`
- Default-deny policy for symlinks, junctions, and other detected reparse points; lexical output containment (`SafeJoin`)
- Release artifacts ship with checksums; verify provenance with `gh attestation verify`

See [`docs/format-v2.md`](docs/format-v2.md) for endianness, header layouts, version negotiation, and reject rules.

### Non-goals

NokVault does not provide or claim:

- Full-disk or volume encryption
- Remote backup, sync, or deduplicating repository semantics
- Cryptographic author identity or multi-recipient / age-style sharing (possible future work)
- Race-proof protection against privileged concurrent path replacement between validation and open (TOCTOU)
- Guaranteed erasure on SSD, flash, or TRIM-backed storage
- Locked memory or immunity to hibernation / crash dumps (possible future work)
- AEAD binding of the file header or optional metadata — **GCM additional data is empty today**

## Residual Risks

Known limits and footguns. Reviewers should treat these as intentional honesty, not accidental omissions.

1. **Memory, swap, hibernation, and crash dumps**  
   Sensitive buffers are best-effort zeroized after use. The OS may still retain secrets in swap, hibernation images, or crash dumps.

2. **`NOKVAULT_PASSWORD`**  
   Environment variables are visible to other processes running as the same user. Prefer a permission-restricted keyfile for automation.

3. **Secure deletion on modern media**  
   Multi-pass overwrite before unlink is oriented toward traditional HDDs. On many SSDs and flash devices (TRIM, wear leveling), overwritten data may remain recoverable. Do not treat `secure-delete` as cryptographic erase.

4. **Empty GCM AAD**  
   Header fields (magic, version, salt, KDF parameters, offsets) are **not** bound into AES-GCM. An attacker who can modify the header without the key may change version/KDF interpretation; payload ciphertext still fails closed on tag mismatch. Details: [`docs/format-v2.md`](docs/format-v2.md) §8 and §12.

5. **Unauthenticated plaintext metadata**  
   Optional JSON metadata sits on disk immediately after the header and is not covered by AEAD. Treat metadata as public adjacent data.

6. **Whole-file-in-RAM encrypt/decrypt**  
   Current encrypt and decrypt paths load entire files into memory. Very large artifacts may be impractical until streaming AEAD lands.

7. **Compression sniff after decrypt**  
   There is no compress flag in the header. After successful decryption, the CLI may attempt gzip decompression if plaintext begins with magic `1f 8b`. Legitimate plaintext that starts with those bytes can be mis-handled.

8. **Path policy timing**  
   Symlink/junction checks and output containment run before prompts and mutation, but validation-then-open is not race-proof against a privileged concurrent replacement of a path component.

9. **`rotate-key` re-encrypts**  
   Rotation decrypts and re-encrypts. Plaintext exists briefly in memory (and follows the same residual memory risks as other decrypt paths).

10. **Weak passwords**  
    Argon2id raises the cost of offline guessing against stolen vaults; it does not make short or reused human passwords safe.

11. **Keys are not stored by NokVault**  
    Users must manage passwords and keyfiles. Loss of the secret means permanent loss of plaintext for that vault.

12. **Argon2id cost on low-resource devices**  
    Default parameters (and stricter custom parameters) can be slow on constrained hardware. That is a usability tradeoff for offline-guessing resistance, not a bypass of the KDF.
```

- [ ] **Step 4: Update Security Audit section**

Replace:

```markdown
## Security Audit

If you're conducting a security audit or penetration test:

1. Please notify us in advance if possible
2. Follow responsible disclosure practices
3. We welcome security research and will work with you
```

With:

```markdown
## Security Audit

Start with this document's **Threat Model** and **Residual Risks**, plus the wire format in [`docs/format-v2.md`](docs/format-v2.md).

If you're conducting a security audit or penetration test:

1. Please notify us in advance if possible
2. Follow responsible disclosure practices
3. We welcome security research and will work with you
```

- [ ] **Step 5: Commit**

```bash
git add SECURITY.md
git commit -m "docs: add SECURITY.md threat model and residual risks"
```

---

### Task 2: Honesty verification

**Files:**
- Verify: `SECURITY.md`, `docs/format-v2.md`
- No Go changes expected

**Interfaces:**
- Consumes: Task 1 `SECURITY.md`
- Produces: Verification notes in report; fix+commit only if contradictions found

- [ ] **Step 1: Placeholder and overclaim scan**

```bash
rg -n "TBD|TODO|FIXME|AAD bound|guarantees secure|race-proof|full-disk" SECURITY.md
```

Expected: no TBD/TODO/FIXME. Mentions of AAD/race must be in the **empty / not claimed** sense only.

- [ ] **Step 2: Cross-check critical claims against format spec**

Confirm `SECURITY.md` and `docs/format-v2.md` agree on:

- GCM AAD empty
- Metadata not AEAD-covered
- Compression not a header flag / gzip sniff
- Payload = nonce \|\| ciphertext\|\|tag

```bash
rg -n "AAD|metadata|compress|nonce" SECURITY.md docs/format-v2.md
```

- [ ] **Step 3: Confirm docs-only diff vs main**

```bash
git diff main...HEAD --stat
```

Expected: `SECURITY.md` plus already-committed design/plan markdown under `docs/`. No `.go` files.

- [ ] **Step 4: Stop before push/PR unless the user asks**

Summarize files changed and that threat model + residual risks are present.

---

## Self-review (plan vs design)

| Design requirement | Task |
| --- | --- |
| Threat Model (scope, assets, attackers, trust, protections, non-goals) | Task 1 |
| Residual Risks (10+ items including AAD, SSD, env, RAM, sniff) | Task 1 |
| Absorb/delete Known Security Considerations | Task 1 |
| Security Audit pointer | Task 1 |
| Format cross-link | Task 1 |
| Honesty verification | Task 2 |
| Docs-only | Global + Task 2 |

No independent subsystems; single docs plan is appropriate.
