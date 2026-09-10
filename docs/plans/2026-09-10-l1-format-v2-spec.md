# L1 Format v2 Spec Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a standalone, reviewer-first vault wire-format document at `docs/format-v2.md` that matches the current Go implementation (no format change).

**Architecture:** Docs-only work on branch `docs/l1-format-v2-spec`. The published markdown is the normative artifact; verify every constant and layout claim against `internal/core/file_handler.go`, `internal/crypto/key_derivation.go`, `internal/crypto/aes.go`, and the CLI compression paths. Do not invent fields (especially AAD binding or a compress flag).

**Tech Stack:** Markdown in-repo; Go sources as the verification oracle (`HeaderWireSize`, `ValidateKDFParams`, AES-GCM Seal/Open with nil AAD).

**Design spec:** `docs/specs/2026-09-10-l1-format-v2-spec-design.md`  
**Path note:** Plans live under `docs/plans/` because `docs/superpowers/` is gitignored in this repo.

## Global Constraints

- Document-as-is: no v3 / format bump / Go behavior changes in this PR
- Audience: reviewers first; short enough for a port
- Published path: `docs/format-v2.md` (Astro package root, **not** under `docs/src/`)
- Top of published doc MUST note: wire format spec, not an Astro page
- AAD is empty (`nil` to GCM); state this explicitly
- Compression is CLI behavior via gzip magic, not a header field
- No normative test-vector appendix
- Optional README pointer only where a natural anchor exists; do not invent a marketing section
- Worktree/branch: `E:\repos\nokvault\.worktrees\l1-format-v2-spec` on `docs/l1-format-v2-spec`

---

## File Structure

| File | Responsibility |
| --- | --- |
| Create: `docs/format-v2.md` | Normative published wire-format spec (primary L1 deliverable) |
| Modify: `README.md` | One-line link under Features “Format v2” and/or Security section |
| Reference only: `internal/core/file_handler.go` | Header sizes, versions, KDF caps, metadata, DataOffset |
| Reference only: `internal/crypto/key_derivation.go` | Argon2id defaults |
| Reference only: `internal/crypto/aes.go` | Nonce/tag sizes; nil AAD |
| Reference only: `internal/core/compression.go`, `internal/cli/encrypt.go`, `internal/cli/decrypt.go` | gzip behavior |

No new Go packages, tests, or Astro pages.

---

### Task 1: Draft `docs/format-v2.md`

**Files:**
- Create: `docs/format-v2.md`
- Verify against: `internal/core/file_handler.go`, `internal/crypto/key_derivation.go`, `internal/crypto/aes.go`, `internal/core/compression.go`, `internal/cli/encrypt.go`, `internal/cli/decrypt.go`

**Interfaces:**
- Consumes: Design outline in `docs/specs/2026-09-10-l1-format-v2-spec-design.md`
- Produces: Published normative markdown at `docs/format-v2.md`

- [ ] **Step 1: Re-read implementation anchors and confirm constants**

Run from worktree root:

```bash
rg -n "NokvaultMagic|Version1|Version2|CurrentVersion|maxMetadataSize|MaxKDF|HeaderWireSize|DefaultMemory|DefaultTime|DefaultParallelism|DefaultKeyLength|NonceSize|GCMTagSize" internal/core/file_handler.go internal/crypto/key_derivation.go internal/crypto/aes.go
```

Expected values to match the draft below:

| Constant | Value |
| --- | --- |
| Magic | `NOKVAULT` |
| Version1 / Version2 / CurrentVersion | 1 / 2 / 2 |
| HeaderWireSize(1) | 38 |
| HeaderWireSize(2) | 54 |
| maxMetadataSize | `1 << 20` (1048576) |
| MaxKDFMemory | `256 * 1024` KiB |
| MaxKDFTime | 10 |
| MaxKDFParallelism | 16 |
| DefaultMemory | `64 * 1024` KiB |
| DefaultTime | 3 |
| DefaultParallelism | 4 |
| DefaultKeyLength / SaltLength | 32 / 16 |
| NonceSize / GCMTagSize | 12 / 16 |
| GCM additional data | `nil` in `Seal`/`Open` |

- [ ] **Step 2: Create `docs/format-v2.md` with this content**

Write the file exactly (minor wording polish OK; do **not** change numbers, field order, or invent AAD/compress header fields):

```markdown
# NokVault vault format (v1 / v2)

> Wire format specification for `.nokvault` files. This file lives under the
> `docs/` package directory for versioning; it is **not** an Astro website page.

**Status:** Implemented (matches current NokVault Go sources)  
**Current writer version:** 2  
**Endianness:** Little-endian for all multi-byte integers  
**Audience:** Crypto reviewers and alternate implementers

## 1. Purpose

This document is the normative on-disk layout for NokVault vault files. It
describes what is written and accepted today so the format can be reviewed
without reading Go structs.

## 2. File layout

```
[ header — 38 bytes (v1) or 54 bytes (v2) ]
[ optional UTF-8 JSON metadata — MetadataSize bytes ]
[ encrypted payload — nonce || ciphertext||tag ]
```

Magic bytes are ASCII `NOKVAULT` (8 bytes, no trailing NUL).

## 3. Header version 1 (38 bytes)

| Offset | Size | Type | Field |
| --- | --- | --- | --- |
| 0 | 8 | bytes | Magic = `NOKVAULT` |
| 8 | 2 | u16 | Version = `1` |
| 10 | 16 | bytes | Salt |
| 26 | 4 | u32 | MetadataSize |
| 30 | 8 | u64 | DataOffset |

Version 1 does **not** store KDF parameters. Readers MUST derive keys using the
default Argon2id parameters in §5.

## 4. Header version 2 (54 bytes)

Same leading fields as v1 with Version = `2`, then:

| Offset | Size | Type | Field |
| --- | --- | --- | --- |
| 38 | 4 | u32 | Memory (KiB, Argon2) |
| 42 | 4 | u32 | Time (Argon2 iterations) |
| 46 | 1 | u8 | Parallelism |
| 47 | 3 | bytes | Pad (writers MUST write zeros; readers MUST consume and ignore) |
| 50 | 4 | u32 | KeyLength (MUST be `32`) |

`HeaderWireSize(1) = 38`. `HeaderWireSize(2) = 54`.

## 5. Key derivation (Argon2id)

- Algorithm: Argon2id (`argon2.IDKey` semantics from `golang.org/x/crypto/argon2`)
- Salt length: 16 bytes
- Defaults (used for all v1 files and as writer defaults):
  - Memory = `65536` KiB (64 MiB)
  - Time = `3`
  - Parallelism = `4`
  - KeyLength = `32`

Accepted / persisted parameter caps (v2 headers and current writers):

| Parameter | Allowed range |
| --- | --- |
| Memory | 1 … 262144 KiB (max 256 MiB) |
| Time | 1 … 10 |
| Parallelism | 1 … 16 |
| KeyLength | MUST equal 32 |

Zero values for Memory, Time, or Parallelism are invalid.

## 6. Version negotiation

| Role | Rule |
| --- | --- |
| Current writer | MUST write version `2` |
| Reader | MUST accept versions `1` and `2` |
| Reader | MUST reject any other version |

A new on-disk version requires a format bump and an update to this document.

## 7. Optional metadata

If `MetadataSize > 0`, that many bytes of UTF-8 JSON follow the header immediately.

- Maximum `MetadataSize`: 1048576 (1 MiB)
- Informational JSON object fields as implemented:

```json
{
  "name": "string",
  "size": 0,
  "mode": 0,
  "mod_time": "RFC3339 timestamp",
  "is_dir": false,
  "relative_path": "string"
}
```

**Invariant:** `DataOffset` MUST equal `HeaderWireSize(version) + MetadataSize`.
Readers MUST reject any other value.

Metadata is plaintext on disk and is **not** covered by AES-GCM.

## 8. Encrypted payload and AAD

- Cipher: AES-256-GCM
- Key: 32-byte Argon2id output
- Nonce: 12 random bytes, prepended
- Tag: 16-byte GCM tag (appended by GCM; part of the sealed blob)
- On-disk payload after `DataOffset`: `nonce (12) || ciphertext||tag`

**Additional authenticated data (AAD): empty.** The current implementation passes
nil AAD to GCM Seal/Open. The header (including version, salt, and KDF fields)
and optional metadata are **not** cryptographically bound into the AEAD.

Minimum ciphertext length after `DataOffset`: 12 + 16 = 28 bytes.

## 9. Compression (implementation behavior)

There is **no** compression flag in the header.

Current CLI behavior:

1. On encrypt, optional gzip may run on plaintext **before** AEAD when compression
   is enabled and heuristics allow it (typically size > 1 KiB; skip if input
   already starts with gzip magic `1f 8b`).
2. On decrypt, after successful AEAD open, if plaintext starts with `1f 8b`, the
   CLI attempts gunzip; on failure it keeps the raw plaintext.

Treat this as implementation behavior, not a versioned format feature. Plaintext
that legitimately begins with gzip magic may be mis-handled by decompress sniffing.

## 10. Compatibility matrix

| File \\ Reader | Modern NokVault (v1+v2) | Pre-v2 / v1-only tool |
| --- | --- | --- |
| Historical v1 file | Decrypt using default KDF | Decrypt using default KDF |
| Current v2 file | Decrypt using header KDF | Unsupported version |
| Current writer output | Always version 2 | Cannot read |

Notes:

- Modern NokVault decrypts both v1 and v2.
- Custom KDF parameters on v2 files will not round-trip on readers that ignore
  header KDF fields (pre-N2 tools).

## 11. Reject rules

Readers MUST fail closed when any of the following hold:

1. Magic ≠ `NOKVAULT`
2. Truncated header or truncated metadata
3. Version ∉ {1, 2}
4. For v2: KDF params outside §5 caps, or KeyLength ≠ 32
5. `MetadataSize` > 1048576
6. `DataOffset` ≠ header wire size + `MetadataSize`
7. Writer salt length ≠ 16
8. Payload shorter than nonce + tag (28 bytes)
9. GCM authentication failure

## 12. Known limitations

- Empty GCM AAD: header and metadata are not AEAD-bound
- No stored compress flag or cipher/KDF algorithm IDs beyond version + Argon2 params
- Encrypt/decrypt load whole files into memory (streaming is future work)
- Compression inferred by magic after decrypt

Future work may add authenticated header binding and an explicit compress flag;
that would be a new format version, not a silent change to v2.

## 13. Out of scope

CLI flags, keyfiles, password prompting, watch/schedule, secure-delete, packaging,
and website UX are outside this document.
```

- [ ] **Step 3: Spot-check the draft against source**

Confirm these claims in the markdown match code:

1. v2 pad is 3 zero bytes between Parallelism and KeyLength (`WriteHeader`)
2. `Seal(nonce, nonce, plaintext, nil)` / `Open(..., nil)` in `aes.go`
3. Decrypt gzip sniff uses `0x1f 0x8b` after AEAD success (`decrypt.go`)

- [ ] **Step 4: Commit**

```bash
git add docs/format-v2.md
git commit -m "docs: add normative vault format v1/v2 wire spec"
```

---

### Task 2: README pointer

**Files:**
- Modify: `README.md` (Features bullet ~line 15; Security Features ~line 200)

**Interfaces:**
- Consumes: `docs/format-v2.md` from Task 1
- Produces: Discoverable link from root README without new marketing sections

- [ ] **Step 1: Update the existing Format v2 feature bullet**

Change:

```markdown
- **📋 Format v2**: KDF parameters stored in each `.nokvault` header (v1 files still decrypt)
```

To:

```markdown
- **📋 Format v2**: KDF parameters stored in each `.nokvault` header (v1 files still decrypt). Wire layout: [`docs/format-v2.md`](docs/format-v2.md)
```

- [ ] **Step 2: Add one sentence under Security Features**

Immediately after the Key Derivation bullet (~line 200), add:

```markdown
- **Format spec**: On-disk header and AEAD framing are documented in [`docs/format-v2.md`](docs/format-v2.md)
```

Do not create a new top-level README section.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: link README to vault format wire spec"
```

---

### Task 3: Final verification and PR prep

**Files:**
- Verify: `docs/format-v2.md`, `README.md`
- No Go changes expected

**Interfaces:**
- Consumes: Tasks 1–2 outputs
- Produces: Branch ready for PR (push/PR creation only if the user asks)

- [ ] **Step 1: Placeholder and honesty scan**

```bash
rg -n "TBD|TODO|FIXME|AAD bound|compress flag|authenticated header" docs/format-v2.md README.md
```

Expected: no TBD/TODO/FIXME. Mentions of compress flag / AAD must be in the **limitations / empty AAD** sense only.

- [ ] **Step 2: Confirm docs-only diff**

```bash
git diff main...HEAD --stat
```

Expected: only markdown under `docs/` and `README.md` (plus the already-committed design/plan docs on this branch). No `.go` files.

- [ ] **Step 3: Optional local graphify refresh**

If `graphify` CLI is available in the main repo checkout (not required for L1 correctness):

```bash
graphify update .
```

Skip if unavailable in the worktree.

- [ ] **Step 4: Stop for human review before push/PR**

Do not push or open a PR unless the user explicitly asks. Summarize:

- Files added/changed
- That AAD is documented as empty
- That compression is documented as non-header behavior

---

## Self-review (plan vs design)

| Design requirement | Task coverage |
| --- | --- |
| Purpose & status | Task 1 §1 |
| Layout / endianness / magic | Task 1 §2 |
| Header v1 / v2 tables | Task 1 §3–4 |
| KDF defaults + caps | Task 1 §5 |
| Version negotiation | Task 1 §6 |
| Metadata + DataOffset invariant + unauthenticated note | Task 1 §7 |
| AEAD framing + empty AAD | Task 1 §8 |
| Compression honesty | Task 1 §9 |
| Compatibility matrix | Task 1 §10 |
| Reject rules | Task 1 §11 |
| Known limitations | Task 1 §12 |
| Out of scope | Task 1 §13 |
| README optional pointer | Task 2 |
| Docs-only PR readiness | Task 3 |
| No test vectors / no format bump | Global Constraints + Task 1 content |

No independent subsystems; single docs plan is appropriate.
