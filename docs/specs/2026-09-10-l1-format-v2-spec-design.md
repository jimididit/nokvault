# L1 — Formal versioned vault format spec (design)

**Date:** 2026-09-10  
**Status:** Approved for implementation planning  
**Roadmap:** L1 (depends on N2)  
**Approach:** Document-as-is (no format bump)  
**Path note:** Lives under `docs/specs/` because `docs/superpowers/` is gitignored in this repo.

## Goal

Publish a standalone, reviewer-first wire-format document that matches the current Go implementation so external crypto review can proceed without reading structs. Keep it short enough for implementers to port against, without a full test-vector appendix.

## Non-goals

- Changing on-disk format (no v3 / compress flag / AAD binding in this work)
- Normative test vectors (defer until a reviewer asks)
- Website page / Astro content page (optional follow-up)
- CLI UX, keyfile formats, config file schema, directory walk policy
- Streaming AEAD framing (L2)

## Decisions (locked)

| Topic | Choice |
| --- | --- |
| Audience | Reviewers first; enough wire detail for a port; keep short |
| Published path | `docs/format-v2.md` (repo path under the Astro package root; **not** a site page unless later mirrored) |
| Scope | Wire layout + crypto + version negotiation + compatibility + reject rules |
| Format truth | Document **as implemented today**; call out gaps honestly |
| Test vectors | Out of scope for L1 v1 of the published spec |

## Deliverables

1. **`docs/format-v2.md`** — normative published format spec (primary L1 artifact)
2. **Optional pointer** — one-line link from root `README.md` Security / Format section if a natural place already exists; do not invent a new marketing section
3. **No Go code changes** unless a factual error in code comments is found while drafting (prefer fixing the doc, not the binary, in L1)

Note: `docs/` is also the Astro site package. Place `format-v2.md` at `docs/format-v2.md` (package root), not under `docs/src/`, so it is versioned with the repo but not published as an Astro route.

## Source of truth (implementation anchors)

Normative behavior is defined by these packages (read them while drafting; do not invent fields):

- `internal/core/file_handler.go` — header wire layout, versioning, KDF caps, metadata, `DataOffset`
- `internal/crypto/key_derivation.go` — Argon2id defaults and `DeriveKey`
- `internal/crypto/aes.go` — AES-256-GCM payload framing (nonce prepended; **AAD is empty**)
- `internal/core/compression.go` + `internal/cli/encrypt.go` / `decrypt.go` — gzip before encrypt; gzip magic sniff after decrypt

## Published doc outline (`docs/format-v2.md`)

### 1. Purpose and status

- Normative description of the NokVault vault file format as shipped.
- Status: **implemented**; versions 1 and 2.
- Current writers use version 2 (`CurrentVersion`).

### 2. File layout overview

```
[ header (v1: 38 bytes | v2: 54 bytes) ]
[ optional JSON metadata (MetadataSize bytes) ]
[ encrypted payload (nonce || ciphertext||tag) ]
```

All multi-byte integers are **little-endian**. Magic is ASCII `NOKVAULT` (8 bytes, no NUL).

### 3. Header v1 (38 bytes)

| Offset | Size | Type | Field |
| --- | --- | --- | --- |
| 0 | 8 | bytes | Magic = `NOKVAULT` |
| 8 | 2 | u16 | Version = 1 |
| 10 | 16 | bytes | Salt |
| 26 | 4 | u32 | MetadataSize |
| 30 | 8 | u64 | DataOffset |

v1 does **not** store KDF parameters on disk. Readers MUST treat KDF as the implementation defaults (see §5).

### 4. Header v2 (54 bytes)

v1 fields with `Version = 2`, then:

| Offset | Size | Type | Field |
| --- | --- | --- | --- |
| 38 | 4 | u32 | Memory (KiB, Argon2) |
| 42 | 4 | u32 | Time (Argon2 iterations) |
| 46 | 1 | u8 | Parallelism |
| 47 | 3 | bytes | Pad (MUST be written as zeros; readers MUST consume and ignore) |
| 50 | 4 | u32 | KeyLength (MUST be 32) |

Wire size formula: `HeaderWireSize(1) = 38`; `HeaderWireSize(2) = 54`.

### 5. KDF (Argon2id)

- Algorithm: Argon2id (`golang.org/x/crypto/argon2`.IDKey semantics).
- Defaults: Memory = 65536 KiB (64 MiB), Time = 3, Parallelism = 4, KeyLength = 32.
- Salt: 16 random bytes.
- Validation caps for **persisted/accepted** params (v2 header and writers):
  - Memory ∈ [1, 262144] KiB (max 256 MiB)
  - Time ∈ [1, 10]
  - Parallelism ∈ [1, 16]
  - KeyLength MUST equal 32
- v1 files: apply defaults; do not read KDF fields from the file.

### 6. Version negotiation

| Role | Rule |
| --- | --- |
| Writer (current) | MUST write version 2 |
| Reader | MUST accept 1 and 2 |
| Reader | MUST reject any other version |
| Future | New versions require a format bump and spec update |

### 7. Metadata

- Optional UTF-8 JSON object immediately after the header.
- `MetadataSize` is the byte length of that JSON (0 if absent).
- Max metadata size: 1 MiB (`1 << 20`).
- Schema (informational; field names as implemented):

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

- **Invariant:** `DataOffset` MUST equal `HeaderWireSize(version) + MetadataSize`. Readers MUST reject mismatches.
- Metadata is **not** covered by AEAD (plaintext adjacent to ciphertext). Spec MUST state this clearly for reviewers.

### 8. AEAD / AAD

- Cipher: AES-256-GCM.
- Key: 32-byte Argon2id output.
- Nonce: 12 random bytes, prepended to the ciphertext.
- Tag: 16-byte GCM tag (appended by GCM as usual); included in the on-disk payload after the nonce.
- On-disk payload: `nonce (12) || ciphertext||tag`.
- **AAD: empty.** Current implementation passes `nil` additional data to GCM Seal/Open. Header and metadata are **not** authenticated by GCM.
- Spec MUST document this honestly under “Cryptographic binding” / known limitations (not invent a bound AAD layout).

### 9. Compression (behavioral, not a header flag)

- There is **no** compress flag in the header.
- Encrypt path (CLI): optional gzip of plaintext **before** AEAD when `--compress` / config enables it and size heuristics pass (`ShouldCompress`, min 1 KiB, skip if already gzip magic `1f 8b`).
- Decrypt path (CLI): after successful AEAD open, if plaintext begins with gzip magic, attempt gunzip; on failure, keep raw plaintext.
- Spec MUST label this as **implementation behavior**, not a versioned format feature, and note ambiguity risk (plaintext that happens to start with gzip magic).

### 10. Compatibility matrix

| Writer \ Reader | v1 reader semantics | v2 reader |
| --- | --- | --- |
| Historical v1 file | Decrypt with default KDF | Same (v1 branch) |
| Current v2 file | N/A (unsupported version if truly v1-only) | Decrypt with header KDF |
| Current writer | Always emits v2 | Required |

Also state:

- Newer NokVault decrypts both v1 and v2.
- Older pre-v2 tools cannot read v2 headers.
- Custom KDF on v2 files will not round-trip on readers that ignore header KDF (pre-N2).

### 11. Reject rules (normative)

Readers MUST fail closed when:

1. Magic ≠ `NOKVAULT`
2. Truncated header / truncated metadata
3. Version ∉ {1, 2}
4. v2 KDF params fail validation caps / KeyLength ≠ 32
5. `MetadataSize` > 1 MiB
6. `DataOffset` ≠ header wire size + `MetadataSize`
7. Salt length on write ≠ 16 (writers)
8. Ciphertext shorter than nonce + tag
9. GCM authentication failure

### 12. Known limitations (non-normative but required)

Document explicitly for audit readiness:

- Empty GCM AAD — header/version/salt/metadata not AEAD-bound
- No stored compress / algorithm IDs beyond version + Argon2 params
- Whole-file-in-memory encrypt/decrypt (streaming is L2)
- Compression inferred by magic after decrypt

Do **not** propose a v3 layout in the published spec body beyond a one-line “future work may add authenticated header binding and an explicit compress flag.”

### 13. Out of scope sections

Omit or one-liner only: CLI flags, keyfiles, password prompting, watch/schedule, secure-delete, packaging.

## Success criteria

- A crypto reviewer can answer from `docs/format-v2.md` alone: endianness, field offsets/sizes, KDF, AEAD framing, what is/isn’t authenticated, v1 vs v2, and what to reject.
- No invented wire fields.
- Document length stays reviewable (target: roughly a short RFC-style note, not a book).
- Implementation plan can be executed as docs-only PR on branch `docs/l1-format-v2-spec`.

## Implementation plan expectations (next skill)

After this design is accepted as written:

1. Draft `docs/format-v2.md` from the outline above, cross-checking offsets against `HeaderWireSize` / `WriteHeader` / `ReadHeader`.
2. Add a minimal README pointer if a natural anchor exists.
3. Self-check: no TBD placeholders; AAD and compression wording match code.
4. Open PR from `docs/l1-format-v2-spec` (docs-only).

## Open risks (accepted)

- Audit checklist still mentions “persisted compress fields”; L1 documents the gap rather than closing it. Closing it is a separate format-bump item, not L1.
- Putting the markdown under `docs/` (Astro package) may confuse contributors; mitigate with a one-line note at the top of `format-v2.md`: “Wire format spec (not an Astro page).”
