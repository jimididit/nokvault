# NokVault vault format (v1 / v2)

> Wire format specification for NokVault vault files (default filename suffix `.nokv`; legacy `.nokvault` still accepted on read). This file lives under the
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

| Vault file | Modern NokVault (v1+v2) | Pre-v2 / v1-only tool |
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
