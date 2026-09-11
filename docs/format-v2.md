# NokVault vault format (v1 / v2 / v3)

> Wire format specification for NokVault vault files (default filename suffix `.nokv`; legacy `.nokvault` still accepted on read). This file lives under the
> `docs/` package directory for versioning; it is **not** an Astro website page.

**Status:** Implemented (matches current NokVault Go sources)  
**Current writer version:** 3
**Reader versions:** 1, 2, and 3
**Endianness:** Little-endian for all multi-byte integers  
**Audience:** Crypto reviewers and alternate implementers

## 1. Purpose

This document is the normative on-disk layout for NokVault vault files. The
filename is retained for stable links even though it now specifies v3. It
describes what is written and accepted today so the format can be reviewed
without reading Go structs.

## 2. File layout

```text
[ header — 38 bytes (v1), 54 bytes (v2), or 58 bytes (v3) ]
[ optional UTF-8 JSON metadata — MetadataSize bytes ]
[ encrypted payload — legacy blob (v1/v2) or STREAM (v3) ]
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
default Argon2id parameters in §6.

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

## 5. Header version 3 (58 bytes)

Version 3 is identical to v2 through `KeyLength`, with Version = `3`, then:

| Offset | Size | Type | Field |
| --- | --- | --- | --- |
| 54 | 1 | u8 | Compress (`0` = none, `1` = gzip before STREAM) |
| 55 | 3 | bytes | Pad (writers MUST write zeros; readers MUST consume and ignore) |

`HeaderWireSize(3) = 58`.

`Compress` values other than `0` or `1` MUST be rejected. KDF parameter caps
and `KeyLength` rules are the same as v2.

## 6. Key derivation (Argon2id)

- Algorithm: Argon2id (`argon2.IDKey` semantics from `golang.org/x/crypto/argon2`)
- Salt length: 16 bytes
- Defaults (used for all v1 files and as writer defaults):
  - Memory = `65536` KiB (64 MiB)
  - Time = `3`
  - Parallelism = `4`
  - KeyLength = `32`

Accepted / persisted parameter caps (v2/v3 headers and current writers):

| Parameter | Allowed range |
| --- | --- |
| Memory | 1 … 262144 KiB (max 256 MiB) |
| Time | 1 … 10 |
| Parallelism | 1 … 16 |
| KeyLength | MUST equal 32 |

Zero values for Memory, Time, or Parallelism are invalid.

## 7. Version negotiation

| Role | Rule |
| --- | --- |
| Current writer | MUST write version `3` |
| Reader | MUST accept versions `1`, `2`, and `3` |
| Reader | MUST reject any other version |

A new on-disk version requires a format bump and an update to this document.

## 8. Optional metadata

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

Metadata is plaintext on disk. In v1/v2 it is not covered by AES-GCM. In v3,
its exact on-disk bytes are authenticated as AAD for every STREAM chunk.

## 9. Legacy encrypted payload and AAD (v1/v2)

- Cipher: AES-256-GCM
- Key: 32-byte Argon2id output
- Nonce: 12 random bytes, prepended
- Tag: 16-byte GCM tag (appended by GCM; part of the sealed blob)
- On-disk payload after `DataOffset`: `nonce (12) || ciphertext||tag`

**Additional authenticated data (AAD): empty.** Legacy decryption passes
nil AAD to GCM Seal/Open. The header (including version, salt, and KDF fields)
and optional metadata are **not** cryptographically bound into the AEAD.

Minimum ciphertext length after `DataOffset`: 12 + 16 = 28 bytes.

## 10. Version 3 STREAM payload and AAD

The payload beginning at `DataOffset` is:

```text
[ stream nonce prefix — 8 random bytes ]
[ AES-256-GCM STREAM chunks ]
```

Each chunk seals at most 65536 plaintext bytes. Its 12-byte GCM nonce is the
8-byte stream nonce prefix followed by a big-endian `uint32` counter. Counters
start at zero; the high bit (`0x80000000`) is set only for the final chunk.
Counter byte order is the sole exception to the header's little-endian rule.

Non-final chunks MUST contain exactly 65536 plaintext bytes and occupy 65552
bytes on disk (plaintext/ciphertext plus the 16-byte GCM tag). The final chunk
contains 0 through 65536 plaintext bytes plus its tag. When the plaintext size
is an exact multiple of 65536, including zero, writers MUST emit a final empty
chunk. There is no per-chunk length field.

For every chunk:

```text
AAD = exact 58-byte header || exact MetadataSize bytes from disk
```

The header includes both pad regions. Metadata bytes are used directly, not
re-marshaled from JSON. Changing any authenticated header or metadata byte
causes GCM authentication to fail.

Readers MUST reject truncated streams, missing final-chunk marking,
authentication failures, and non-final chunks that do not decode to exactly
65536 bytes. The minimum v3 payload is 24 bytes: an 8-byte prefix and a
16-byte tag for the empty final chunk.

## 11. Compression

For v3, `Compress=1` means plaintext was passed through streaming gzip before
STREAM encryption; `Compress=0` means it was not. Readers MUST follow this
flag after successful authentication and MUST report invalid gzip data as an
error. Writers set `Compress=1` only when gzip actually runs.

For v1/v2 there is no compression flag. Legacy CLI behavior is:

1. On encrypt, optional gzip may run on plaintext **before** AEAD when compression
   is enabled and heuristics allow it (typically size > 1 KiB; skip if input
   already starts with gzip magic `1f 8b`).
2. On decrypt, after successful AEAD open, if plaintext starts with `1f 8b`, the
   CLI attempts gunzip; on failure it keeps the raw plaintext.

Treat v1/v2 sniffing as legacy implementation behavior, not a versioned format
feature. Plaintext that legitimately begins with gzip magic may be mis-handled
by decompress sniffing.

## 12. Compatibility matrix

| Vault file | Current NokVault (v1–v3) | v2-only tool | v1-only tool |
| --- | --- | --- | --- |
| Historical v1 | Decrypt using default KDF | Decrypt using default KDF | Decrypt using default KDF |
| Legacy v2 | Decrypt using header KDF | Decrypt using header KDF | Unsupported version |
| Current v3 | Decrypt STREAM using header KDF | Unsupported version | Unsupported version |
| Current writer output | Always version 3 | Cannot read | Cannot read |

Notes:

- Current NokVault decrypts v1, v2, and v3.
- Custom KDF parameters on v2 files will not round-trip on readers that ignore
  header KDF fields (pre-N2 tools).

## 13. Reject rules

Readers MUST fail closed when any of the following hold:

1. Magic ≠ `NOKVAULT`
2. Truncated header or truncated metadata
3. Version ∉ {1, 2, 3}
4. For v2/v3: KDF params outside §6 caps, or KeyLength ≠ 32
5. `MetadataSize` > 1048576
6. `DataOffset` ≠ header wire size + `MetadataSize`
7. Writer salt length ≠ 16
8. For v1/v2: payload shorter than nonce + tag (28 bytes)
9. For v3: `Compress` ∉ {0, 1}, malformed/truncated STREAM framing, missing
   final chunk, or invalid gzip when `Compress=1`
10. GCM authentication failure

## 14. Known limitations

- v1/v2 use empty GCM AAD, so their header and metadata are not AEAD-bound.
- v1/v2 decrypt buffers the whole encrypted payload in memory; v3 encryption
  and decryption use bounded STREAM chunks.
- v1/v2 have no stored compress flag and infer compression by post-decrypt magic.
- No cipher or KDF algorithm IDs are stored beyond version and Argon2 parameters.
- Metadata remains visible in plaintext even though v3 authenticates it.

## 15. Out of scope

CLI flags, keyfiles, password prompting, watch/schedule, secure-delete, packaging,
and website UX are outside this document.
