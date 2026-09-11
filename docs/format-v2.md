# NokVault vault format (v1 / v2 / v3 / v4)

> Wire format specification for NokVault vault files (default filename suffix `.nokv`; legacy `.nokvault` still accepted on read). This file lives under the
> `docs/` package directory for versioning; it is **not** an Astro website page.

**Status:** Implemented (matches current NokVault Go sources)  
**Current writer version:** 3 (passphrase/keyfile); 4 (recipient mode)  
**Reader versions:** 1, 2, 3, and 4  
**Endianness:** Little-endian for all multi-byte integers  
**Audience:** Crypto reviewers and alternate implementers

## 1. Purpose

This document is the normative on-disk layout for NokVault vault files. The
filename is retained for stable links even though it now specifies v4. It
describes what is written and accepted today so the format can be reviewed
without reading Go structs.

## 2. File layout

```text
[ header — 38 bytes (v1), 54 bytes (v2), 58 bytes (v3), or 62 bytes (v4) ]
[ optional UTF-8 JSON metadata — MetadataSize bytes ]
[ recipient section — RecipientCount × 80 bytes (v4 only) ]
[ encrypted payload — legacy blob (v1/v2) or STREAM (v3/v4) ]
```

Magic bytes are ASCII `NOKVAULT` (8 bytes, no trailing NUL).

For v4, `DataOffset` MUST equal `62 + MetadataSize + (RecipientCount × 80)`.

## 3. Header version 1 (38 bytes)

| Offset | Size | Type | Field |
| --- | --- | --- | --- |
| 0 | 8 | bytes | Magic = `NOKVAULT` |
| 8 | 2 | u16 | Version = `1` |
| 10 | 16 | bytes | Salt |
| 26 | 4 | u32 | MetadataSize |
| 30 | 8 | u64 | DataOffset |

Version 1 does **not** store KDF parameters. Readers MUST derive keys using the
default Argon2id parameters in §7.

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

## 6. Header version 4 (62 bytes)

Version 4 is identical to v3 through `Compress/pad`, with Version = `4`, then:

| Offset | Size | Type | Field |
| --- | --- | --- | --- |
| 58 | 2 | u16 | RecipientCount (`1…MaxRecipients`) |
| 60 | 2 | bytes | Pad (writers MUST write zeros; readers MUST consume and ignore) |

`HeaderWireSize(4) = 62`. `MaxRecipients = 20`.

**Recipient-mode header rules (v4):**

- `Salt` MUST be 16 zero bytes.
- `Memory`, `Time`, and `Parallelism` MUST be zero.
- `KeyLength` MUST be `32`.
- `Compress` ∈ {0, 1} as in v3.
- Readers MUST reject non-zero salt or non-zero KDF fields on v4 (L3.1 recipient-only vaults).
- `RecipientCount` MUST be in `1…20`. Zero is invalid for v4.

The 32-byte file key is not derived from Argon2id on v4; it is random and wrapped per recipient (§6.2).

### 6.1 Recipient stanza (80 bytes, binary)

Each stanza is written contiguously after metadata:

| Offset | Size | Content |
| --- | --- | --- |
| 0 | 32 | Ephemeral X25519 public key |
| 32 | 48 | ChaCha20-Poly1305 ciphertext‖tag over the 32-byte file key |

There is no per-stanza type byte in L3.1 (X25519-only).

### 6.2 File-key wrap (normative)

For each recipient public key `R` (32 bytes):

1. Generate ephemeral X25519 key pair `(eph_sk, eph_pk)`.
2. `shared = X25519(eph_sk, R)` (RFC 7748); reject low-order/all-zero shared secrets as age does.
3. `wrap_key = HKDF-SHA256(ikm=shared, salt=eph_pk || R, info="nokvault.org/v4/X25519", L=32)`.
4. `body = ChaCha20-Poly1305-Seal(key=wrap_key, nonce=12×0x00, plaintext=file_key, aad=empty)`.
5. Write stanza `eph_pk || body` (32 + 48).

Unwrap: for each identity secret `i` and each stanza, recompute the shared secret with `eph_pk`, derive `wrap_key`, and open `body`. The first successful open yields `file_key`. Failures on individual stanzas are silent; if none succeed, return a generic error.

**Domain separation:** HKDF info MUST be `nokvault.org/v4/X25519` (not age’s info string), even though the construction mirrors age.

## 7. Key derivation (Argon2id)

Applies to passphrase/keyfile vaults (versions 1–3). Version 4 recipient vaults do not use Argon2id for the file key.

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

Zero values for Memory, Time, or Parallelism are invalid on v2/v3. On v4, KDF fields MUST be zero (see §6).

## 8. Version negotiation

| Role | Rule |
| --- | --- |
| Passphrase/keyfile writer | MUST write version `3` |
| Recipient writer | MUST write version `4` |
| Reader | MUST accept versions `1`, `2`, `3`, and `4` |
| Reader | MUST reject any other version |

Passphrase and recipient modes MUST NOT be mixed on the same vault in L3.1.

A new on-disk version requires a format bump and an update to this document.

## 9. Optional metadata

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

**Invariant:** `DataOffset` MUST equal `HeaderWireSize(version) + MetadataSize` for v1–v3, and `62 + MetadataSize + (RecipientCount × 80)` for v4.
Readers MUST reject any other value.

Metadata is plaintext on disk. In v1/v2 it is not covered by AES-GCM. In v3/v4,
its exact on-disk bytes are authenticated as AAD for every STREAM chunk.

## 10. Legacy encrypted payload and AAD (v1/v2)

- Cipher: AES-256-GCM
- Key: 32-byte Argon2id output
- Nonce: 12 random bytes, prepended
- Tag: 16-byte GCM tag (appended by GCM; part of the sealed blob)
- On-disk payload after `DataOffset`: `nonce (12) || ciphertext||tag`

**Additional authenticated data (AAD): empty.** Legacy decryption passes
nil AAD to GCM Seal/Open. The header (including version, salt, and KDF fields)
and optional metadata are **not** cryptographically bound into the AEAD.

Minimum ciphertext length after `DataOffset`: 12 + 16 = 28 bytes.

## 11. Version 3 / 4 STREAM payload and AAD

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
AAD (v3) = exact 58-byte header || exact MetadataSize bytes from disk

AAD (v4) = exact 62-byte header || exact MetadataSize bytes || exact recipient section bytes
```

The header includes both pad regions. Metadata and (for v4) recipient section bytes are used directly from disk, not re-marshaled or re-encoded. Changing any authenticated header, metadata, or recipient stanza byte causes GCM authentication to fail.

Readers MUST reject truncated streams, missing final-chunk marking,
authentication failures, and non-final chunks that do not decode to exactly
65536 bytes. The minimum v3/v4 payload is 24 bytes: an 8-byte prefix and a
16-byte tag for the empty final chunk.

## 12. Compression

For v3/v4, `Compress=1` means plaintext was passed through streaming gzip before
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

## 13. Compatibility matrix

| Vault file | Current NokVault (v1–v4) | v3-only tool | v2-only tool | v1-only tool |
| --- | --- | --- | --- | --- |
| Historical v1 | Decrypt using default KDF | Unsupported version | Decrypt using default KDF | Decrypt using default KDF |
| Legacy v2 | Decrypt using header KDF | Unsupported version | Decrypt using header KDF | Unsupported version |
| Passphrase v3 | Decrypt STREAM using header KDF | Decrypt STREAM using header KDF | Unsupported version | Unsupported version |
| Recipient v4 | Decrypt with `--identity` | Unsupported version | Unsupported version | Unsupported version |
| Passphrase writer output | Always version 3 | Can read | Cannot read | Cannot read |
| Recipient writer output | Always version 4 | Cannot read | Cannot read | Cannot read |

Notes:

- Current NokVault decrypts v1, v2, v3, and v4.
- Custom KDF parameters on v2 files will not round-trip on readers that ignore
  header KDF fields (pre-N2 tools).
- v4 vaults require NokVault (or another v4 implementer); they are not age-compatible files.

## 14. Reject rules

Readers MUST fail closed when any of the following hold:

1. Magic ≠ `NOKVAULT`
2. Truncated header, metadata, or (v4) recipient section
3. Version ∉ {1, 2, 3, 4}
4. For v2/v3: KDF params outside §7 caps, or KeyLength ≠ 32
5. For v4: non-zero salt or non-zero KDF fields; `RecipientCount` ∉ {1…20}; recipient section size mismatch
6. `MetadataSize` > 1048576
7. `DataOffset` ≠ expected offset for the version (see §9)
8. Writer salt length ≠ 16 (v1–v3); v4 salt MUST be all zeros
9. For v1/v2: payload shorter than nonce + tag (28 bytes)
10. For v3/v4: `Compress` ∉ {0, 1}, malformed/truncated STREAM framing, missing
   final chunk, or invalid gzip when `Compress=1`
11. GCM authentication failure
12. (v4) No recipient stanza unwraps with the supplied identity

## 15. Known limitations

- v1/v2 use empty GCM AAD, so their header and metadata are not AEAD-bound.
- v1/v2 decrypt buffers the whole encrypted payload in memory; v3/v4 encryption
  and decryption use bounded STREAM chunks.
- v1/v2 have no stored compress flag and infer compression by post-decrypt magic.
- No cipher or KDF algorithm IDs are stored beyond version and Argon2 parameters.
- Metadata remains visible in plaintext even though v3/v4 authenticate it.
- v4 provides multi-recipient sharing within NokVault’s wire format but is not interoperable with age/rage files.
- v4 does not provide cross-file forward secrecy; compromise of an identity key decrypts all vaults wrapped to that recipient.

## 16. Out of scope

CLI flags, keyfiles, password prompting, identity encoding (`nokvault keygen`), watch/schedule on v4 vaults, secure-delete, packaging,
and website UX are outside this document.
