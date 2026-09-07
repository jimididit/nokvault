# Nokvault file format (contributor sketch)

This is a short reference for the on-disk `.nokvault` container. For the full design rationale see `docs/superpowers/specs/2026-09-07-n2-kdf-header-params-design.md`.

## Endianness

All multi-byte integers are **little-endian**.

## Header layout

| Field | Size | v1 | v2 | Notes |
|-------|------|----|----|-------|
| Magic | 8 | ✓ | ✓ | ASCII `NOKVAULT` |
| Version | 2 | ✓ | ✓ | `1` or `2` |
| Salt | 16 | ✓ | ✓ | Random per file |
| MetadataSize | 4 | ✓ | ✓ | Length of JSON metadata block |
| DataOffset | 8 | ✓ | ✓ | Byte offset of ciphertext from file start |
| Memory | 4 | — | ✓ | Argon2 memory cost (KiB) |
| Time | 4 | — | ✓ | Argon2 time cost |
| Parallelism | 1 | — | ✓ | Argon2 parallelism |
| _pad | 3 | — | ✓ | Zero padding for alignment |
| KeyLength | 4 | — | ✓ | Derived key length (32 bytes today) |

- **v1 wire size:** 38 bytes (+ metadata JSON + ciphertext)
- **v2 wire size:** 54 bytes (+ metadata JSON + ciphertext)

`DataOffset` equals header size for the file's version plus `MetadataSize`.

## Version policy

| Version | Write | Decrypt KDF |
|---------|-------|-------------|
| **1** | Legacy (no longer written) | Built-in defaults: 65536 KiB memory, time 3, parallelism 4, key length 32 |
| **2** | Current (`CurrentVersion`) | Parameters read from header |
| **other** | — | Rejected with unsupported-version error |

## Metadata and payload

After the header:

1. **Metadata** — UTF-8 JSON (`MetadataSize` bytes): original filename, mode, mtime, etc.
2. **Ciphertext** — AES-256-GCM payload (IV + encrypted data + auth tag)

KDF parameters in the header are not secret; integrity relies on GCM over the payload.

## Config vs header

- **Encrypt-side** (new files): uses `[key_derivation]` from config when deriving keys and writes params into v2 header.
- **Decrypt-side**: ignores config; uses header params (v2) or v1 defaults.
