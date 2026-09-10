# Security Policy

## Supported Versions

We actively support the following versions of Nokvault with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| ≤ 0.3.x | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in Nokvault, please follow these steps:

### 1. **Do NOT** create a public GitHub issue

Security vulnerabilities should be reported privately to prevent exploitation before a fix is available.

### 2. Report the vulnerability

Please email security concerns to: **<security@jimididit.com>** (or open a private security advisory on GitHub)

Include the following information:

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if any)

### 3. Response timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity, typically 30-90 days

### 4. Disclosure

We will coordinate with you on the disclosure timeline. Once a fix is available:

- A security advisory will be published on GitHub
- The vulnerability will be listed in the CHANGELOG
- A new release will be made with the fix

## Security Best Practices

### For Users

1. **Keep Nokvault Updated**: Always use the latest version to receive security patches
2. **Use Strong Passwords**: Use long, random passwords or keyfiles
3. **Protect Keyfiles**: Store keyfiles securely with appropriate permissions (600 on Unix)
4. **Use Keyfiles**: Prefer keyfiles over passwords when possible
5. **Secure Deletion**: Use `secure-delete` for sensitive files
6. **Rotate Keys**: Periodically rotate encryption keys using `rotate-key`
7. **Verify Downloads**: Verify release checksums and GitHub build provenance with `gh attestation verify <binary> --repo jimididit/nokvault`
8. **Regular Paths**: Point commands at regular files and directories; Nokvault does not follow symlinks or junctions

### For Developers

1. **Dependency Updates**: Keep dependencies up to date
2. **Code Review**: All security-sensitive code changes require review
3. **Testing**: Ensure security-related tests pass before merging
4. **Documentation**: Document security implications of changes
5. **Automated Analysis**: CI runs vulnerability, static, and security-focused analysis on every change

## Security Features

Nokvault implements several security measures:

- **Authenticated Encryption**: AES-256-GCM provides confidentiality and authenticity for the encrypted **payload** (header/metadata are not AEAD-bound; see Threat Model and [`docs/format-v2.md`](docs/format-v2.md))
- **Key Derivation**: Argon2id with configurable parameters prevents brute-force attacks
- **Memory Safety**: Sensitive data is zeroized after use
- **Timing Attack Protection**: Constant-time operations for key comparisons
- **File Integrity**: Built-in authentication tags detect tampering
- **Secure Deletion**: Multi-pass overwrite before unlink (effectiveness depends on storage media; see Residual Risks)
- **Path policy**: Default-deny for symlinks, Windows junctions, and other reparse points; lexical output containment. Not a claim of race-proof concurrent replacement protection.
- **Format documentation**: On-disk layout and AEAD binding limits are documented in [`docs/format-v2.md`](docs/format-v2.md)

## Threat Model

This section describes what NokVault protects, against whom, and what it explicitly does not claim. It matches the current implementation. Wire-format details live in [`docs/format-v2.md`](docs/format-v2.md).

### Product scope

NokVault is a local CLI for encrypting files and directories, with optional watch, schedule, and secure-delete helpers. It is **not** a backup system, network sync service, full-disk encryptor, or multi-recipient sharing tool.

### Assets

- User plaintext (source files and transient plaintext during encrypt, decrypt, and `rotate-key`)
- Secrets: interactive passwords, keyfile bytes, and `NOKVAULT_PASSWORD`
- Derived AES-256 keys and salts in process memory
- On-disk `.nokv` containers (legacy `.nokvault` filenames still decrypt; header, optional plaintext JSON metadata, ciphertext payload)
- Released binaries and their checksum / attestation metadata

### Attackers and environments

| Class | What we model |
| --- | --- |
| Offline vault thief | Possesses `.nokv` / legacy `.nokvault` file(s) but not the password or keyfile |
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

## Security Audit

Start with this document's **Threat Model** and **Residual Risks**, plus the wire format in [`docs/format-v2.md`](docs/format-v2.md).

If you're conducting a security audit or penetration test:

1. Please notify us in advance if possible
2. Follow responsible disclosure practices
3. We welcome security research and will work with you

## Acknowledgments

We thank security researchers who responsibly disclose vulnerabilities. Contributors will be acknowledged (with permission) in security advisories and release notes.
