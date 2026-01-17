# Changelog

All notable changes to Nokvault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-01-16

### Added

- Initial public release
- **Core Encryption Features**:
  - AES-256-GCM authenticated encryption
  - Argon2id key derivation with configurable parameters
  - Support for password, keyfile, and environment variable authentication
  - File and directory encryption/decryption with metadata preservation
  - Optional compression before encryption (gzip)

- **CLI Commands**:
  - `encrypt` - Encrypt files or directories
  - `decrypt` - Decrypt nokvault encrypted files
  - `watch` - Watch directories for changes and optionally auto-encrypt
  - `schedule` - Schedule periodic encryption operations
  - `rotate-key` - Rotate encryption keys without re-encrypting data
  - `secure-delete` - Securely delete files with multiple overwrite passes
  - `config` - Manage configuration settings
  - `protect` - Directory protection (partial implementation)

- **Security Features**:
  - Secure memory handling (zeroization of sensitive data)
  - Constant-time operations for timing attack protection
  - Secure file deletion with multiple overwrite passes
  - File integrity verification via authentication tags

- **User Experience**:
  - Progress bars for long-running operations
  - Verbose output mode
  - Dry-run mode for testing
  - Helpful error messages with hints
  - Cross-platform support (Windows, Linux, macOS)

- **Configuration**:
  - Global configuration file (`~/.config/nokvault/config.toml`)
  - Local configuration file (`.nokvault.toml`)
  - Environment variable support (`NOKVAULT_PASSWORD`)

- **Documentation**:
  - Comprehensive README with quick start guide
  - GitHub Pages documentation site
  - Contributing guidelines
  - Security best practices guide

- **Testing**:
  - Unit tests for core cryptography (80% coverage)
  - Unit tests for file operations (67% coverage)
  - Integration tests for end-to-end workflows
  - CLI integration tests

- **CI/CD**:
  - Automated cross-platform builds (Windows, Linux, macOS)
  - Automated release workflow
  - Automated documentation deployment

### Known Limitations

- `protect` command is not yet fully implemented
- Package manager support (Homebrew, Scoop, APT) coming soon
- Some edge cases may need additional testing

[0.1.0]: https://github.com/jimididit/nokvault/releases/tag/v0.1.0
