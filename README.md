# Nokvault

[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8?style=flat-square&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/jimididit/nokvault/release.yml?style=flat-square)](https://github.com/jimididit/nokvault/actions)
[![Release](https://img.shields.io/github/v/release/jimididit/nokvault?style=flat-square)](https://github.com/jimididit/nokvault/releases)

A modern, feature-rich CLI tool for encrypting and protecting local folders and files. Built with Go for cross-platform support (Windows, Linux, macOS).

## Features

- **🔒 Strong Encryption**: AES-256-GCM authenticated encryption with Argon2id key derivation
- **📁 Directory Support**: Encrypt entire directories recursively with metadata preservation
- **🔑 Flexible Authentication**: Password, keyfile, or environment variable support
- **⚡ Auto-Encryption**: Watch directories and automatically encrypt files on change
- **🔄 Key Rotation**: Rotate encryption keys without re-encrypting data
- **🗑️ Secure Deletion**: Overwrite files multiple times before deletion
- **📦 Compression**: Optional compression before encryption
- **⚙️ Configuration**: Global and per-project configuration files
- **📊 Progress Tracking**: Visual progress bars for operations
- **🌐 Cross-Platform**: Single binary for Windows, Linux, and macOS

## Quick Start

### Installation

**Download pre-built binaries:**

```bash
# Visit https://github.com/jimididit/nokvault/releases
# Download the binary for your platform
```

**Or build from source:**

```bash
git clone https://github.com/jimididit/nokvault.git
cd nokvault
# Windows
go build -o nokvault.exe ./cmd/nokvault

# Linux/macOS
go build -o nokvault ./cmd/nokvault
```

**Package managers** (coming soon):

```bash
# Homebrew (macOS) - Coming soon
# brew install nokvault

# Scoop (Windows) - Coming soon
# scoop install nokvault

# APT (Debian/Ubuntu) - Coming soon
# sudo apt install nokvault
```

### Basic Usage

```bash
# Encrypt a file
nokvault encrypt document.txt

# Decrypt a file
nokvault decrypt document.txt.nokvault

# Encrypt a directory
nokvault encrypt ./documents

# Use a keyfile
nokvault encrypt file.txt --keyfile ~/.keys/master.key

# Watch and auto-encrypt
nokvault watch ./documents --auto-encrypt --keyfile ~/.keys/master.key

# Schedule periodic encryption
nokvault schedule encrypt ./backups --interval 1h

# Rotate encryption key
nokvault rotate-key file.nokvault

# Securely delete a file
nokvault secure-delete sensitive-file.txt
```

## Commands

| Command | Description |
| --------- | ------------- |
| `encrypt <path>` | Encrypt a file or directory |
| `decrypt <path>` | Decrypt a nokvault encrypted file |
| `watch <path>` | Watch directory for changes and optionally auto-encrypt |
| `schedule encrypt <path>` | Schedule periodic encryption operations |
| `rotate-key <path>` | Rotate encryption key for a file |
| `secure-delete <path>` | Securely delete a file with multiple overwrite passes |
| `config` | Manage configuration settings |

## Configuration

Initialize configuration:

```bash
nokvault config --init
```

View current settings:

```bash
nokvault config --show
```

Configuration files:

- Global: `~/.config/nokvault/config.toml`
- Local: `.nokvault.toml` (in current directory)

## Advanced Usage

**Compression:**

```bash
nokvault encrypt large-file.bin --compress
```

**Exclude patterns:**

```bash
nokvault encrypt ./documents --exclude "*.tmp" --exclude "*.log"
```

**Use environment variable:**

```bash
export NOKVAULT_PASSWORD="your-password"
nokvault encrypt file.txt --no-prompt
```

**Watch directory with auto-encrypt:**

```bash
nokvault watch ./sensitive --auto-encrypt \
  --keyfile ~/.keys/master.key \
  --delay 5s \
  --exclude "*.tmp"
```

**Dry run:**

```bash
nokvault encrypt ./files --dry-run
```

**Verbose output:**

```bash
nokvault encrypt ./files -v
```

## Known Limitations

- **`protect` command**: Directory protection (archive mode) is not yet fully implemented. Use `encrypt` for individual files or directories.
- **Package managers**: Homebrew, Scoop, and APT support is planned but not yet available. Download binaries from [GitHub Releases](https://github.com/jimididit/nokvault/releases).
- **Edge cases**: Some edge cases may need additional testing. Please report any issues you encounter.
- **CLI flag persistence**: In test environments, Cobra flags may persist between test runs (does not affect normal usage).

## Security

- **Encryption**: AES-256-GCM authenticated encryption
- **Key Derivation**: Argon2id with configurable parameters
- **Memory Safety**: Sensitive data zeroized after use
- **Timing Attack Protection**: Constant-time operations
- **File Integrity**: Built-in authentication tags

### Security Best Practices

1. **Use keyfiles** instead of passwords when possible
2. **Rotate keys** periodically using `rotate-key`
3. **Use secure deletion** for sensitive files: `secure-delete`
4. **Never commit** passwords or keyfiles to version control
5. **Use environment variables** for automation: `NOKVAULT_PASSWORD`

## Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes and add tests
4. Ensure all tests pass: `go test ./...`
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

Please ensure code follows Go conventions and includes appropriate tests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Documentation

📚 **[Full Documentation Website](https://jimididit.github.io/nokvault/)** - Complete documentation with examples, guides, and API reference.

## Support

- **Issues**: [GitHub Issues](https://github.com/jimididit/nokvault/issues)
- **Discussions**: [GitHub Discussions](https://github.com/jimididit/nokvault/discussions)

---

Made with ❤️ using Go
