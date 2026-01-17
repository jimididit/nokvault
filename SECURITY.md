# Security Policy

## Supported Versions

We actively support the following versions of Nokvault with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

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
7. **Verify Downloads**: Always verify checksums when downloading binaries

### For Developers

1. **Dependency Updates**: Keep dependencies up to date
2. **Code Review**: All security-sensitive code changes require review
3. **Testing**: Ensure security-related tests pass before merging
4. **Documentation**: Document security implications of changes

## Security Features

Nokvault implements several security measures:

- **Authenticated Encryption**: AES-256-GCM provides both confidentiality and authenticity
- **Key Derivation**: Argon2id with configurable parameters prevents brute-force attacks
- **Memory Safety**: Sensitive data is zeroized after use
- **Timing Attack Protection**: Constant-time operations for key comparisons
- **File Integrity**: Built-in authentication tags detect tampering
- **Secure Deletion**: Multiple overwrite passes make file recovery difficult

## Known Security Considerations

1. **Key Storage**: Nokvault does not store encryption keys. Users must manage keys securely.
2. **Memory**: While we zeroize sensitive data, operating system memory management may retain data in swap files or memory dumps.
3. **Secure Deletion**: Secure deletion effectiveness depends on storage media (SSD vs HDD) and file system.
4. **Key Derivation**: Default Argon2id parameters provide good security but may be slow on low-resource devices.

## Security Audit

If you're conducting a security audit or penetration test:

1. Please notify us in advance if possible
2. Follow responsible disclosure practices
3. We welcome security research and will work with you

## Acknowledgments

We thank security researchers who responsibly disclose vulnerabilities. Contributors will be acknowledged (with permission) in security advisories and release notes.
