package utils

import (
	"fmt"
	"path/filepath"
	"strings"
)

const (
	// VaultExt is the default suffix for newly written vault files and directories.
	VaultExt = ".nokv"
	// LegacyVaultExt is accepted on read for vaults written before the .nokv rename.
	LegacyVaultExt = ".nokvault"
)

// IsVaultPath reports whether path refers to a vault file or directory by suffix.
func IsVaultPath(path string) bool {
	return HasVaultExt(filepath.Base(path))
}

// HasVaultExt reports whether name ends with VaultExt or LegacyVaultExt.
func HasVaultExt(name string) bool {
	return strings.HasSuffix(name, VaultExt) || strings.HasSuffix(name, LegacyVaultExt)
}

// StripVaultExt removes a vault suffix from path. It prefers the longer legacy
// suffix when both could apply (they cannot with the current constants).
func StripVaultExt(path string) (string, bool) {
	switch {
	case strings.HasSuffix(path, LegacyVaultExt):
		return path[:len(path)-len(LegacyVaultExt)], true
	case strings.HasSuffix(path, VaultExt):
		return path[:len(path)-len(VaultExt)], true
	default:
		return path, false
	}
}

// WithVaultExt appends VaultExt to path. If path already has a vault suffix, it is returned unchanged.
func WithVaultExt(path string) string {
	if IsVaultPath(path) {
		return path
	}
	return path + VaultExt
}

// DefaultVaultOutput returns the default encrypt output path for input.
// Trailing separators are cleaned so "test/" becomes "test.nokv", not "test/.nokv".
// Clean results of "." or ".." are rejected; pass a concrete path or --output.
func DefaultVaultOutput(input string) (string, error) {
	cleaned := filepath.Clean(input)
	if cleaned == "." || cleaned == ".." {
		return "", fmt.Errorf("cannot derive default output for %q; pass a concrete path or --output", input)
	}
	return WithVaultExt(cleaned), nil
}
