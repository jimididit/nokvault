package utils

import (
	"crypto/subtle"
	"runtime"
)

// SecureZeroize securely zeroizes a byte slice
// Uses runtime.KeepAlive to prevent compiler optimizations
func SecureZeroize(data []byte) {
	if len(data) == 0 {
		return
	}

	// Zeroize the data
	for i := range data {
		data[i] = 0
	}

	// Prevent compiler optimizations that might remove the zeroization
	runtime.KeepAlive(data)
}

// SecureCompare performs constant-time comparison of two byte slices
// Returns true if slices are equal, false otherwise
func SecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// SecureCopy copies data securely, zeroizing the source after copying
func SecureCopy(dst, src []byte) {
	copy(dst, src)
	SecureZeroize(src)
}
