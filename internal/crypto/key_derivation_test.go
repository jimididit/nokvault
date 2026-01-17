package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveKey(t *testing.T) {
	password := []byte("test-password-123")
	salt, err := GenerateSalt()
	require.NoError(t, err, "Failed to generate salt")

	params := DefaultArgon2Params()
	key, err := DeriveKey(password, salt, params)
	require.NoError(t, err, "Key derivation should succeed")

	// Verify key length
	assert.Equal(t, int(params.KeyLength), len(key), "Key length should match params")

	// Verify key is not all zeros
	allZeros := true
	for _, b := range key {
		if b != 0 {
			allZeros = false
			break
		}
	}
	assert.False(t, allZeros, "Derived key should not be all zeros")
}

func TestDeriveKeyDeterministic(t *testing.T) {
	password := []byte("test-password")
	salt := make([]byte, SaltLength)
	for i := range salt {
		salt[i] = byte(i)
	}

	params := DefaultArgon2Params()

	// Derive key twice with same inputs
	key1, err := DeriveKey(password, salt, params)
	require.NoError(t, err, "First key derivation should succeed")

	key2, err := DeriveKey(password, salt, params)
	require.NoError(t, err, "Second key derivation should succeed")

	// Keys should be identical
	assert.True(t, ConstantTimeCompare(key1, key2), "Derived keys should be identical for same inputs")
}

func TestDeriveKeyDifferentSalts(t *testing.T) {
	password := []byte("test-password")
	salt1, err := GenerateSalt()
	require.NoError(t, err, "Failed to generate salt1")

	salt2, err := GenerateSalt()
	require.NoError(t, err, "Failed to generate salt2")

	params := DefaultArgon2Params()

	key1, err := DeriveKey(password, salt1, params)
	require.NoError(t, err, "Key derivation with salt1 should succeed")

	key2, err := DeriveKey(password, salt2, params)
	require.NoError(t, err, "Key derivation with salt2 should succeed")

	// Keys should be different with different salts
	assert.False(t, ConstantTimeCompare(key1, key2), "Derived keys should be different with different salts")
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	require.NoError(t, err, "Failed to generate salt1")

	assert.Equal(t, SaltLength, len(salt1), "Salt length should match expected")

	// Generate another salt
	salt2, err := GenerateSalt()
	require.NoError(t, err, "Failed to generate salt2")

	// Salts should be different (very high probability)
	assert.False(t, ConstantTimeCompare(salt1, salt2), "Generated salts should be different")
}

func TestConstantTimeCompare(t *testing.T) {
	a := []byte{1, 2, 3, 4}
	b := []byte{1, 2, 3, 4}
	c := []byte{1, 2, 3, 5}

	assert.True(t, ConstantTimeCompare(a, b), "Equal slices should compare equal")
	assert.False(t, ConstantTimeCompare(a, c), "Different slices should not compare equal")
	assert.False(t, ConstantTimeCompare(a, []byte{1, 2}), "Different length slices should not compare equal")
}

func TestEncodeDecodeSalt(t *testing.T) {
	originalSalt, err := GenerateSalt()
	require.NoError(t, err, "Failed to generate salt")

	encoded := EncodeSalt(originalSalt)
	decoded, err := DecodeSalt(encoded)
	require.NoError(t, err, "Failed to decode salt")

	assert.True(t, ConstantTimeCompare(originalSalt, decoded), "Decoded salt should match original")
}
