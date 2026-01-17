package crypto

import (
	"testing"
)

func TestDeriveKey(t *testing.T) {
	password := []byte("test-password-123")
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	params := DefaultArgon2Params()
	key, err := DeriveKey(password, salt, params)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}

	// Verify key length
	if len(key) != int(params.KeyLength) {
		t.Errorf("Key length mismatch: got %d, want %d", len(key), params.KeyLength)
	}

	// Verify key is not all zeros
	allZeros := true
	for _, b := range key {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Derived key should not be all zeros")
	}
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
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}

	key2, err := DeriveKey(password, salt, params)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}

	// Keys should be identical
	if !ConstantTimeCompare(key1, key2) {
		t.Error("Derived keys should be identical for same inputs")
	}
}

func TestDeriveKeyDifferentSalts(t *testing.T) {
	password := []byte("test-password")
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	params := DefaultArgon2Params()

	key1, err := DeriveKey(password, salt1, params)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}

	key2, err := DeriveKey(password, salt2, params)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}

	// Keys should be different with different salts
	if ConstantTimeCompare(key1, key2) {
		t.Error("Derived keys should be different with different salts")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	if len(salt1) != SaltLength {
		t.Errorf("Salt length mismatch: got %d, want %d", len(salt1), SaltLength)
	}

	// Generate another salt
	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	// Salts should be different (very high probability)
	if ConstantTimeCompare(salt1, salt2) {
		t.Error("Generated salts should be different")
	}
}

func TestConstantTimeCompare(t *testing.T) {
	a := []byte{1, 2, 3, 4}
	b := []byte{1, 2, 3, 4}
	c := []byte{1, 2, 3, 5}

	if !ConstantTimeCompare(a, b) {
		t.Error("Equal slices should compare equal")
	}

	if ConstantTimeCompare(a, c) {
		t.Error("Different slices should not compare equal")
	}

	if ConstantTimeCompare(a, []byte{1, 2}) {
		t.Error("Different length slices should not compare equal")
	}
}

func TestEncodeDecodeSalt(t *testing.T) {
	originalSalt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	encoded := EncodeSalt(originalSalt)
	decoded, err := DecodeSalt(encoded)
	if err != nil {
		t.Fatalf("Failed to decode salt: %v", err)
	}

	if !ConstantTimeCompare(originalSalt, decoded) {
		t.Error("Decoded salt should match original")
	}
}
