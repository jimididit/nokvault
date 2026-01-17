package crypto

import (
	"testing"
)

func TestAESGCMEncryptDecrypt(t *testing.T) {
	// Generate a test key (32 bytes for AES-256)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	aesGCM, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("Failed to create AES-GCM: %v", err)
	}

	// Test data
	plaintext := []byte("Hello, World! This is a test message.")

	// Encrypt
	ciphertext, err := aesGCM.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify ciphertext is different from plaintext
	if string(ciphertext) == string(plaintext) {
		t.Error("Ciphertext should be different from plaintext")
	}

	// Verify ciphertext includes nonce
	if len(ciphertext) < NonceSize+GCMTagSize {
		t.Errorf("Ciphertext too short: got %d, expected at least %d", len(ciphertext), NonceSize+GCMTagSize)
	}

	// Decrypt
	decrypted, err := aesGCM.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify decrypted matches original
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match: got %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestAESGCMInvalidKey(t *testing.T) {
	// Test with invalid key length
	invalidKey := make([]byte, 16) // Too short for AES-256

	_, err := NewAESGCM(invalidKey)
	if err == nil {
		t.Error("Expected error for invalid key length")
	}
}

func TestAESGCMTamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	aesGCM, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("Failed to create AES-GCM: %v", err)
	}

	plaintext := []byte("Test message")
	ciphertext, err := aesGCM.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Tamper with ciphertext
	ciphertext[NonceSize] ^= 0xFF

	// Decryption should fail
	_, err = aesGCM.Decrypt(ciphertext)
	if err == nil {
		t.Error("Expected error when decrypting tampered ciphertext")
	}
}

func TestAESGCMDifferentNonces(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	aesGCM, err := NewAESGCM(key)
	if err != nil {
		t.Fatalf("Failed to create AES-GCM: %v", err)
	}

	plaintext := []byte("Test message")

	// Encrypt twice
	ciphertext1, err := aesGCM.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	ciphertext2, err := aesGCM.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Ciphertexts should be different (due to different nonces)
	if string(ciphertext1) == string(ciphertext2) {
		t.Error("Ciphertexts should be different due to random nonces")
	}

	// Both should decrypt to the same plaintext
	decrypted1, err := aesGCM.Decrypt(ciphertext1)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	decrypted2, err := aesGCM.Decrypt(ciphertext2)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted1) != string(plaintext) || string(decrypted2) != string(plaintext) {
		t.Error("Both decryptions should match original plaintext")
	}
}
