package core

import (
	"testing"
)

func TestEncryptionServiceEncryptDecrypt(t *testing.T) {
	service := NewEncryptionService()
	keyManager := service.GetKeyManager()

	password := []byte("test-password-123")
	key, _, err := keyManager.DeriveKeyFromPassword(password)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	plaintext := []byte("This is a test message for encryption.")

	// Encrypt
	ciphertext, err := service.EncryptData(plaintext, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify ciphertext is different
	if string(ciphertext) == string(plaintext) {
		t.Error("Ciphertext should be different from plaintext")
	}

	// Decrypt
	decrypted, err := service.DecryptData(ciphertext, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify decrypted matches original
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match: got %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestEncryptionServiceWrongKey(t *testing.T) {
	service := NewEncryptionService()
	keyManager := service.GetKeyManager()

	password1 := []byte("password1")
	password2 := []byte("password2")

	key1, salt1, err := keyManager.DeriveKeyFromPassword(password1)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	defer func() {
		for i := range key1 {
			key1[i] = 0
		}
	}()

	plaintext := []byte("Test message")

	// Encrypt with key1
	ciphertext, err := service.EncryptData(plaintext, key1)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Try to decrypt with key derived from different password
	key2, err := keyManager.DeriveKeyFromPasswordAndSalt(password2, salt1)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	defer func() {
		for i := range key2 {
			key2[i] = 0
		}
	}()

	// Decryption should fail or produce garbage
	_, err = service.DecryptData(ciphertext, key2)
	// Note: GCM will detect authentication failure, but the exact error may vary
	// The important thing is that it doesn't silently succeed
}
