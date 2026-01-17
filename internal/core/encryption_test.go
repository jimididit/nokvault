package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptionServiceEncryptDecrypt(t *testing.T) {
	service := NewEncryptionService()
	keyManager := service.GetKeyManager()

	password := []byte("test-password-123")
	key, _, err := keyManager.DeriveKeyFromPassword(password)
	require.NoError(t, err, "Failed to derive key")
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	plaintext := []byte("This is a test message for encryption.")

	// Encrypt
	ciphertext, err := service.EncryptData(plaintext, key)
	require.NoError(t, err, "Encryption should succeed")

	// Verify ciphertext is different from plaintext
	assert.NotEqual(t, plaintext, ciphertext, "Ciphertext should be different from plaintext")

	// Decrypt
	decrypted, err := service.DecryptData(ciphertext, key)
	require.NoError(t, err, "Decryption should succeed")

	// Verify decrypted matches original
	assert.Equal(t, plaintext, decrypted, "Decrypted text should match original")
}

func TestEncryptionServiceWrongKey(t *testing.T) {
	service := NewEncryptionService()
	keyManager := service.GetKeyManager()

	password1 := []byte("password1")
	password2 := []byte("password2")

	key1, salt1, err := keyManager.DeriveKeyFromPassword(password1)
	require.NoError(t, err, "Failed to derive key1")
	defer func() {
		for i := range key1 {
			key1[i] = 0
		}
	}()

	plaintext := []byte("Test message")

	// Encrypt with key1
	ciphertext, err := service.EncryptData(plaintext, key1)
	require.NoError(t, err, "Encryption should succeed")

	// Try to decrypt with key derived from different password
	key2, err := keyManager.DeriveKeyFromPasswordAndSalt(password2, salt1)
	require.NoError(t, err, "Failed to derive key2")
	defer func() {
		for i := range key2 {
			key2[i] = 0
		}
	}()

	// Decryption should fail - GCM will detect authentication failure
	_, err = service.DecryptData(ciphertext, key2)
	assert.Error(t, err, "Decryption with wrong key should fail")
}
