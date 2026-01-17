package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESGCMEncryptDecrypt(t *testing.T) {
	// Generate a test key (32 bytes for AES-256)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	aesGCM, err := NewAESGCM(key)
	require.NoError(t, err, "Failed to create AES-GCM")

	// Test data
	plaintext := []byte("Hello, World! This is a test message.")

	// Encrypt
	ciphertext, err := aesGCM.Encrypt(plaintext)
	require.NoError(t, err, "Encryption should succeed")

	// Verify ciphertext is different from plaintext
	assert.NotEqual(t, plaintext, ciphertext, "Ciphertext should be different from plaintext")

	// Verify ciphertext includes nonce
	minSize := NonceSize + GCMTagSize
	assert.GreaterOrEqual(t, len(ciphertext), minSize, "Ciphertext should include nonce and tag")

	// Decrypt
	decrypted, err := aesGCM.Decrypt(ciphertext)
	require.NoError(t, err, "Decryption should succeed")

	// Verify decrypted matches original
	assert.Equal(t, plaintext, decrypted, "Decrypted text should match original")
}

func TestAESGCMInvalidKey(t *testing.T) {
	// Test with invalid key length
	invalidKey := make([]byte, 16) // Too short for AES-256

	_, err := NewAESGCM(invalidKey)
	assert.Error(t, err, "Expected error for invalid key length")
}

func TestAESGCMTamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	aesGCM, err := NewAESGCM(key)
	require.NoError(t, err, "Failed to create AES-GCM")

	plaintext := []byte("Test message")
	ciphertext, err := aesGCM.Encrypt(plaintext)
	require.NoError(t, err, "Encryption should succeed")

	// Tamper with ciphertext
	ciphertext[NonceSize] ^= 0xFF

	// Decryption should fail
	_, err = aesGCM.Decrypt(ciphertext)
	assert.Error(t, err, "Expected error when decrypting tampered ciphertext")
}

func TestAESGCMDifferentNonces(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	aesGCM, err := NewAESGCM(key)
	require.NoError(t, err, "Failed to create AES-GCM")

	plaintext := []byte("Test message")

	// Encrypt twice
	ciphertext1, err := aesGCM.Encrypt(plaintext)
	require.NoError(t, err, "First encryption should succeed")

	ciphertext2, err := aesGCM.Encrypt(plaintext)
	require.NoError(t, err, "Second encryption should succeed")

	// Ciphertexts should be different (due to different nonces)
	assert.NotEqual(t, ciphertext1, ciphertext2, "Ciphertexts should be different due to random nonces")

	// Both should decrypt to the same plaintext
	decrypted1, err := aesGCM.Decrypt(ciphertext1)
	require.NoError(t, err, "First decryption should succeed")

	decrypted2, err := aesGCM.Decrypt(ciphertext2)
	require.NoError(t, err, "Second decryption should succeed")

	assert.Equal(t, plaintext, decrypted1, "First decryption should match original")
	assert.Equal(t, plaintext, decrypted2, "Second decryption should match original")
}
