package core

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptVault_RoundTrip_V3(t *testing.T) {
	es := NewEncryptionService()
	key := make([]byte, 32)
	salt := make([]byte, 16)
	_, err := rand.Read(key)
	require.NoError(t, err)
	_, err = rand.Read(salt)
	require.NoError(t, err)
	plain := bytes.Repeat([]byte("x"), 70_000)
	metadata := &FileMetadata{Name: "large.bin", Size: int64(len(plain))}

	var vault bytes.Buffer
	require.NoError(t, es.EncryptVault(
		&vault,
		bytes.NewReader(plain),
		key,
		salt,
		metadata,
		1,
	))

	fh := NewFileHandler()
	header, gotMetadata, aad, _, err := fh.ReadHeaderWithMetadata(bytes.NewReader(vault.Bytes()))
	require.NoError(t, err)
	require.Equal(t, Version3, header.Version)
	require.Equal(t, uint8(1), header.Compress)
	require.Equal(t, metadata, gotMetadata)

	require.Equal(t, vault.Bytes()[:header.DataOffset], aad)
	payload := bytes.NewReader(vault.Bytes()[header.DataOffset:])
	var out bytes.Buffer
	require.NoError(t, es.DecryptVaultPayload(
		&out,
		payload,
		key,
		header.Version,
		aad,
	))
	require.Equal(t, plain, out.Bytes())
}

func TestEncryptVault_InvalidKeyWritesNothing(t *testing.T) {
	es := NewEncryptionService()
	var vault bytes.Buffer

	err := es.EncryptVault(
		&vault,
		bytes.NewReader([]byte("secret")),
		make([]byte, 31),
		make([]byte, 16),
		nil,
		0,
	)

	require.Error(t, err)
	require.Empty(t, vault.Bytes())
}

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
