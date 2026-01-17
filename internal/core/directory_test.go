package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirectoryEncryptor_EncryptDirectory(t *testing.T) {
	encryptionService := NewEncryptionService()
	encryptor := NewDirectoryEncryptor(encryptionService, false)
	keyManager := encryptionService.GetKeyManager()

	password := []byte("test-password-123")
	key, salt, err := keyManager.DeriveKeyFromPassword(password)
	require.NoError(t, err, "Failed to derive key")
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// Create temporary input directory
	inputDir, err := os.MkdirTemp("", "nokvault-test-input-*")
	require.NoError(t, err, "Failed to create input directory")
	defer os.RemoveAll(inputDir)

	// Create temporary output directory
	outputDir, err := os.MkdirTemp("", "nokvault-test-output-*")
	require.NoError(t, err, "Failed to create output directory")
	defer os.RemoveAll(outputDir)

	// Create test files
	files := map[string][]byte{
		"file1.txt":        []byte("content of file 1"),
		"file2.txt":        []byte("content of file 2"),
		"subdir/file3.txt": []byte("content of file 3"),
	}

	for relPath, content := range files {
		filePath := filepath.Join(inputDir, relPath)
		err := os.MkdirAll(filepath.Dir(filePath), 0755)
		require.NoError(t, err, "Failed to create subdirectory")
		err = os.WriteFile(filePath, content, 0644)
		require.NoError(t, err, "Failed to create test file")
	}

	// Encrypt directory
	progressCount := 0
	err = encryptor.EncryptDirectory(inputDir, outputDir, key, salt, func(current, total int, currentFile string) {
		progressCount++
	})
	require.NoError(t, err, "Failed to encrypt directory")

	// Verify progress callback was called
	assert.Equal(t, len(files), progressCount, "Progress callback should be called for each file")

	// Verify encrypted files exist
	for relPath := range files {
		encryptedPath := filepath.Join(outputDir, relPath+".nokvault")
		_, err := os.Stat(encryptedPath)
		assert.NoError(t, err, "Encrypted file should exist: %s", encryptedPath)
	}
}

func TestDirectoryDecryptor_DecryptDirectory(t *testing.T) {
	encryptionService := NewEncryptionService()
	encryptor := NewDirectoryEncryptor(encryptionService, false)
	decryptor := NewDirectoryDecryptor(encryptionService, false)
	keyManager := encryptionService.GetKeyManager()

	password := []byte("test-password-123")
	key, salt, err := keyManager.DeriveKeyFromPassword(password)
	require.NoError(t, err, "Failed to derive key")
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// Create temporary directories
	inputDir, err := os.MkdirTemp("", "nokvault-test-encrypted-*")
	require.NoError(t, err, "Failed to create input directory")
	defer os.RemoveAll(inputDir)

	decryptOutputDir, err := os.MkdirTemp("", "nokvault-test-decrypted-*")
	require.NoError(t, err, "Failed to create output directory")
	defer os.RemoveAll(decryptOutputDir)

	// Create test files and encrypt them
	originalFiles := map[string][]byte{
		"file1.txt":        []byte("content of file 1"),
		"file2.txt":        []byte("content of file 2"),
		"subdir/file3.txt": []byte("content of file 3"),
	}

	// First encrypt the files
	for relPath, content := range originalFiles {
		filePath := filepath.Join(inputDir, relPath)
		err := os.MkdirAll(filepath.Dir(filePath), 0755)
		require.NoError(t, err, "Failed to create subdirectory")
		err = os.WriteFile(filePath, content, 0644)
		require.NoError(t, err, "Failed to create test file")
	}

	// Encrypt directory
	encryptOutputDir, err := os.MkdirTemp("", "nokvault-test-encrypt-out-*")
	require.NoError(t, err, "Failed to create encrypt output directory")
	defer os.RemoveAll(encryptOutputDir)

	err = encryptor.EncryptDirectory(inputDir, encryptOutputDir, key, salt, nil)
	require.NoError(t, err, "Failed to encrypt directory")

	// Now decrypt
	progressCount := 0
	err = decryptor.DecryptDirectory(encryptOutputDir, decryptOutputDir, key, func(current, total int, currentFile string) {
		progressCount++
	})
	require.NoError(t, err, "Failed to decrypt directory")

	// Verify progress callback was called
	assert.Equal(t, len(originalFiles), progressCount, "Progress callback should be called for each file")

	// Verify decrypted files match originals
	for relPath, originalContent := range originalFiles {
		decryptedPath := filepath.Join(decryptOutputDir, relPath)
		decryptedContent, err := os.ReadFile(decryptedPath)
		require.NoError(t, err, "Failed to read decrypted file: %s", decryptedPath)
		assert.Equal(t, originalContent, decryptedContent, "Decrypted content should match original for: %s", relPath)
	}
}

func TestDirectoryEncryptor_SetCompression(t *testing.T) {
	encryptionService := NewEncryptionService()
	encryptor := NewDirectoryEncryptor(encryptionService, false)

	assert.False(t, encryptor.compress, "Compression should be disabled by default")

	encryptor.SetCompression(true)
	assert.True(t, encryptor.compress, "Compression should be enabled after SetCompression(true)")

	encryptor.SetCompression(false)
	assert.False(t, encryptor.compress, "Compression should be disabled after SetCompression(false)")
}

func TestDirectoryEncryptor_EncryptDirectory_EmptyDirectory(t *testing.T) {
	encryptionService := NewEncryptionService()
	encryptor := NewDirectoryEncryptor(encryptionService, false)
	keyManager := encryptionService.GetKeyManager()

	password := []byte("test-password-123")
	key, salt, err := keyManager.DeriveKeyFromPassword(password)
	require.NoError(t, err, "Failed to derive key")
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// Create empty input directory
	inputDir, err := os.MkdirTemp("", "nokvault-test-empty-input-*")
	require.NoError(t, err, "Failed to create input directory")
	defer os.RemoveAll(inputDir)

	outputDir, err := os.MkdirTemp("", "nokvault-test-empty-output-*")
	require.NoError(t, err, "Failed to create output directory")
	defer os.RemoveAll(outputDir)

	// Encrypt empty directory (should succeed with no files)
	err = encryptor.EncryptDirectory(inputDir, outputDir, key, salt, nil)
	require.NoError(t, err, "Failed to encrypt empty directory")
}

func TestDirectoryEncryptor_EncryptDirectory_NonExistentInput(t *testing.T) {
	encryptionService := NewEncryptionService()
	encryptor := NewDirectoryEncryptor(encryptionService, false)
	keyManager := encryptionService.GetKeyManager()

	password := []byte("test-password-123")
	key, salt, err := keyManager.DeriveKeyFromPassword(password)
	require.NoError(t, err, "Failed to derive key")
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	outputDir, err := os.MkdirTemp("", "nokvault-test-output-*")
	require.NoError(t, err, "Failed to create output directory")
	defer os.RemoveAll(outputDir)

	nonExistentDir := filepath.Join(os.TempDir(), "nokvault-nonexistent-12345")

	err = encryptor.EncryptDirectory(nonExistentDir, outputDir, key, salt, nil)
	assert.Error(t, err, "Expected error when encrypting non-existent directory")
}
