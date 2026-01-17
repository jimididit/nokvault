package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryEncryptor_EncryptDirectory(t *testing.T) {
	encryptionService := NewEncryptionService()
	encryptor := NewDirectoryEncryptor(encryptionService, false)
	keyManager := encryptionService.GetKeyManager()

	password := []byte("test-password-123")
	key, salt, err := keyManager.DeriveKeyFromPassword(password)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// Create temporary input directory
	inputDir, err := os.MkdirTemp("", "nokvault-test-input-*")
	if err != nil {
		t.Fatalf("Failed to create input directory: %v", err)
	}
	defer os.RemoveAll(inputDir)

	// Create temporary output directory
	outputDir, err := os.MkdirTemp("", "nokvault-test-output-*")
	if err != nil {
		t.Fatalf("Failed to create output directory: %v", err)
	}
	defer os.RemoveAll(outputDir)

	// Create test files
	files := map[string][]byte{
		"file1.txt":        []byte("content of file 1"),
		"file2.txt":        []byte("content of file 2"),
		"subdir/file3.txt": []byte("content of file 3"),
	}

	for relPath, content := range files {
		filePath := filepath.Join(inputDir, relPath)
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			t.Fatalf("Failed to create subdirectory: %v", err)
		}
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Encrypt directory
	progressCount := 0
	err = encryptor.EncryptDirectory(inputDir, outputDir, key, salt, func(current, total int, currentFile string) {
		progressCount++
	})
	if err != nil {
		t.Fatalf("Failed to encrypt directory: %v", err)
	}

	// Verify progress callback was called
	if progressCount != len(files) {
		t.Errorf("Expected progress callback %d times, got %d", len(files), progressCount)
	}

	// Verify encrypted files exist
	for relPath := range files {
		encryptedPath := filepath.Join(outputDir, relPath+".nokvault")
		if _, err := os.Stat(encryptedPath); err != nil {
			t.Errorf("Encrypted file %s does not exist: %v", encryptedPath, err)
		}
	}
}

func TestDirectoryDecryptor_DecryptDirectory(t *testing.T) {
	encryptionService := NewEncryptionService()
	encryptor := NewDirectoryEncryptor(encryptionService, false)
	decryptor := NewDirectoryDecryptor(encryptionService, false)
	keyManager := encryptionService.GetKeyManager()

	password := []byte("test-password-123")
	key, salt, err := keyManager.DeriveKeyFromPassword(password)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// Create temporary directories
	inputDir, err := os.MkdirTemp("", "nokvault-test-encrypted-*")
	if err != nil {
		t.Fatalf("Failed to create input directory: %v", err)
	}
	defer os.RemoveAll(inputDir)

	decryptOutputDir, err := os.MkdirTemp("", "nokvault-test-decrypted-*")
	if err != nil {
		t.Fatalf("Failed to create output directory: %v", err)
	}
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
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			t.Fatalf("Failed to create subdirectory: %v", err)
		}
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
			}
	}

	// Encrypt directory
	encryptOutputDir, err := os.MkdirTemp("", "nokvault-test-encrypt-out-*")
	if err != nil {
		t.Fatalf("Failed to create encrypt output directory: %v", err)
	}
	defer os.RemoveAll(encryptOutputDir)

	err = encryptor.EncryptDirectory(inputDir, encryptOutputDir, key, salt, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt directory: %v", err)
	}

	// Now decrypt
	progressCount := 0
	err = decryptor.DecryptDirectory(encryptOutputDir, decryptOutputDir, key, func(current, total int, currentFile string) {
		progressCount++
	})
	if err != nil {
		t.Fatalf("Failed to decrypt directory: %v", err)
	}

	// Verify progress callback was called
	if progressCount != len(originalFiles) {
		t.Errorf("Expected progress callback %d times, got %d", len(originalFiles), progressCount)
	}

	// Verify decrypted files match originals
	for relPath, originalContent := range originalFiles {
		decryptedPath := filepath.Join(decryptOutputDir, relPath)
		decryptedContent, err := os.ReadFile(decryptedPath)
		if err != nil {
			t.Errorf("Failed to read decrypted file %s: %v", decryptedPath, err)
			continue
		}

		if string(decryptedContent) != string(originalContent) {
			t.Errorf("Decrypted content doesn't match for %s. Expected %s, got %s",
				relPath, string(originalContent), string(decryptedContent))
		}
	}
}

func TestDirectoryEncryptor_SetCompression(t *testing.T) {
	encryptionService := NewEncryptionService()
	encryptor := NewDirectoryEncryptor(encryptionService, false)

	if encryptor.compress {
		t.Error("Compression should be disabled by default")
	}

	encryptor.SetCompression(true)
	if !encryptor.compress {
		t.Error("Compression should be enabled after SetCompression(true)")
	}

	encryptor.SetCompression(false)
	if encryptor.compress {
		t.Error("Compression should be disabled after SetCompression(false)")
	}
}

func TestDirectoryEncryptor_EncryptDirectory_EmptyDirectory(t *testing.T) {
	encryptionService := NewEncryptionService()
	encryptor := NewDirectoryEncryptor(encryptionService, false)
	keyManager := encryptionService.GetKeyManager()

	password := []byte("test-password-123")
	key, salt, err := keyManager.DeriveKeyFromPassword(password)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// Create empty input directory
	inputDir, err := os.MkdirTemp("", "nokvault-test-empty-input-*")
	if err != nil {
		t.Fatalf("Failed to create input directory: %v", err)
	}
	defer os.RemoveAll(inputDir)

	outputDir, err := os.MkdirTemp("", "nokvault-test-empty-output-*")
	if err != nil {
		t.Fatalf("Failed to create output directory: %v", err)
	}
	defer os.RemoveAll(outputDir)

	// Encrypt empty directory (should succeed with no files)
	err = encryptor.EncryptDirectory(inputDir, outputDir, key, salt, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt empty directory: %v", err)
	}
}

func TestDirectoryEncryptor_EncryptDirectory_NonExistentInput(t *testing.T) {
	encryptionService := NewEncryptionService()
	encryptor := NewDirectoryEncryptor(encryptionService, false)
	keyManager := encryptionService.GetKeyManager()

	password := []byte("test-password-123")
	key, salt, err := keyManager.DeriveKeyFromPassword(password)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	outputDir, err := os.MkdirTemp("", "nokvault-test-output-*")
	if err != nil {
		t.Fatalf("Failed to create output directory: %v", err)
	}
	defer os.RemoveAll(outputDir)

	nonExistentDir := filepath.Join(os.TempDir(), "nokvault-nonexistent-12345")

	err = encryptor.EncryptDirectory(nonExistentDir, outputDir, key, salt, nil)
	if err == nil {
		t.Error("Expected error when encrypting non-existent directory")
	}
}
