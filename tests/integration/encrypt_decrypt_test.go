package integration

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/jimididit/nokvault/internal/core"
)

func TestEncryptDecryptFile(t *testing.T) {
	encryptionService := core.NewEncryptionService()
	keyManager := encryptionService.GetKeyManager()
	fileHandler := core.NewFileHandler()

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

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "nokvault-integration-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	testContent := []byte("This is test content for integration testing")
	if _, err := tmpFile.Write(testContent); err != nil {
		t.Fatalf("Failed to write test content: %v", err)
	}
	tmpFile.Close()

	// Read metadata
	metadata, err := fileHandler.ReadMetadata(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read metadata: %v", err)
	}

	// Encrypt file
	encryptedPath := tmpFile.Name() + ".nokvault"
	encryptedFile, err := os.Create(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to create encrypted file: %v", err)
	}
	defer os.Remove(encryptedPath)
	defer encryptedFile.Close()

	// Write header
	if err := fileHandler.WriteHeader(encryptedFile, salt, metadata); err != nil {
		t.Fatalf("Failed to write header: %v", err)
	}

	// Encrypt data
	ciphertext, err := encryptionService.EncryptData(testContent, key)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	if _, err := encryptedFile.Write(ciphertext); err != nil {
		t.Fatalf("Failed to write ciphertext: %v", err)
	}
	encryptedFile.Close()

	// Decrypt file
	encryptedFile, err = os.Open(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to open encrypted file: %v", err)
	}
	defer encryptedFile.Close()

	// Read header
	header, readMetadata, err := fileHandler.ReadHeaderWithMetadata(encryptedFile)
	if err != nil {
		t.Fatalf("Failed to read header: %v", err)
	}

	if string(header.Magic[:]) != core.NokvaultMagic {
		t.Errorf("Invalid magic number")
	}

	if readMetadata == nil {
		t.Fatal("Metadata should not be nil")
	}

	// Read encrypted data
	encryptedData, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	dataStart := int64(header.DataOffset)
	ciphertext = encryptedData[dataStart:]

	// Decrypt
	plaintext, err := encryptionService.DecryptData(ciphertext, key)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	// Verify content matches
	if string(plaintext) != string(testContent) {
		t.Errorf("Decrypted content doesn't match. Expected %s, got %s",
			string(testContent), string(plaintext))
	}
}

func TestEncryptDecryptDirectory(t *testing.T) {
	encryptionService := core.NewEncryptionService()
	encryptor := core.NewDirectoryEncryptor(encryptionService, false)
	decryptor := core.NewDirectoryDecryptor(encryptionService, false)
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
	inputDir, err := os.MkdirTemp("", "nokvault-integration-input-*")
	if err != nil {
		t.Fatalf("Failed to create input directory: %v", err)
	}
	defer os.RemoveAll(inputDir)

	encryptedDir, err := os.MkdirTemp("", "nokvault-integration-encrypted-*")
	if err != nil {
		t.Fatalf("Failed to create encrypted directory: %v", err)
	}
	defer os.RemoveAll(encryptedDir)

	decryptedDir, err := os.MkdirTemp("", "nokvault-integration-decrypted-*")
	if err != nil {
		t.Fatalf("Failed to create decrypted directory: %v", err)
	}
	defer os.RemoveAll(decryptedDir)

	// Create test files
	testFiles := map[string][]byte{
		"file1.txt":        []byte("content 1"),
		"file2.txt":        []byte("content 2"),
		"subdir/file3.txt": []byte("content 3"),
		"subdir/file4.txt": []byte("content 4"),
	}

	for relPath, content := range testFiles {
		filePath := filepath.Join(inputDir, relPath)
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			t.Fatalf("Failed to create subdirectory: %v", err)
		}
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Encrypt directory
	if err := encryptor.EncryptDirectory(inputDir, encryptedDir, key, salt, nil); err != nil {
		t.Fatalf("Failed to encrypt directory: %v", err)
	}

	// Verify encrypted files exist
	for relPath := range testFiles {
		encryptedPath := filepath.Join(encryptedDir, relPath+".nokvault")
		if _, err := os.Stat(encryptedPath); err != nil {
			t.Errorf("Encrypted file %s does not exist: %v", encryptedPath, err)
		}
	}

	// Decrypt directory
	if err := decryptor.DecryptDirectory(encryptedDir, decryptedDir, key, nil); err != nil {
		t.Fatalf("Failed to decrypt directory: %v", err)
	}

	// Verify decrypted files match originals
	for relPath, originalContent := range testFiles {
		decryptedPath := filepath.Join(decryptedDir, relPath)
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

func TestEncryptDecryptWithCompression(t *testing.T) {
	encryptionService := core.NewEncryptionService()
	encryptor := core.NewDirectoryEncryptor(encryptionService, false)
	decryptor := core.NewDirectoryDecryptor(encryptionService, false)
	keyManager := encryptionService.GetKeyManager()

	// Enable compression
	encryptor.SetCompression(true)

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
	inputDir, err := os.MkdirTemp("", "nokvault-compress-input-*")
	if err != nil {
		t.Fatalf("Failed to create input directory: %v", err)
	}
	defer os.RemoveAll(inputDir)

	encryptedDir, err := os.MkdirTemp("", "nokvault-compress-encrypted-*")
	if err != nil {
		t.Fatalf("Failed to create encrypted directory: %v", err)
	}
	defer os.RemoveAll(encryptedDir)

	decryptedDir, err := os.MkdirTemp("", "nokvault-compress-decrypted-*")
	if err != nil {
		t.Fatalf("Failed to create decrypted directory: %v", err)
	}
	defer os.RemoveAll(decryptedDir)

	// Create a file with compressible content (repeated patterns)
	compressibleContent := bytes.Repeat([]byte("repeated pattern "), 100)
	filePath := filepath.Join(inputDir, "compressible.txt")
	if err := os.WriteFile(filePath, compressibleContent, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Encrypt with compression
	if err := encryptor.EncryptDirectory(inputDir, encryptedDir, key, salt, nil); err != nil {
		t.Fatalf("Failed to encrypt directory: %v", err)
	}

	// Decrypt
	if err := decryptor.DecryptDirectory(encryptedDir, decryptedDir, key, nil); err != nil {
		t.Fatalf("Failed to decrypt directory: %v", err)
	}

	// Verify content matches
	decryptedPath := filepath.Join(decryptedDir, "compressible.txt")
	decryptedContent, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(decryptedContent, compressibleContent) {
		t.Error("Decrypted compressed content doesn't match original")
	}
}
