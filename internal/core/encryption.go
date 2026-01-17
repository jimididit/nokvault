package core

import (
	"fmt"
	"io"
	"os"

	"github.com/jimididit/nokvault/internal/crypto"
)

// EncryptionService handles file encryption/decryption operations
type EncryptionService struct {
	keyManager *KeyManager
}

// NewEncryptionService creates a new encryption service
func NewEncryptionService() *EncryptionService {
	return &EncryptionService{
		keyManager: NewKeyManager(),
	}
}

// EncryptData encrypts data using AES-256-GCM
func (es *EncryptionService) EncryptData(data []byte, key []byte) ([]byte, error) {
	aesGCM, err := crypto.NewAESGCM(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM cipher: %w", err)
	}

	ciphertext, err := aesGCM.Encrypt(data)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	return ciphertext, nil
}

// DecryptData decrypts data using AES-256-GCM
func (es *EncryptionService) DecryptData(ciphertext []byte, key []byte) ([]byte, error) {
	aesGCM, err := crypto.NewAESGCM(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM cipher: %w", err)
	}

	plaintext, err := aesGCM.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptFile encrypts a file
func (es *EncryptionService) EncryptFile(inputPath string, outputPath string, key []byte) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	ciphertext, err := es.EncryptData(data, key)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, ciphertext, 0600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

// DecryptFile decrypts a file
func (es *EncryptionService) DecryptFile(inputPath string, outputPath string, key []byte) error {
	ciphertext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	plaintext, err := es.DecryptData(ciphertext, key)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, plaintext, 0600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

// EncryptStream encrypts data from a reader and writes to a writer
func (es *EncryptionService) EncryptStream(reader io.Reader, writer io.Writer, key []byte) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read data: %w", err)
	}

	ciphertext, err := es.EncryptData(data, key)
	if err != nil {
		return err
	}

	if _, err := writer.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write encrypted data: %w", err)
	}

	return nil
}

// DecryptStream decrypts data from a reader and writes to a writer
func (es *EncryptionService) DecryptStream(reader io.Reader, writer io.Writer, key []byte) error {
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read data: %w", err)
	}

	plaintext, err := es.DecryptData(ciphertext, key)
	if err != nil {
		return err
	}

	if _, err := writer.Write(plaintext); err != nil {
		return fmt.Errorf("failed to write decrypted data: %w", err)
	}

	return nil
}

// GetKeyManager returns the key manager
func (es *EncryptionService) GetKeyManager() *KeyManager {
	return es.keyManager
}
