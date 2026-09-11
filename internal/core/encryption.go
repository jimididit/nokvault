package core

import (
	"fmt"
	"io"
	"os"

	"github.com/jimididit/nokvault/internal/crypto"
	"github.com/jimididit/nokvault/internal/utils"
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

// NewEncryptionServiceWithParams creates an encryption service with custom Argon2 parameters.
func NewEncryptionServiceWithParams(p *crypto.Argon2Params) *EncryptionService {
	es := NewEncryptionService()
	es.keyManager.SetArgon2Params(p)
	return es
}

// EncryptVault writes a v3 vault header followed by a chunked STREAM payload.
func (es *EncryptionService) EncryptVault(
	w io.Writer,
	plaintext io.Reader,
	key, salt []byte,
	metadata *FileMetadata,
	compress uint8,
) error {
	if _, err := crypto.NewAESGCM(key); err != nil {
		return fmt.Errorf("failed to create AES-GCM cipher: %w", err)
	}

	fh := NewFileHandler()
	aad, err := fh.WriteHeader(
		w,
		salt,
		metadata,
		es.keyManager.Params(),
		compress,
	)
	if err != nil {
		return fmt.Errorf("failed to write vault header: %w", err)
	}
	if err := crypto.EncryptSTREAMWithKey(w, plaintext, key, aad); err != nil {
		return fmt.Errorf("failed to encrypt vault payload: %w", err)
	}
	return nil
}

// DecryptVaultPayload decrypts a vault payload according to its format version.
func (es *EncryptionService) DecryptVaultPayload(
	w io.Writer,
	payload io.Reader,
	key []byte,
	version uint16,
	aad []byte,
) error {
	switch version {
	case Version1, Version2:
		ciphertext, err := io.ReadAll(payload)
		if err != nil {
			return fmt.Errorf("failed to read vault payload: %w", err)
		}
		plaintext, err := es.DecryptData(ciphertext, key)
		if err != nil {
			return err
		}
		if _, err := w.Write(plaintext); err != nil {
			return fmt.Errorf("failed to write decrypted vault payload: %w", err)
		}
		return nil
	case Version3:
		if err := crypto.DecryptSTREAMWithKey(w, payload, key, aad); err != nil {
			return fmt.Errorf("failed to decrypt vault payload: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported vault version: %d", version)
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
	// #nosec G304 -- this service intentionally accepts a caller-selected input path.
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	ciphertext, err := es.EncryptData(data, key)
	if err != nil {
		return err
	}

	if err := utils.AtomicWrite(outputPath, ciphertext, 0o600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

// DecryptFile decrypts a file
func (es *EncryptionService) DecryptFile(inputPath string, outputPath string, key []byte) error {
	// #nosec G304 -- this service intentionally accepts a caller-selected input path.
	ciphertext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	plaintext, err := es.DecryptData(ciphertext, key)
	if err != nil {
		return err
	}

	if err := utils.AtomicWrite(outputPath, plaintext, 0o600); err != nil {
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
