package core

import (
	"fmt"
	"os"
	"path/filepath"
)

// DirectoryEncryptor handles directory encryption operations
type DirectoryEncryptor struct {
	encryptionService  *EncryptionService
	fileHandler        *FileHandler
	compressionService *CompressionService
	verbose            bool
	compress           bool
}

// NewDirectoryEncryptor creates a new directory encryptor
func NewDirectoryEncryptor(encryptionService *EncryptionService, verbose bool) *DirectoryEncryptor {
	return &DirectoryEncryptor{
		encryptionService:  encryptionService,
		fileHandler:        NewFileHandler(),
		compressionService: NewCompressionService(),
		verbose:            verbose,
		compress:           false,
	}
}

// SetCompression enables or disables compression
func (de *DirectoryEncryptor) SetCompression(compress bool) {
	de.compress = compress
}

// EncryptDirectory encrypts all files in a directory recursively
func (de *DirectoryEncryptor) EncryptDirectory(inputDir, outputDir string, key, salt []byte, onProgress func(current, total int, currentFile string)) error {
	// Ensure output directory exists
	if err := de.fileHandler.EnsureDirectory(outputDir); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Count total files for progress tracking
	totalFiles, err := de.fileHandler.CountFiles(inputDir)
	if err != nil {
		return fmt.Errorf("failed to count files: %w", err)
	}

	currentFile := 0

	// Walk directory and encrypt each file
	err = de.fileHandler.WalkDirectory(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error accessing %s: %w", path, err)
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		currentFile++

		// Get relative path
		relPath, err := de.fileHandler.GetRelativePath(inputDir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		// Create output path maintaining directory structure
		outputPath := filepath.Join(outputDir, relPath+".nokvault")

		// Ensure output directory exists
		outputFileDir := filepath.Dir(outputPath)
		if err := de.fileHandler.EnsureDirectory(outputFileDir); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		// Report progress
		if onProgress != nil {
			onProgress(currentFile, totalFiles, relPath)
		}

		// Encrypt file
		if err := de.encryptFileWithMetadata(path, outputPath, key, salt); err != nil {
			return fmt.Errorf("failed to encrypt %s: %w", relPath, err)
		}

		return nil
	})

	return err
}

// encryptFileWithMetadata encrypts a file and preserves metadata
func (de *DirectoryEncryptor) encryptFileWithMetadata(inputPath, outputPath string, key, salt []byte) error {
	// Read file metadata
	metadata, err := de.fileHandler.ReadMetadata(inputPath)
	if err != nil {
		return err
	}

	// Set relative path
	metadata.RelativePath = filepath.Base(inputPath)

	// Read file data
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Compress if enabled
	if de.compress && de.compressionService.ShouldCompress(data, 1024) {
		compressed, err := de.compressionService.Compress(data)
		if err != nil {
			return fmt.Errorf("compression failed: %w", err)
		}
		data = compressed
	}

	// Encrypt data
	ciphertext, err := de.encryptionService.EncryptData(data, key)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Create output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	// Write header with metadata
	if err := de.fileHandler.WriteHeader(outputFile, salt, metadata); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write encrypted data
	if _, err := outputFile.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write encrypted data: %w", err)
	}

	return nil
}

// DirectoryDecryptor handles directory decryption operations
type DirectoryDecryptor struct {
	encryptionService  *EncryptionService
	fileHandler        *FileHandler
	compressionService *CompressionService
	verbose            bool
}

// NewDirectoryDecryptor creates a new directory decryptor
func NewDirectoryDecryptor(encryptionService *EncryptionService, verbose bool) *DirectoryDecryptor {
	return &DirectoryDecryptor{
		encryptionService:  encryptionService,
		fileHandler:        NewFileHandler(),
		compressionService: NewCompressionService(),
		verbose:            verbose,
	}
}

// DecryptDirectory decrypts all .nokvault files in a directory recursively
func (dd *DirectoryDecryptor) DecryptDirectory(inputDir, outputDir string, key []byte, onProgress func(current, total int, currentFile string)) error {
	// Ensure output directory exists
	if err := dd.fileHandler.EnsureDirectory(outputDir); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Count total .nokvault files
	totalFiles := 0
	err := dd.fileHandler.WalkDirectory(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".nokvault" {
			totalFiles++
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to count files: %w", err)
	}

	currentFile := 0

	// Walk directory and decrypt each .nokvault file
	err = dd.fileHandler.WalkDirectory(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error accessing %s: %w", path, err)
		}

		// Skip directories and non-.nokvault files
		if info.IsDir() || filepath.Ext(path) != ".nokvault" {
			return nil
		}

		currentFile++

		// Get relative path
		relPath, err := dd.fileHandler.GetRelativePath(inputDir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		// Remove .nokvault extension
		outputRelPath := relPath[:len(relPath)-len(".nokvault")]
		outputPath := filepath.Join(outputDir, outputRelPath)

		// Ensure output directory exists
		outputFileDir := filepath.Dir(outputPath)
		if err := dd.fileHandler.EnsureDirectory(outputFileDir); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		// Report progress
		if onProgress != nil {
			onProgress(currentFile, totalFiles, outputRelPath)
		}

		// Decrypt file
		if err := dd.decryptFileWithMetadata(path, outputPath, key); err != nil {
			return fmt.Errorf("failed to decrypt %s: %w", relPath, err)
		}

		return nil
	})

	return err
}

// decryptFileWithMetadata decrypts a file and restores metadata
func (dd *DirectoryDecryptor) decryptFileWithMetadata(inputPath, outputPath string, key []byte) error {
	// Open input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	// Read header with metadata
	header, metadata, err := dd.fileHandler.ReadHeaderWithMetadata(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Derive key from salt (if we have the salt from header)
	// Note: In practice, we already have the key, but we verify it matches
	// For now, we'll use the provided key directly

	// Read encrypted data
	ciphertext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted data: %w", err)
	}

	// Skip header and metadata
	dataStart := int64(header.DataOffset)
	ciphertext = ciphertext[dataStart:]

	// Decrypt data
	plaintext, err := dd.encryptionService.DecryptData(ciphertext, key)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Try to decompress if data appears to be compressed
	if len(plaintext) >= 2 && plaintext[0] == 0x1f && plaintext[1] == 0x8b {
		decompressed, err := dd.compressionService.Decompress(plaintext)
		if err == nil {
			plaintext = decompressed
		}
	}

	// Write decrypted data
	if err := os.WriteFile(outputPath, plaintext, 0600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	// Restore metadata if available
	if metadata != nil {
		if err := dd.fileHandler.WriteMetadata(outputPath, metadata); err != nil {
			// Log warning but don't fail
			if dd.verbose {
				fmt.Fprintf(os.Stderr, "Warning: Could not restore metadata for %s: %v\n", outputPath, err)
			}
		}
	}

	return nil
}
