package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jimididit/nokvault/internal/utils"
)

func ensureContainedOutputRoot(fh *FileHandler, outputDir string) error {
	if err := utils.ValidateNoSymlinkComponents(outputDir); err != nil {
		return err
	}
	if err := fh.EnsureDirectory(outputDir); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	if err := utils.ValidateNoSymlinkComponents(outputDir); err != nil {
		return err
	}
	return nil
}

// DirectoryEncryptor handles directory encryption operations
type DirectoryEncryptor struct {
	encryptionService  *EncryptionService
	fileHandler        *FileHandler
	compressionService *CompressionService
	verbose            bool
	compress           bool
	overwrite          bool
}

// NewDirectoryEncryptor creates a new directory encryptor
func NewDirectoryEncryptor(encryptionService *EncryptionService, verbose bool) *DirectoryEncryptor {
	return &DirectoryEncryptor{
		encryptionService:  encryptionService,
		fileHandler:        NewFileHandler(),
		compressionService: NewCompressionService(),
		verbose:            verbose,
		compress:           false,
		overwrite:          true,
	}
}

// SetCompression enables or disables compression
func (de *DirectoryEncryptor) SetCompression(compress bool) {
	de.compress = compress
}

// SetOverwrite controls whether existing encrypted outputs may be replaced.
// It defaults to true for existing non-CLI callers such as watch and schedule.
func (de *DirectoryEncryptor) SetOverwrite(overwrite bool) {
	de.overwrite = overwrite
}

// EncryptDirectory encrypts all files in a directory recursively
func (de *DirectoryEncryptor) EncryptDirectory(inputDir, outputDir string, key, salt []byte, onProgress func(current, total int, currentFile string)) error {
	// Count/validate input before creating a missing output root.
	totalFiles, err := de.fileHandler.CountFiles(inputDir)
	if err != nil {
		return fmt.Errorf("failed to count files: %w", err)
	}

	if err := ensureContainedOutputRoot(de.fileHandler, outputDir); err != nil {
		return err
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
		outputPath, err := utils.SafeJoin(outputDir, utils.WithVaultExt(relPath))
		if err != nil {
			return fmt.Errorf("failed to construct output path for %s: %w", relPath, err)
		}

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

	compressFlag := uint8(0)
	if de.compress {
		shouldCompress, err := de.compressionService.ShouldCompressFile(inputPath, 1024)
		if err != nil {
			return err
		}
		if shouldCompress {
			compressFlag = 1
		}
	}

	atomicWrite := utils.AtomicWriteFuncNoReplace
	if de.overwrite {
		atomicWrite = utils.AtomicWriteFunc
	}
	if err := atomicWrite(outputPath, 0o600, func(outputFile *os.File) error {
		// #nosec G304 -- directory walking validates this caller-selected path.
		inputFile, err := os.Open(inputPath)
		if err != nil {
			return fmt.Errorf("failed to open input file: %w", err)
		}
		defer inputFile.Close()
		if compressFlag == 0 {
			return de.encryptionService.EncryptVault(outputFile, inputFile, key, salt, metadata, 0)
		}
		return encryptVaultGzip(outputFile, inputFile, key, salt, metadata, de.encryptionService, de.compressionService)
	}); err != nil {
		return err
	}

	return nil
}

func encryptVaultGzip(output io.Writer, plaintext io.Reader, key, salt []byte, metadata *FileMetadata, es *EncryptionService, cs *CompressionService) error {
	compressedReader, compressedWriter := io.Pipe()
	done := make(chan error, 1)
	go func() {
		gzipWriter := cs.GzipWriter(compressedWriter)
		_, copyErr := io.Copy(gzipWriter, plaintext)
		closeErr := gzipWriter.Close()
		if copyErr == nil {
			copyErr = closeErr
		}
		_ = compressedWriter.CloseWithError(copyErr)
		done <- copyErr
	}()

	encryptErr := es.EncryptVault(output, compressedReader, key, salt, metadata, 1)
	_ = compressedReader.CloseWithError(encryptErr)
	compressErr := <-done
	if encryptErr != nil {
		return encryptErr
	}
	if compressErr != nil {
		return fmt.Errorf("compression failed: %w", compressErr)
	}
	return nil
}

// DirectoryDecryptor handles directory decryption operations
type DirectoryDecryptor struct {
	encryptionService  *EncryptionService
	fileHandler        *FileHandler
	compressionService *CompressionService
	verbose            bool
	preserveMode       bool
}

// NewDirectoryDecryptor creates a new directory decryptor
func NewDirectoryDecryptor(encryptionService *EncryptionService, verbose bool) *DirectoryDecryptor {
	return &DirectoryDecryptor{
		encryptionService:  encryptionService,
		fileHandler:        NewFileHandler(),
		compressionService: NewCompressionService(),
		verbose:            verbose,
		preserveMode:       false,
	}
}

// SetPreserveMode controls whether original file modes are restored without clamping.
func (dd *DirectoryDecryptor) SetPreserveMode(preserve bool) {
	dd.preserveMode = preserve
}

// DecryptDirectory decrypts all vault files (.nokv / legacy .nokvault) in a directory recursively
func (dd *DirectoryDecryptor) DecryptDirectory(inputDir, outputDir string, password []byte, onProgress func(current, total int, currentFile string)) error {
	// Count/validate input before creating a missing output root.
	totalFiles := 0
	err := dd.fileHandler.WalkDirectory(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && utils.IsVaultPath(path) {
			totalFiles++
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to count files: %w", err)
	}

	if err := ensureContainedOutputRoot(dd.fileHandler, outputDir); err != nil {
		return err
	}

	currentFile := 0

	// Walk directory and decrypt each vault file
	err = dd.fileHandler.WalkDirectory(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error accessing %s: %w", path, err)
		}

		// Skip directories and non-vault files
		if info.IsDir() || !utils.IsVaultPath(path) {
			return nil
		}

		currentFile++

		// Get relative path
		relPath, err := dd.fileHandler.GetRelativePath(inputDir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		outputRelPath, ok := utils.StripVaultExt(relPath)
		if !ok {
			return fmt.Errorf("not a vault path: %s", relPath)
		}
		outputPath, err := utils.SafeJoin(outputDir, outputRelPath)
		if err != nil {
			return fmt.Errorf("failed to construct output path for %s: %w", outputRelPath, err)
		}

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
		if err := dd.decryptFileWithMetadata(path, outputPath, password); err != nil {
			return fmt.Errorf("failed to decrypt %s: %w", relPath, err)
		}

		return nil
	})

	return err
}

// decryptFileWithMetadata decrypts a file and restores metadata
func (dd *DirectoryDecryptor) decryptFileWithMetadata(inputPath, outputPath string, password []byte) error {
	// Open input file
	// #nosec G304 -- directory walking and output preflight validate this caller-selected path.
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	// Read header with metadata
	header, metadata, aad, err := dd.fileHandler.ReadHeaderWithMetadata(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Derive key from password and salt using header KDF parameters
	keyManager := dd.encryptionService.GetKeyManager()
	keyManager.SetArgon2Params(header.Argon2Params())
	key, err := keyManager.DeriveKeyFromPasswordAndSalt(password, header.Salt[:])
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}
	defer utils.ZeroizeKey(key)

	if err := utils.AtomicWriteFunc(outputPath, 0o600, func(outputFile *os.File) error {
		return decryptVaultPayloadToFile(outputFile, inputFile, key, header, aad, dd.encryptionService, dd.compressionService)
	}); err != nil {
		return fmt.Errorf("failed to decrypt output file: %w", err)
	}

	// Restore metadata if available
	if metadata != nil {
		if err := dd.fileHandler.WriteMetadata(outputPath, metadata, dd.preserveMode); err != nil {
			// Log warning but don't fail
			if dd.verbose {
				fmt.Fprintf(os.Stderr, "Warning: Could not restore metadata for %s: %v\n", outputPath, err)
			}
		}
	}

	return nil
}

func decryptVaultPayloadToFile(outputFile *os.File, payload io.Reader, key []byte, header *NokvaultHeader, aad []byte, es *EncryptionService, cs *CompressionService) error {
	if header.Version == Version3 && header.Compress == 0 {
		return es.DecryptVaultPayload(outputFile, payload, key, header.Version, aad)
	}

	staging, err := os.CreateTemp(filepath.Dir(outputFile.Name()), ".nokvault-plaintext-*.tmp")
	if err != nil {
		return err
	}
	stagingName := staging.Name()
	defer func() {
		_ = staging.Close()
		_ = os.Remove(stagingName)
	}()
	if err := es.DecryptVaultPayload(staging, payload, key, header.Version, aad); err != nil {
		return err
	}
	if _, err := staging.Seek(0, io.SeekStart); err != nil {
		return err
	}

	if header.Version == Version3 {
		gzipReader, err := cs.GzipReader(staging)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(outputFile, gzipReader)
		closeErr := gzipReader.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}

	var magic [2]byte
	n, readErr := io.ReadFull(staging, magic[:])
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		return readErr
	}
	if _, err := staging.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if n == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gzipReader, gzipErr := cs.GzipReader(staging)
		if gzipErr == nil {
			_, copyErr := io.Copy(outputFile, gzipReader)
			closeErr := gzipReader.Close()
			if copyErr == nil && closeErr == nil {
				return nil
			}
		}
		if err := outputFile.Truncate(0); err != nil {
			return err
		}
		if _, err := outputFile.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if _, err := staging.Seek(0, io.SeekStart); err != nil {
			return err
		}
	}
	_, err = io.Copy(outputFile, staging)
	return err
}
