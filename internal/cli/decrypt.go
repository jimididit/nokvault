package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jimididit/nokvault/internal/core"
	"github.com/jimididit/nokvault/internal/utils"
	"github.com/spf13/cobra"
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt <path>",
	Short: "Decrypt a file or directory",
	Long: `Decrypt a nokvault encrypted file or directory.

The decrypted output will be saved to the original location (without .nokvault extension)
by default, or to the path specified by --output flag.`,
	Args: cobra.ExactArgs(1),
	RunE: runDecrypt,
}

var (
	decryptOutput   string
	decryptPassword string
	decryptKeyfile  string
	decryptNoPrompt bool
	decryptDryRun   bool
	decryptVerbose  bool
)

func init() {
	decryptCmd.Flags().StringVarP(&decryptOutput, "output", "o", "", "Output file or directory path")
	decryptCmd.Flags().StringVarP(&decryptPassword, "password", "p", "", "Decryption password")
	decryptCmd.Flags().StringVarP(&decryptKeyfile, "keyfile", "k", "", "Path to keyfile")
	decryptCmd.Flags().BoolVar(&decryptNoPrompt, "no-prompt", false, "Don't prompt for password")
	decryptCmd.Flags().BoolVar(&decryptDryRun, "dry-run", false, "Show what would be decrypted without actually decrypting")
	decryptCmd.Flags().BoolVarP(&decryptVerbose, "verbose", "v", false, "Verbose output")

	rootCmd.AddCommand(decryptCmd)
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	inputPath := args[0]

	// Validate input path
	info, err := os.Stat(inputPath)
	if os.IsNotExist(err) {
		PrintError(fmt.Sprintf("Path does not exist: %s", inputPath))
		return utils.NewError(utils.ErrFileNotFound.Code, fmt.Sprintf("Path does not exist: %s", inputPath), err)
	}

	// Determine output path
	outputPath := decryptOutput
	if outputPath == "" {
		// Remove .nokvault extension if present
		if filepath.Ext(inputPath) == ".nokvault" {
			outputPath = inputPath[:len(inputPath)-len(".nokvault")]
		} else {
			outputPath = inputPath + ".decrypted"
		}
	}

	if decryptDryRun {
		PrintInfo(fmt.Sprintf("Would decrypt: %s -> %s", inputPath, outputPath))
		return nil
	}

	// Get password first (needed for both file and directory)
	password, err := utils.GetPassword(decryptPassword, decryptKeyfile, decryptNoPrompt, false)
	if err != nil {
		return err
	}
	defer utils.ZeroizePassword(password)

	// Create encryption service
	encryptionService := core.NewEncryptionService()

	// Handle directory vs file
	if info.IsDir() {
		return decryptDirectory(inputPath, outputPath, password, encryptionService)
	}

	return decryptFile(inputPath, outputPath, password, encryptionService)
}

func decryptFile(inputPath, outputPath string, password []byte, encryptionService *core.EncryptionService) error {
	if decryptVerbose {
		PrintInfo(fmt.Sprintf("Decrypting file: %s", inputPath))
	}

	// Open input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	// Read header with metadata
	fileHandler := core.NewFileHandler()
	header, metadata, err := fileHandler.ReadHeaderWithMetadata(inputFile)
	if err != nil {
		PrintError("Invalid nokvault file format")
		return utils.NewError(utils.ErrInvalidFormat.Code, "Invalid nokvault file format", err)
	}

	// Derive key from password and salt
	keyManager := encryptionService.GetKeyManager()
	key, err := keyManager.DeriveKeyFromPasswordAndSalt(password, header.Salt[:])
	if err != nil {
		PrintError("Failed to derive decryption key")
		return err
	}
	defer utils.ZeroizeKey(key)

	// Read file to get size for progress
	fileInfo, err := inputFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	// Show progress for large files
	var progressBar *utils.ProgressBar
	if fileInfo.Size() > 1024*1024 { // Show progress for files > 1MB
		progressBar = utils.NewProgressBar(fileInfo.Size(), "Decrypting")
		defer progressBar.Wait()
	}

	// Read encrypted data (skip header)
	inputFile.Seek(int64(header.DataOffset), io.SeekStart)
	ciphertext, err := io.ReadAll(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read encrypted data: %w", err)
	}

	if progressBar != nil {
		progressBar.Increment(int64(len(ciphertext)))
	}

	// Decrypt data
	plaintext, err := encryptionService.DecryptData(ciphertext, key)
	if err != nil {
		return utils.NewErrorWithHint(utils.ErrDecryptionFailed.Code, "Decryption failed - incorrect password or corrupted file", err, "Verify your password is correct. If using a keyfile, ensure it hasn't changed.")
	}

	// Try to decompress if data appears to be compressed
	compressionService := core.NewCompressionService()
	if len(plaintext) >= 2 && plaintext[0] == 0x1f && plaintext[1] == 0x8b {
		// Looks like gzip compressed data
		decompressed, err := compressionService.Decompress(plaintext)
		if err == nil {
			if decryptVerbose {
				PrintInfo(fmt.Sprintf("Decompressed: %d -> %d bytes", len(plaintext), len(decompressed)))
			}
			plaintext = decompressed
		} else if decryptVerbose {
			PrintInfo("Data appears compressed but decompression failed, using as-is")
		}
	}

	// Write decrypted data
	if err := os.WriteFile(outputPath, plaintext, 0600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	// Restore metadata if available
	if metadata != nil {
		if err := fileHandler.WriteMetadata(outputPath, metadata); err != nil {
			if decryptVerbose {
				PrintInfo(fmt.Sprintf("Warning: Could not restore metadata: %v", err))
			}
		}
	}

	PrintSuccess(fmt.Sprintf("Decrypted: %s -> %s", inputPath, outputPath))
	return nil
}

func decryptDirectory(inputPath, outputPath string, password []byte, encryptionService *core.EncryptionService) error {
	fileHandler := core.NewFileHandler()

	// Count .nokvault files for progress
	totalFiles := 0
	err := fileHandler.WalkDirectory(inputPath, func(path string, info os.FileInfo, err error) error {
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

	if totalFiles == 0 {
		PrintInfo("No .nokvault files found in directory")
		return nil
	}

	PrintInfo(fmt.Sprintf("Decrypting %d files in directory...", totalFiles))

	// Create progress bar
	progressBar := utils.NewProgressBar(int64(totalFiles), "Decrypting files")

	// For directory decryption, we need to handle key derivation per file
	// Each file may have a different salt, so we derive the key per file
	// This is a simplified version - in practice, we'd want to optimize this
	var failedFiles []string
	var successCount int

	err = fileHandler.WalkDirectory(inputPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Log error but continue processing
			PrintError(fmt.Sprintf("Error accessing %s: %v", path, err))
			return nil // Continue with other files
		}

		// Skip directories and non-.nokvault files
		if info.IsDir() || filepath.Ext(path) != ".nokvault" {
			return nil
		}

		// Get relative path
		relPath, err := fileHandler.GetRelativePath(inputPath, path)
		if err != nil {
			PrintError(fmt.Sprintf("Failed to get relative path for %s: %v", path, err))
			progressBar.Increment(1)
			failedFiles = append(failedFiles, relPath)
			return nil // Continue with other files
		}

		// Remove .nokvault extension
		outputRelPath := relPath[:len(relPath)-len(".nokvault")]
		outputFilePath := filepath.Join(outputPath, outputRelPath)

		// Ensure output directory exists
		outputFileDir := filepath.Dir(outputFilePath)
		if err := fileHandler.EnsureDirectory(outputFileDir); err != nil {
			PrintError(fmt.Sprintf("Failed to create output directory for %s: %v", relPath, err))
			progressBar.Increment(1)
			failedFiles = append(failedFiles, relPath)
			return nil // Continue with other files
		}

		// Read header to get salt
		inputFile, err := os.Open(path)
		if err != nil {
			PrintError(fmt.Sprintf("Failed to open file %s: %v", relPath, err))
			progressBar.Increment(1)
			failedFiles = append(failedFiles, relPath)
			return nil // Continue with other files
		}
		defer inputFile.Close()

		header, _, err := fileHandler.ReadHeaderWithMetadata(inputFile)
		if err != nil {
			PrintError(fmt.Sprintf("Failed to read header for %s: %v", relPath, err))
			progressBar.Increment(1)
			failedFiles = append(failedFiles, relPath)
			return nil // Continue with other files
		}

		// Derive key from password and salt
		keyManager := encryptionService.GetKeyManager()
		key, err := keyManager.DeriveKeyFromPasswordAndSalt(password, header.Salt[:])
		if err != nil {
			PrintError(fmt.Sprintf("Failed to derive key for %s: %v", relPath, err))
			progressBar.Increment(1)
			failedFiles = append(failedFiles, relPath)
			return nil // Continue with other files
		}
		defer utils.ZeroizeKey(key)

		// Decrypt single file
		if err := decryptSingleFile(path, outputFilePath, key, encryptionService, fileHandler); err != nil {
			PrintError(fmt.Sprintf("Failed to decrypt %s: %v", relPath, err))
			progressBar.Increment(1)
			failedFiles = append(failedFiles, relPath)
			return nil // Continue with other files instead of stopping
		}

		successCount++
		progressBar.Increment(1)
		if decryptVerbose {
			PrintInfo(fmt.Sprintf("Decrypted: %s", outputRelPath))
		}

		return nil
	})

	// Report results
	if len(failedFiles) > 0 {
		PrintError(fmt.Sprintf("Failed to decrypt %d file(s):", len(failedFiles)))
		for _, file := range failedFiles {
			PrintError(fmt.Sprintf("  - %s", file))
		}
		if successCount > 0 {
			PrintInfo(fmt.Sprintf("Successfully decrypted %d file(s)", successCount))
		}
		return fmt.Errorf("directory decryption completed with %d error(s) out of %d file(s)", len(failedFiles), totalFiles)
	}

	if successCount == 0 && totalFiles > 0 {
		progressBar.Wait()
		return fmt.Errorf("failed to decrypt any files - check password and file integrity")
	}

	// Complete and wait for progress bar before printing success message
	progressBar.Wait()

	PrintSuccess(fmt.Sprintf("Decrypted %d files: %s -> %s", successCount, inputPath, outputPath))
	return nil
}

func decryptSingleFile(inputPath, outputPath string, key []byte, encryptionService *core.EncryptionService, fileHandler *core.FileHandler) error {
	// Open input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	// Read header with metadata
	header, metadata, err := fileHandler.ReadHeaderWithMetadata(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Read encrypted data (skip header)
	inputFile.Seek(int64(header.DataOffset), io.SeekStart)
	ciphertext, err := io.ReadAll(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read encrypted data: %w", err)
	}

	// Decrypt data
	plaintext, err := encryptionService.DecryptData(ciphertext, key)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Try to decompress if data appears to be compressed
	compressionService := core.NewCompressionService()
	if len(plaintext) >= 2 && plaintext[0] == 0x1f && plaintext[1] == 0x8b {
		// Looks like gzip compressed data
		decompressed, err := compressionService.Decompress(plaintext)
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
		if err := fileHandler.WriteMetadata(outputPath, metadata); err != nil {
			// Log warning but don't fail
		}
	}

	return nil
}
