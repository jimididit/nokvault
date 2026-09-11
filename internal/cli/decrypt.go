package cli

import (
	"errors"
	"fmt"
	"io"
	"math"
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

The decrypted output will be saved to the original location (without .nokv / legacy .nokvault extension)
by default, or to the path specified by --output flag.`,
	Args: cobra.ExactArgs(1),
	RunE: runDecrypt,
}

var (
	decryptOutput       string
	decryptPassword     string
	decryptKeyfile      string
	decryptNoPrompt     bool
	decryptDryRun       bool
	decryptVerbose      bool
	decryptPreserveMode bool
	decryptForce        bool
	decryptStrict       bool
	decryptIdentities   []string
)

func init() {
	decryptCmd.Flags().StringVarP(&decryptOutput, "output", "o", "", "Output file or directory path")
	decryptCmd.Flags().StringVarP(&decryptPassword, "password", "p", "", "Removed: passwords on argv are refused (use --keyfile or NOKVAULT_PASSWORD)")
	decryptCmd.Flags().StringVarP(&decryptKeyfile, "keyfile", "k", "", "Path to keyfile")
	decryptCmd.Flags().BoolVar(&decryptNoPrompt, "no-prompt", false, "Don't prompt for password")
	decryptCmd.Flags().BoolVar(&decryptDryRun, "dry-run", false, "Show what would be decrypted without actually decrypting")
	decryptCmd.Flags().BoolVar(&decryptPreserveMode, "preserve-mode", false, "Restore original file modes (default clamps to ≤0600 files / ≤0700 dirs)")
	decryptCmd.Flags().BoolVarP(&decryptForce, "force", "f", false, "Overwrite existing output path")
	decryptCmd.Flags().BoolVar(&decryptStrict, "strict", false, "Abort directory decrypt on the first failure")
	decryptCmd.Flags().BoolVarP(&decryptVerbose, "verbose", "v", false, "Verbose output")
	decryptCmd.Flags().StringArrayVar(&decryptIdentities, "identity", nil, "X25519 identity file for recipient-mode vaults (repeatable)")

	rootCmd.AddCommand(decryptCmd)
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	inputPath := args[0]

	if err := utils.ValidateNoSymlinkComponents(inputPath); err != nil {
		return err
	}

	info, err := os.Lstat(inputPath)
	if os.IsNotExist(err) {
		PrintError(fmt.Sprintf("Path does not exist: %s", inputPath))
		return utils.NewError(utils.ErrFileNotFound.Code, fmt.Sprintf("Path does not exist: %s", inputPath), err)
	}
	if err != nil {
		return err
	}

	// Determine output path
	outputPath := decryptOutput
	if outputPath == "" {
		cleaned := filepath.Clean(inputPath)
		if stripped, ok := utils.StripVaultExt(cleaned); ok {
			outputPath = stripped
		} else {
			outputPath = cleaned + ".decrypted"
		}
	}

	if err := utils.ValidateNoSymlinkComponents(outputPath); err != nil {
		return err
	}

	if info.IsDir() {
		if err := preflightDirectoryDecryptOutputs(inputPath, outputPath); err != nil {
			return err
		}
	}

	if decryptDryRun {
		processed := 1
		targetKind := "file"
		if info.IsDir() {
			targetKind = "directory"
			processed = 0
			countErr := core.NewFileHandler().WalkDirectory(inputPath, func(path string, entry os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if !entry.IsDir() && utils.IsVaultPath(path) {
					processed++
				}
				return nil
			})
			if countErr != nil {
				return countErr
			}
		}
		if JSONEnabled() {
			return EmitResult("decrypt", DecryptResult{
				Input: inputPath, Output: outputPath, TargetKind: targetKind,
				DryRun: true, Processed: processed, Succeeded: processed,
				Force: decryptForce, Strict: decryptStrict,
			})
		}
		PrintInfo(fmt.Sprintf("Would decrypt: %s -> %s", inputPath, outputPath))
		return nil
	}

	// Check if using identity mode
	usingIdentities := len(decryptIdentities) > 0
	
	// For directories with identities, go directly to identity-based decrypt
	if info.IsDir() && usingIdentities {
		// Check for passphrase material exclusivity
		if decryptPassword != "" || decryptKeyfile != "" || os.Getenv("NOKVAULT_PASSWORD") != "" {
			return fmt.Errorf("cannot mix --identity with password/keyfile/NOKVAULT_PASSWORD")
		}
		identities, err := loadIdentities(decryptIdentities)
		if err != nil {
			return err
		}
		encryptionService := core.NewEncryptionService()
		return decryptDirectoryWithIdentities(inputPath, outputPath, identities, encryptionService)
	}
	
	// For single files, peek at the vault header to determine version/requirements
	if !info.IsDir() {
		fileHandler := core.NewFileHandler()
		// Read the version to determine mode requirements
		// #nosec G304 -- runDecrypt validates the user-selected input path
		peekFile, err := os.Open(inputPath)
		if err != nil {
			return fmt.Errorf("failed to open input file: %w", err)
		}
		header, _, _, _, err := fileHandler.ReadHeaderWithMetadata(peekFile)
		peekFile.Close()
		if err != nil {
			// If header read fails and we're not using identities, fall through to password flow
			// which will give a better error (INVALID_PASSWORD instead of INVALID_FORMAT)
			if !usingIdentities {
				goto passphraseFlow
			}
			return utils.NewError(utils.ErrInvalidFormat.Code, "Invalid nokvault file format", err)
		}
		vaultVersion := header.Version

		// Version 4 (recipient mode) requirements
		if vaultVersion == core.Version4 {
			if !usingIdentities {
				return fmt.Errorf("recipient vault (v4) requires --identity flag")
			}
			// v4 refuses passphrase material
			if decryptPassword != "" || decryptKeyfile != "" || os.Getenv("NOKVAULT_PASSWORD") != "" {
				return fmt.Errorf("recipient vault (v4) cannot use passphrase material (password/keyfile/NOKVAULT_PASSWORD); use --identity only")
			}
			// Decrypt with identities
			identities, err := loadIdentities(decryptIdentities)
			if err != nil {
				return err
			}
			encryptionService := core.NewEncryptionService()
			return decryptFileWithIdentities(inputPath, outputPath, identities, encryptionService)
		}

		// v1-v3 passphrase mode with --identity is an error
		if usingIdentities {
			return fmt.Errorf("--identity can only be used with recipient vaults (v4); this is a passphrase vault (v%d)", vaultVersion)
		}
	}

passphraseFlow:
	// Passphrase mode - check exclusivity
	if usingIdentities {
		return fmt.Errorf("cannot mix --identity with password/keyfile/NOKVAULT_PASSWORD")
	}

	// Get password first (needed for both file and directory)
	password, err := utils.GetPassword(decryptPassword, decryptKeyfile, decryptNoPrompt || JSONEnabled(), false)
	if err != nil {
		return utils.NewError(utils.ErrInvalidPassword.Code, "Failed to get decryption password", err)
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
	// #nosec G304 -- runDecrypt validates the user-selected input path before this open.
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	// Read header with metadata
	fileHandler := core.NewFileHandler()
	header, metadata, aad, _, err := fileHandler.ReadHeaderWithMetadata(inputFile)
	if err != nil {
		PrintError("Invalid nokvault file format")
		return utils.NewError(utils.ErrInvalidFormat.Code, "Invalid nokvault file format", err)
	}

	// Derive key from password and salt using header KDF parameters
	keyManager := encryptionService.GetKeyManager()
	keyManager.SetArgon2Params(header.Argon2Params())
	key, err := keyManager.DeriveKeyFromPasswordAndSalt(password, header.Salt[:])
	if err != nil {
		PrintError("Failed to derive decryption key")
		return err
	}
	defer utils.ZeroizeKey(key)

	dataOffset, err := checkedDataOffset(header.DataOffset)
	if err != nil {
		return err
	}
	if _, err := inputFile.Seek(dataOffset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek encrypted data: %w", err)
	}
	// Ensure output directory exists (only if not root directory)
	if outputDir := filepath.Dir(outputPath); outputDir != "." && outputDir != "" {
		if err := os.MkdirAll(outputDir, 0700); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	if err := refuseIfExists(outputPath, decryptForce); err != nil {
		PrintError(err.Error())
		return err
	}

	atomicWrite := utils.AtomicWriteFuncNoReplace
	if decryptForce {
		atomicWrite = utils.AtomicWriteFunc
	}
	compressionService := core.NewCompressionService()
	if err := atomicWrite(outputPath, 0o600, func(outputFile *os.File) error {
		if err := decryptVaultToOutput(outputFile, inputFile, key, header, aad, encryptionService, compressionService); err != nil {
			return utils.NewErrorWithHint(utils.ErrDecryptionFailed.Code, "Decryption failed - incorrect password or corrupted file", err, "Verify your password is correct. If using a keyfile, ensure it hasn't changed.")
		}
		return nil
	}); err != nil {
		return err
	}

	// Restore metadata if available
	if metadata != nil {
		if err := fileHandler.WriteMetadata(outputPath, metadata, decryptPreserveMode); err != nil {
			if decryptVerbose {
				PrintInfo(fmt.Sprintf("Warning: Could not restore metadata: %v", err))
			}
		}
	}

	if JSONEnabled() {
		return EmitResult("decrypt", DecryptResult{
			Input: inputPath, Output: outputPath, TargetKind: "file",
			Processed: 1, Succeeded: 1, Force: decryptForce, Strict: decryptStrict,
		})
	}
	PrintSuccess(fmt.Sprintf("Decrypted: %s -> %s", inputPath, outputPath))
	return nil
}

func decryptDirectory(inputPath, outputPath string, password []byte, encryptionService *core.EncryptionService) error {
	fileHandler := core.NewFileHandler()
	result := DecryptResult{
		Input: inputPath, Output: outputPath, TargetKind: "directory",
		Force: decryptForce, Strict: decryptStrict,
	}

	// Count vault files for progress
	totalFiles := 0
	err := fileHandler.WalkDirectory(inputPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && utils.IsVaultPath(path) {
			totalFiles++
		}
		return nil
	})
	if err != nil {
		if isPathPolicyError(err) {
			return err
		}
		return WithErrorData(fmt.Errorf("failed to count files: %w", err), result)
	}
	result.Processed = totalFiles

	if totalFiles == 0 {
		if JSONEnabled() {
			return EmitResult("decrypt", result)
		}
		PrintInfo("No .nokv / .nokvault files found in directory")
		return nil
	}

	PrintInfo(fmt.Sprintf("Decrypting %d files in directory...", totalFiles))

	// Create progress bar
	progressBar := newOperationProgressBar(int64(totalFiles), "Decrypting files")

	// For directory decryption, we need to handle key derivation per file
	// Each file may have a different salt, so we derive the key per file
	// This is a simplified version - in practice, we'd want to optimize this
	var failedFiles []string
	var successCount int

	recordFailure := func(relPath string, cause error) error {
		PrintError(fmt.Sprintf("Failed to decrypt %s: %v", relPath, cause))
		progressBar.Increment(1)
		failedFiles = append(failedFiles, relPath)
		result.Failed++
		result.Failures = append(result.Failures, fileFailure(relPath, cause))
		if decryptStrict {
			result.AbortedAt = relPath
			return WithErrorData(utils.NewError(
				utils.ErrPartialFailure.Code,
				fmt.Sprintf("Strict directory decryption aborted after failure on %s", relPath),
				cause,
			), result)
		}
		return nil
	}

	walkErr := fileHandler.WalkDirectory(inputPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if isPathPolicyError(err) {
				return err
			}
			PrintError(fmt.Sprintf("Error accessing %s: %v", path, err))
			if decryptStrict {
				return fmt.Errorf("strict mode: aborted after access error on %s: %w", path, err)
			}
			return nil
		}

		// Skip directories and non-vault files
		if info.IsDir() || !utils.IsVaultPath(path) {
			return nil
		}

		// Get relative path
		relPath, err := fileHandler.GetRelativePath(inputPath, path)
		if err != nil {
			return recordFailure(path, err)
		}

		outputRelPath, ok := utils.StripVaultExt(relPath)
		if !ok {
			return recordFailure(relPath, fmt.Errorf("not a vault path: %s", relPath))
		}
		outputFilePath, joinErr := utils.SafeJoin(outputPath, outputRelPath)
		if joinErr != nil {
			if isPathPolicyError(joinErr) {
				return joinErr
			}
			return recordFailure(relPath, joinErr)
		}

		// Ensure output directory exists
		outputFileDir := filepath.Dir(outputFilePath)
		if err := fileHandler.EnsureDirectory(outputFileDir); err != nil {
			return recordFailure(relPath, err)
		}

		if err := refuseIfExists(outputFilePath, decryptForce); err != nil {
			return recordFailure(relPath, err)
		}

		// Read header to get salt
		// #nosec G304 -- WalkDirectory validates every path before this open.
		inputFile, err := os.Open(path)
		if err != nil {
			return recordFailure(relPath, err)
		}
		defer inputFile.Close()

		header, _, _, _, err := fileHandler.ReadHeaderWithMetadata(inputFile)
		if err != nil {
			return recordFailure(relPath, err)
		}

		// Derive key from password and salt using header KDF parameters
		keyManager := encryptionService.GetKeyManager()
		keyManager.SetArgon2Params(header.Argon2Params())
		key, err := keyManager.DeriveKeyFromPasswordAndSalt(password, header.Salt[:])
		if err != nil {
			return recordFailure(relPath, err)
		}
		defer utils.ZeroizeKey(key)

		// Decrypt single file
		if err := decryptSingleFile(path, outputFilePath, key, encryptionService, fileHandler); err != nil {
			return recordFailure(relPath, err)
		}

		successCount++
		result.Succeeded++
		progressBar.Increment(1)
		if decryptVerbose {
			PrintInfo(fmt.Sprintf("Decrypted: %s", outputRelPath))
		}

		return nil
	})
	if walkErr != nil {
		progressBar.Abort()
		var operationErr *operationError
		if errors.As(walkErr, &operationErr) {
			return walkErr
		}
		return WithErrorData(walkErr, result)
	}

	// Report results
	if len(failedFiles) > 0 {
		PrintError(fmt.Sprintf("Failed to decrypt %d file(s):", len(failedFiles)))
		for _, file := range failedFiles {
			PrintError(fmt.Sprintf("  - %s", file))
		}
		if successCount > 0 {
			PrintInfo(fmt.Sprintf("Successfully decrypted %d file(s)", successCount))
		}
		return WithErrorData(
			utils.NewError(
				utils.ErrPartialFailure.Code,
				fmt.Sprintf("Directory decryption completed with %d error(s) out of %d file(s)", len(failedFiles), totalFiles),
				nil,
			),
			result,
		)
	}

	if successCount == 0 && totalFiles > 0 {
		progressBar.Wait()
		return WithErrorData(utils.NewError(
			utils.ErrPartialFailure.Code,
			"Failed to decrypt any files",
			nil,
		), result)
	}

	// Complete and wait for progress bar before printing success message
	progressBar.Wait()

	if JSONEnabled() {
		return EmitResult("decrypt", result)
	}
	PrintSuccess(fmt.Sprintf("Decrypted %d files: %s -> %s", successCount, inputPath, outputPath))
	return nil
}

func decryptSingleFile(inputPath, outputPath string, key []byte, encryptionService *core.EncryptionService, fileHandler *core.FileHandler) error {
	// Open input file
	// #nosec G304 -- WalkDirectory validates the caller-selected input path before this open.
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	// Read header with metadata
	header, metadata, aad, _, err := fileHandler.ReadHeaderWithMetadata(inputFile)
	if err != nil {
		return utils.NewError(utils.ErrInvalidFormat.Code, "Invalid nokvault file format", err)
	}

	// Read encrypted data (skip header)
	dataOffset, err := checkedDataOffset(header.DataOffset)
	if err != nil {
		return err
	}
	if _, err := inputFile.Seek(dataOffset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek encrypted data: %w", err)
	}
	// Ensure output directory exists (only if not root directory)
	if outputDir := filepath.Dir(outputPath); outputDir != "." && outputDir != "" {
		if err := os.MkdirAll(outputDir, 0700); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	if err := refuseIfExists(outputPath, decryptForce); err != nil {
		return err
	}

	atomicWrite := utils.AtomicWriteFuncNoReplace
	if decryptForce {
		atomicWrite = utils.AtomicWriteFunc
	}
	compressionService := core.NewCompressionService()
	if err := atomicWrite(outputPath, 0o600, func(outputFile *os.File) error {
		if err := decryptVaultToOutput(outputFile, inputFile, key, header, aad, encryptionService, compressionService); err != nil {
			return utils.NewError(utils.ErrDecryptionFailed.Code, "Decryption failed", err)
		}
		return nil
	}); err != nil {
		return err
	}

	// Restore metadata if available
	if metadata != nil {
		if err := fileHandler.WriteMetadata(outputPath, metadata, decryptPreserveMode); err != nil {
			// Log warning but don't fail
		}
	}

	return nil
}

func decryptVaultToOutput(
	outputFile *os.File,
	payload io.Reader,
	key []byte,
	header *core.NokvaultHeader,
	aad []byte,
	encryptionService *core.EncryptionService,
	compressionService *core.CompressionService,
) error {
	if header.Version == core.Version3 && header.Compress == 0 {
		return encryptionService.DecryptVaultPayload(outputFile, payload, key, header.Version, aad)
	}

	intermediate, err := os.CreateTemp(filepath.Dir(outputFile.Name()), ".nokvault-plaintext-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create decryption staging file: %w", err)
	}
	intermediateName := intermediate.Name()
	defer func() {
		_ = intermediate.Close()
		_ = os.Remove(intermediateName)
	}()

	if err := encryptionService.DecryptVaultPayload(intermediate, payload, key, header.Version, aad); err != nil {
		return err
	}
	if _, err := intermediate.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to rewind decrypted payload: %w", err)
	}

	if header.Version == core.Version3 {
		gzipReader, err := compressionService.GzipReader(intermediate)
		if err != nil {
			return fmt.Errorf("failed to create decompressor: %w", err)
		}
		_, copyErr := io.Copy(outputFile, gzipReader)
		closeErr := gzipReader.Close()
		if copyErr != nil {
			return fmt.Errorf("failed to decompress payload: %w", copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("failed to close decompressor: %w", closeErr)
		}
		return nil
	}

	var magic [2]byte
	n, readErr := io.ReadFull(intermediate, magic[:])
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		return fmt.Errorf("failed to inspect legacy plaintext: %w", readErr)
	}
	if _, err := intermediate.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to rewind legacy plaintext: %w", err)
	}
	if n == len(magic) && magic[0] == 0x1f && magic[1] == 0x8b {
		gzipReader, gzipErr := compressionService.GzipReader(intermediate)
		if gzipErr == nil {
			_, copyErr := io.Copy(outputFile, gzipReader)
			closeErr := gzipReader.Close()
			if copyErr == nil && closeErr == nil {
				return nil
			}
		}
		if err := outputFile.Truncate(0); err != nil {
			return fmt.Errorf("failed to reset output after legacy gzip fallback: %w", err)
		}
		if _, err := outputFile.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("failed to rewind output after legacy gzip fallback: %w", err)
		}
		if _, err := intermediate.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("failed to rewind legacy plaintext: %w", err)
		}
	}

	if _, err := io.Copy(outputFile, intermediate); err != nil {
		return fmt.Errorf("failed to write decrypted payload: %w", err)
	}
	return nil
}

func checkedDataOffset(offset uint64) (int64, error) {
	if offset > math.MaxInt64 {
		return 0, fmt.Errorf("encrypted data offset %d exceeds platform limit", offset)
	}
	return int64(offset), nil
}
