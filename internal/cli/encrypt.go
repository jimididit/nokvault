package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jimididit/nokvault/internal/core"
	"github.com/jimididit/nokvault/internal/utils"
	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt <path>",
	Short: "Encrypt a file or directory",
	Long: `Encrypt a file or directory using AES-256-GCM encryption.

The encrypted output will be saved as <path>.nokv by default.
You can specify a custom output path using the --output flag.
Legacy .nokvault outputs remain decryptable.`,
	Args: cobra.ExactArgs(1),
	RunE: runEncrypt,
}

var (
	encryptOutput     string
	encryptPassword   string
	encryptKeyfile    string
	encryptNoPrompt   bool
	encryptDryRun     bool
	encryptVerbose    bool
	encryptCompress   bool
	encryptNoCompress bool
	encryptForce      bool
)

func init() {
	encryptCmd.Flags().StringVarP(&encryptOutput, "output", "o", "", "Output file or directory path")
	encryptCmd.Flags().StringVarP(&encryptPassword, "password", "p", "", "Removed: passwords on argv are refused (use --keyfile or NOKVAULT_PASSWORD)")
	encryptCmd.Flags().StringVarP(&encryptKeyfile, "keyfile", "k", "", "Path to keyfile")
	encryptCmd.Flags().BoolVar(&encryptNoPrompt, "no-prompt", false, "Don't prompt for password (use environment variable or keyfile)")
	encryptCmd.Flags().BoolVar(&encryptDryRun, "dry-run", false, "Show what would be encrypted without actually encrypting")
	encryptCmd.Flags().BoolVarP(&encryptVerbose, "verbose", "v", false, "Verbose output")
	encryptCmd.Flags().BoolVar(&encryptCompress, "compress", false, "Compress data before encryption")
	encryptCmd.Flags().BoolVar(&encryptNoCompress, "no-compress", false, "Disable compression (overrides config)")
	encryptCmd.Flags().BoolVarP(&encryptForce, "force", "f", false, "Overwrite existing output path")

	rootCmd.AddCommand(encryptCmd)
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	inputPath := args[0]

	if err := utils.ValidateNoSymlinkComponents(inputPath); err != nil {
		return err
	}

	info, err := os.Lstat(inputPath)
	if os.IsNotExist(err) {
		return utils.NewError(utils.ErrInvalidPath.Code, fmt.Sprintf("Path does not exist: %s", inputPath), err)
	}
	if err != nil {
		return err
	}

	// Determine output path
	outputPath := encryptOutput
	if outputPath == "" {
		var derErr error
		outputPath, derErr = utils.DefaultVaultOutput(inputPath)
		if derErr != nil {
			return utils.NewError(utils.ErrInvalidPath.Code, derErr.Error(), derErr)
		}
	}

	if err := utils.ValidateNoSymlinkComponents(outputPath); err != nil {
		return err
	}

	if info.IsDir() {
		if err := preflightDirectoryEncryptOutputs(inputPath, outputPath); err != nil {
			return err
		}
	}

	if encryptDryRun {
		processed := 1
		targetKind := "file"
		if info.IsDir() {
			targetKind = "directory"
			processed, err = core.NewFileHandler().CountFiles(inputPath)
			if err != nil {
				return fmt.Errorf("failed to count files: %w", err)
			}
		}
		if JSONEnabled() {
			return EmitResult("encrypt", EncryptResult{
				Input: inputPath, Output: outputPath, TargetKind: targetKind,
				DryRun: true, Processed: processed, Succeeded: processed,
				Compression: shouldCompress(), Force: encryptForce,
			})
		}
		PrintInfo(fmt.Sprintf("Would encrypt: %s -> %s", inputPath, outputPath))
		return nil
	}

	// Get password
	password, err := utils.GetPassword(encryptPassword, encryptKeyfile, encryptNoPrompt || JSONEnabled(), true)
	if err != nil {
		return utils.NewError(utils.ErrInvalidPassword.Code, "Failed to get encryption password", err)
	}
	defer utils.ZeroizePassword(password)

	// Create encryption service
	encryptionService := core.NewEncryptionService()
	keyManager := encryptionService.GetKeyManager()
	if err := applyKDFConfig(keyManager); err != nil {
		return utils.NewError(utils.ErrKeyDerivation.Code, "Invalid key derivation configuration", err)
	}

	// Derive key from password
	key, salt, err := keyManager.DeriveKeyFromPassword(password)
	if err != nil {
		return utils.NewError(utils.ErrKeyDerivation.Code, "Failed to derive encryption key", err)
	}
	defer utils.ZeroizeKey(key)

	var result EncryptResult
	if info.IsDir() {
		result, err = encryptDirectoryWithCompression(inputPath, outputPath, key, salt, encryptionService, shouldCompress())
	} else {
		result, err = encryptFileWithCompression(inputPath, outputPath, key, salt, encryptionService, shouldCompress())
	}
	if err != nil {
		return err
	}
	if JSONEnabled() {
		return EmitResult("encrypt", result)
	}
	if info.IsDir() {
		PrintSuccess(fmt.Sprintf("Encrypted %d files: %s -> %s", result.Succeeded, inputPath, outputPath))
	} else {
		PrintSuccess(fmt.Sprintf("Encrypted: %s -> %s", inputPath, outputPath))
	}
	return nil
}

func encryptFileWithCompression(inputPath, outputPath string, key, salt []byte, encryptionService *core.EncryptionService, compress bool) (result EncryptResult, err error) {
	result = EncryptResult{
		Input: inputPath, Output: outputPath, TargetKind: "file",
		Processed: 1, Compression: compress, Force: encryptForce,
	}
	defer func() {
		if err != nil {
			result.Failed = 1
		}
	}()
	if encryptVerbose {
		PrintInfo(fmt.Sprintf("Encrypting file: %s", inputPath))
		if compress {
			PrintInfo("Compression enabled")
		}
	}

	// Read file metadata
	fileHandler := core.NewFileHandler()
	metadata, err := fileHandler.ReadMetadata(inputPath)
	if err != nil {
		return result, fmt.Errorf("failed to read metadata: %w", err)
	}

	// Read file data
	// #nosec G304 -- runEncrypt validates the user-selected input path before this read.
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return result, fmt.Errorf("failed to read file: %w", err)
	}

	// Compress if enabled
	if compress {
		compressionService := core.NewCompressionService()
		if compressionService.ShouldCompress(data, 1024) { // Compress if > 1KB
			compressed, err := compressionService.Compress(data)
			if err != nil {
				return result, fmt.Errorf("compression failed: %w", err)
			}
			if encryptVerbose {
				PrintInfo(fmt.Sprintf("Compressed: %d -> %d bytes (%.1f%%)", len(data), len(compressed), float64(len(compressed))/float64(len(data))*100))
			}
			data = compressed
		}
	}

	// Note: For single file operations, we process everything at once,
	// so progress bars aren't very useful. We'll skip them for now.
	// Progress bars work better for directory operations.
	// Show progress for large files (disabled - not useful for single file ops)
	// var progressBar *utils.ProgressBar
	// if originalSize > 1024*1024 {
	// 	progressBar = utils.NewProgressBar(originalSize, "Encrypting")
	// }

	// Encrypt data
	ciphertext, err := encryptionService.EncryptData(data, key)
	if err != nil {
		return result, utils.NewError(utils.ErrEncryptionFailed.Code, "Encryption failed", err)
	}

	// Ensure output directory exists (only if not root directory)
	if outputDir := filepath.Dir(outputPath); outputDir != "." && outputDir != "" {
		if err := os.MkdirAll(outputDir, 0700); err != nil {
			return result, fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	if err := refuseIfExists(outputPath, encryptForce); err != nil {
		PrintError(err.Error())
		return result, err
	}

	atomicWrite := utils.AtomicWriteFuncNoReplace
	if encryptForce {
		atomicWrite = utils.AtomicWriteFunc
	}
	err = atomicWrite(outputPath, 0o600, func(outputFile *os.File) error {
		if err := fileHandler.WriteHeader(outputFile, salt, metadata, encryptionService.GetKeyManager().Params()); err != nil {
			return fmt.Errorf("failed to write header: %w", err)
		}
		if _, err := outputFile.Write(ciphertext); err != nil {
			return fmt.Errorf("failed to write encrypted data: %w", err)
		}
		return nil
	})
	if err != nil {
		return result, err
	}

	result.Succeeded = 1
	return result, nil
}

func shouldCompress() bool {
	// Command line flags take precedence
	if encryptNoCompress {
		return false
	}
	if encryptCompress {
		return true
	}
	// TODO: Check config file
	return false
}

func encryptDirectoryWithCompression(inputPath, outputPath string, key, salt []byte, encryptionService *core.EncryptionService, compress bool) (EncryptResult, error) {
	result := EncryptResult{
		Input: inputPath, Output: outputPath, TargetKind: "directory",
		Compression: compress, Force: encryptForce,
	}
	fileHandler := core.NewFileHandler()

	// Count files for progress
	totalFiles, err := fileHandler.CountFiles(inputPath)
	if err != nil {
		return result, fmt.Errorf("failed to count files: %w", err)
	}
	result.Processed = totalFiles

	if totalFiles == 0 {
		PrintInfo("No files found in directory")
		return result, nil
	}

	if encryptVerbose && compress {
		PrintInfo("Compression enabled for directory encryption")
	}

	PrintInfo(fmt.Sprintf("Encrypting %d files in directory...", totalFiles))

	// Preflight: refuse existing outputs unless --force
	if err := fileHandler.WalkDirectory(inputPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relPath, relErr := fileHandler.GetRelativePath(inputPath, path)
		if relErr != nil {
			return relErr
		}
		out, joinErr := utils.SafeJoin(outputPath, utils.WithVaultExt(relPath))
		if joinErr != nil {
			return joinErr
		}
		if refuseErr := refuseIfExists(out, encryptForce); refuseErr != nil {
			PrintError(refuseErr.Error())
			return refuseErr
		}
		return nil
	}); err != nil {
		return result, err
	}

	// Create progress bar
	progressBar := newOperationProgressBar(int64(totalFiles), "Encrypting files")

	// Create directory encryptor
	encryptor := core.NewDirectoryEncryptor(encryptionService, encryptVerbose)
	encryptor.SetCompression(compress)
	encryptor.SetOverwrite(encryptForce)

	// Encrypt directory with progress callback
	err = encryptor.EncryptDirectory(inputPath, outputPath, key, salt, func(current, total int, currentFile string) {
		progressBar.Increment(1)
		if encryptVerbose {
			PrintInfo(fmt.Sprintf("[%d/%d] %s", current, total, currentFile))
		}
	})

	// Complete and wait for progress bar before printing success message
	progressBar.Wait()

	if err != nil {
		PrintError(fmt.Sprintf("Directory encryption failed: %v", err))
		return result, err
	}

	result.Succeeded = totalFiles
	return result, nil
}
