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
		Processed: 1, Force: encryptForce,
	}
	defer func() {
		if err != nil {
			result.Failed = 1
		}
	}()
	// Read file metadata
	fileHandler := core.NewFileHandler()
	metadata, err := fileHandler.ReadMetadata(inputPath)
	if err != nil {
		return result, fmt.Errorf("failed to read metadata: %w", err)
	}

	compressFlag := uint8(0)
	compressionService := core.NewCompressionService()
	if compress {
		shouldCompress, err := compressionService.ShouldCompressFile(inputPath, 1024)
		if err != nil {
			return result, fmt.Errorf("failed to inspect input for compression: %w", err)
		}
		if shouldCompress {
			compressFlag = 1
		}
	}
	result.Compression = compressFlag == 1

	if encryptVerbose {
		PrintInfo(fmt.Sprintf("Encrypting file: %s", inputPath))
		if compressFlag == 1 {
			PrintInfo("Compression enabled")
		}
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
		// #nosec G304 -- runEncrypt validates the user-selected input path before this open.
		inputFile, err := os.Open(inputPath)
		if err != nil {
			return fmt.Errorf("failed to open input file: %w", err)
		}
		defer inputFile.Close()

		if compressFlag == 0 {
			if err := encryptionService.EncryptVault(outputFile, inputFile, key, salt, metadata, 0); err != nil {
				return utils.NewError(utils.ErrEncryptionFailed.Code, "Encryption failed", err)
			}
			return nil
		}
		if err := encryptVaultWithGzip(outputFile, inputFile, key, salt, metadata, encryptionService, compressionService); err != nil {
			return utils.NewError(utils.ErrEncryptionFailed.Code, "Encryption failed", err)
		}
		return nil
	})
	if err != nil {
		return result, err
	}

	result.Succeeded = 1
	return result, nil
}

func encryptVaultWithGzip(
	output io.Writer,
	plaintext io.Reader,
	key, salt []byte,
	metadata *core.FileMetadata,
	encryptionService *core.EncryptionService,
	compressionService *core.CompressionService,
) error {
	compressedReader, compressedWriter := io.Pipe()
	compressDone := make(chan error, 1)
	go func() {
		gzipWriter := compressionService.GzipWriter(compressedWriter)
		_, copyErr := io.Copy(gzipWriter, plaintext)
		closeErr := gzipWriter.Close()
		if copyErr == nil {
			copyErr = closeErr
		}
		_ = compressedWriter.CloseWithError(copyErr)
		compressDone <- copyErr
	}()

	encryptErr := encryptionService.EncryptVault(output, compressedReader, key, salt, metadata, 1)
	_ = compressedReader.CloseWithError(encryptErr)
	compressErr := <-compressDone
	if encryptErr != nil {
		return encryptErr
	}
	if compressErr != nil {
		return fmt.Errorf("compression failed: %w", compressErr)
	}
	return nil
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
