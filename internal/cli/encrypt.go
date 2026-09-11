package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jimididit/nokvault/internal/core"
	"github.com/jimididit/nokvault/internal/crypto"
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
	encryptRecipients []string
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
	encryptCmd.Flags().StringArrayVarP(&encryptRecipients, "recipient", "r", nil, "X25519 recipient public key or file (repeatable)")

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

	// Check for recipient mode
	usingRecipients := len(encryptRecipients) > 0
	if usingRecipients {
		// Recipient mode: enforce exclusivity
		if err := assertNoPassphraseMaterial(encryptPassword, encryptKeyfile); err != nil {
			return err
		}
		// Encrypt with recipients (skip passphrase path)
		return encryptWithRecipients(inputPath, outputPath, info.IsDir())
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

// assertNoPassphraseMaterial returns an error if password/keyfile flags or NOKVAULT_PASSWORD env var are set.
// Used to enforce recipient mode exclusivity.
func assertNoPassphraseMaterial(passwordFlag, keyfileFlag string) error {
	if passwordFlag != "" {
		return fmt.Errorf("recipient mode (-r) cannot be used with --password flag")
	}
	if keyfileFlag != "" {
		return fmt.Errorf("recipient mode (-r) cannot be used with --keyfile flag")
	}
	if os.Getenv("NOKVAULT_PASSWORD") != "" {
		return fmt.Errorf("recipient mode (-r) cannot be used with NOKVAULT_PASSWORD environment variable")
	}
	return nil
}

// parseRecipients parses recipient strings (inline or file paths) into Recipient objects.
func parseRecipients(args []string) ([]*crypto.Recipient, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}
	if len(args) > crypto.MaxRecipients {
		return nil, fmt.Errorf("too many recipients (max %d)", crypto.MaxRecipients)
	}
	
	recipients := make([]*crypto.Recipient, 0, len(args))
	for _, arg := range args {
		r, err := crypto.ReadRecipientFileOrString(arg)
		if err != nil {
			return nil, fmt.Errorf("failed to parse recipient %q: %w", arg, err)
		}
		recipients = append(recipients, r)
	}
	return recipients, nil
}

// encryptWithRecipients encrypts a file or directory using recipient mode (v4).
func encryptWithRecipients(inputPath, outputPath string, isDir bool) error {
	recipients, err := parseRecipients(encryptRecipients)
	if err != nil {
		return err
	}

	if encryptDryRun {
		processed := 1
		targetKind := "file"
		if isDir {
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
		PrintInfo(fmt.Sprintf("Would encrypt with %d recipient(s): %s -> %s", len(recipients), inputPath, outputPath))
		return nil
	}

	encryptionService := core.NewEncryptionService()
	var result EncryptResult
	if isDir {
		result, err = encryptDirectoryWithRecipientsAndCompression(inputPath, outputPath, recipients, encryptionService, shouldCompress())
	} else {
		result, err = encryptFileWithRecipientsAndCompression(inputPath, outputPath, recipients, encryptionService, shouldCompress())
	}
	if err != nil {
		return err
	}
	if JSONEnabled() {
		return EmitResult("encrypt", result)
	}
	if isDir {
		PrintSuccess(fmt.Sprintf("Encrypted %d files with %d recipient(s): %s -> %s", result.Succeeded, len(recipients), inputPath, outputPath))
	} else {
		PrintSuccess(fmt.Sprintf("Encrypted with %d recipient(s): %s -> %s", len(recipients), inputPath, outputPath))
	}
	return nil
}

// encryptFileWithRecipientsAndCompression encrypts a single file with recipients.
func encryptFileWithRecipientsAndCompression(inputPath, outputPath string, recipients []*crypto.Recipient, encryptionService *core.EncryptionService, compress bool) (result EncryptResult, err error) {
	result = EncryptResult{
		Input: inputPath, Output: outputPath, TargetKind: "file",
		Processed: 1, Force: encryptForce,
	}
	defer func() {
		if err != nil {
			result.Failed = 1
		}
	}()

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
		PrintInfo(fmt.Sprintf("Encrypting file with %d recipient(s): %s", len(recipients), inputPath))
		if compressFlag == 1 {
			PrintInfo("Compression enabled")
		}
	}

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

	if err := atomicWrite(outputPath, 0o600, func(outputFile *os.File) error {
		plaintext, err := os.Open(inputPath)
		if err != nil {
			return fmt.Errorf("failed to open input file: %w", err)
		}
		defer plaintext.Close()

		return encryptionService.EncryptVaultWithRecipients(outputFile, plaintext, recipients, metadata, compressFlag)
	}); err != nil {
		return result, fmt.Errorf("failed to encrypt file: %w", err)
	}

	result.Succeeded = 1
	return result, nil
}

// encryptDirectoryWithRecipientsAndCompression encrypts a directory with recipients.
func encryptDirectoryWithRecipientsAndCompression(inputPath, outputPath string, recipients []*crypto.Recipient, encryptionService *core.EncryptionService, compress bool) (result EncryptResult, err error) {
	result = EncryptResult{
		Input: inputPath, Output: outputPath, TargetKind: "directory",
		Force: encryptForce,
	}

	if encryptVerbose {
		PrintInfo(fmt.Sprintf("Encrypting directory with %d recipient(s): %s", len(recipients), inputPath))
		if compress {
			PrintInfo("Compression enabled")
		}
	}

	fileHandler := core.NewFileHandler()
	totalFiles, err := fileHandler.CountFiles(inputPath)
	if err != nil {
		return result, fmt.Errorf("failed to count files: %w", err)
	}
	result.Processed = totalFiles

	// Preflight: refuse existing outputs unless --force
	if err := fileHandler.WalkDirectory(inputPath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
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

	progressBar := newOperationProgressBar(int64(totalFiles), "Encrypting files")

	encryptor := core.NewDirectoryEncryptor(encryptionService, encryptVerbose)
	encryptor.SetCompression(compress)
	encryptor.SetOverwrite(encryptForce)

	err = encryptor.EncryptDirectoryWithRecipients(inputPath, outputPath, recipients, func(current, total int, currentFile string) {
		progressBar.Increment(1)
		if encryptVerbose {
			PrintInfo(fmt.Sprintf("[%d/%d] %s", current, total, currentFile))
		}
	})

	progressBar.Wait()

	if err != nil {
		PrintError(fmt.Sprintf("Directory encryption failed: %v", err))
		return result, err
	}

	result.Succeeded = totalFiles
	result.Failed = 0
	return result, nil
}
