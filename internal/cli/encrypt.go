package cli

import (
	"fmt"
	"os"

	"github.com/jimididit/nokvault/internal/core"
	"github.com/jimididit/nokvault/internal/utils"
	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt <path>",
	Short: "Encrypt a file or directory",
	Long: `Encrypt a file or directory using AES-256-GCM encryption.

The encrypted output will be saved as <path>.nokvault by default.
You can specify a custom output path using the --output flag.`,
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
)

func init() {
	encryptCmd.Flags().StringVarP(&encryptOutput, "output", "o", "", "Output file or directory path")
	encryptCmd.Flags().StringVarP(&encryptPassword, "password", "p", "", "Encryption password (not recommended for security)")
	encryptCmd.Flags().StringVarP(&encryptKeyfile, "keyfile", "k", "", "Path to keyfile")
	encryptCmd.Flags().BoolVar(&encryptNoPrompt, "no-prompt", false, "Don't prompt for password (use environment variable or keyfile)")
	encryptCmd.Flags().BoolVar(&encryptDryRun, "dry-run", false, "Show what would be encrypted without actually encrypting")
	encryptCmd.Flags().BoolVarP(&encryptVerbose, "verbose", "v", false, "Verbose output")
	encryptCmd.Flags().BoolVar(&encryptCompress, "compress", false, "Compress data before encryption")
	encryptCmd.Flags().BoolVar(&encryptNoCompress, "no-compress", false, "Disable compression (overrides config)")

	rootCmd.AddCommand(encryptCmd)
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	inputPath := args[0]

	// Validate input path
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		return utils.NewError(utils.ErrInvalidPath.Code, fmt.Sprintf("Path does not exist: %s", inputPath), err)
	}

	// Determine output path
	outputPath := encryptOutput
	if outputPath == "" {
		outputPath = inputPath + ".nokvault"
	}

	if encryptDryRun {
		PrintInfo(fmt.Sprintf("Would encrypt: %s -> %s", inputPath, outputPath))
		return nil
	}

	// Get password
	password, err := utils.GetPassword(encryptPassword, encryptKeyfile, encryptNoPrompt, true)
	if err != nil {
		return err
	}
	defer utils.ZeroizePassword(password)

	// Create encryption service
	encryptionService := core.NewEncryptionService()
	keyManager := encryptionService.GetKeyManager()

	// Derive key from password
	key, salt, err := keyManager.DeriveKeyFromPassword(password)
	if err != nil {
		return utils.NewError(utils.ErrKeyDerivation.Code, "Failed to derive encryption key", err)
	}
	defer utils.ZeroizeKey(key)

	// Encrypt file or directory
	info, err := os.Stat(inputPath)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return encryptDirectory(inputPath, outputPath, key, salt, encryptionService)
	}

	return encryptFile(inputPath, outputPath, key, salt, encryptionService)
}

func encryptFile(inputPath, outputPath string, key, salt []byte, encryptionService *core.EncryptionService) error {
	return encryptFileWithCompression(inputPath, outputPath, key, salt, encryptionService, shouldCompress())
}

func encryptFileWithCompression(inputPath, outputPath string, key, salt []byte, encryptionService *core.EncryptionService, compress bool) error {
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
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	// Read file data
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	originalSize := int64(len(data))

	// Compress if enabled
	if compress {
		compressionService := core.NewCompressionService()
		if compressionService.ShouldCompress(data, 1024) { // Compress if > 1KB
			compressed, err := compressionService.Compress(data)
			if err != nil {
				return fmt.Errorf("compression failed: %w", err)
			}
			if encryptVerbose {
				PrintInfo(fmt.Sprintf("Compressed: %d -> %d bytes (%.1f%%)", len(data), len(compressed), float64(len(compressed))/float64(len(data))*100))
			}
			data = compressed
		}
	}

	// Show progress for large files
	var progressBar *utils.ProgressBar
	if originalSize > 1024*1024 { // Show progress for files > 1MB
		progressBar = utils.NewProgressBar(originalSize, "Encrypting")
		defer progressBar.Wait()
	}

	// Encrypt data
	ciphertext, err := encryptionService.EncryptData(data, key)
	if err != nil {
		return utils.NewError(utils.ErrEncryptionFailed.Code, "Encryption failed", err)
	}

	if progressBar != nil {
		progressBar.Increment(originalSize)
	}

	// Create output file with header
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	// Write header with metadata
	if err := fileHandler.WriteHeader(outputFile, salt, metadata); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write encrypted data
	if _, err := outputFile.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write encrypted data: %w", err)
	}

	PrintSuccess(fmt.Sprintf("Encrypted: %s -> %s", inputPath, outputPath))
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

func encryptDirectory(inputPath, outputPath string, key, salt []byte, encryptionService *core.EncryptionService) error {
	return encryptDirectoryWithCompression(inputPath, outputPath, key, salt, encryptionService, shouldCompress())
}

func encryptDirectoryWithCompression(inputPath, outputPath string, key, salt []byte, encryptionService *core.EncryptionService, compress bool) error {
	fileHandler := core.NewFileHandler()

	// Count files for progress
	totalFiles, err := fileHandler.CountFiles(inputPath)
	if err != nil {
		return fmt.Errorf("failed to count files: %w", err)
	}

	if totalFiles == 0 {
		PrintInfo("No files found in directory")
		return nil
	}

	if encryptVerbose && compress {
		PrintInfo("Compression enabled for directory encryption")
	}

	PrintInfo(fmt.Sprintf("Encrypting %d files in directory...", totalFiles))

	// Create progress bar
	progressBar := utils.NewProgressBar(int64(totalFiles), "Encrypting files")
	defer progressBar.Wait()

	// Create directory encryptor
	encryptor := core.NewDirectoryEncryptor(encryptionService, encryptVerbose)
	encryptor.SetCompression(compress)

	// Encrypt directory with progress callback
	err = encryptor.EncryptDirectory(inputPath, outputPath, key, salt, func(current, total int, currentFile string) {
		progressBar.Increment(1)
		if encryptVerbose {
			PrintInfo(fmt.Sprintf("[%d/%d] %s", current, total, currentFile))
		}
	})

	if err != nil {
		PrintError(fmt.Sprintf("Directory encryption failed: %v", err))
		return err
	}

	PrintSuccess(fmt.Sprintf("Encrypted %d files: %s -> %s", totalFiles, inputPath, outputPath))
	return nil
}
