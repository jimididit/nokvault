package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/jimididit/nokvault/internal/core"
	"github.com/jimididit/nokvault/internal/crypto"
	"github.com/jimididit/nokvault/internal/utils"
	"github.com/spf13/cobra"
)

var rotateKeyCmd = &cobra.Command{
	Use:   "rotate-key <path>",
	Short: "Rotate the encryption key for an encrypted file",
	Long: `Rotate the encryption key for a nokvault encrypted file by decrypting
it with the old password and re-encrypting it with a new password.

This is useful for password changes or key rotation policies.`,
	Args: cobra.ExactArgs(1),
	RunE: runRotateKey,
}

var (
	rotateKeyOldPassword string
	rotateKeyNewPassword string
	rotateKeyOldKeyfile  string
	rotateKeyNewKeyfile  string
	rotateKeyNoPrompt    bool
	rotateKeyVerbose     bool
)

func init() {
	rotateKeyCmd.Flags().StringVarP(&rotateKeyOldPassword, "old-password", "o", "", "Old password")
	rotateKeyCmd.Flags().StringVarP(&rotateKeyNewPassword, "new-password", "n", "", "New password")
	rotateKeyCmd.Flags().StringVar(&rotateKeyOldKeyfile, "old-keyfile", "", "Old keyfile path")
	rotateKeyCmd.Flags().StringVar(&rotateKeyNewKeyfile, "new-keyfile", "", "New keyfile path")
	rotateKeyCmd.Flags().BoolVar(&rotateKeyNoPrompt, "no-prompt", false, "Don't prompt for passwords")
	rotateKeyCmd.Flags().BoolVarP(&rotateKeyVerbose, "verbose", "v", false, "Verbose output")

	rootCmd.AddCommand(rotateKeyCmd)
}

func runRotateKey(cmd *cobra.Command, args []string) error {
	inputPath := args[0]

	// Validate input path
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		PrintError(fmt.Sprintf("Path does not exist: %s", inputPath))
		return utils.NewError(utils.ErrFileNotFound.Code, fmt.Sprintf("Path does not exist: %s", inputPath), err)
	}

	// Get old password
	oldPassword, err := utils.GetPassword(rotateKeyOldPassword, rotateKeyOldKeyfile, rotateKeyNoPrompt, false)
	if err != nil {
		return fmt.Errorf("failed to get old password: %w", err)
	}
	defer utils.ZeroizePassword(oldPassword)

	// Get new password
	newPassword, err := utils.GetPassword(rotateKeyNewPassword, rotateKeyNewKeyfile, rotateKeyNoPrompt, true)
	if err != nil {
		return fmt.Errorf("failed to get new password: %w", err)
	}
	defer utils.ZeroizePassword(newPassword)

	// Create encryption service
	encryptionService := core.NewEncryptionService()
	keyManager := encryptionService.GetKeyManager()

	// Open input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	// Read header
	fileHandler := core.NewFileHandler()
	header, metadata, err := fileHandler.ReadHeaderWithMetadata(inputFile)
	if err != nil {
		PrintError("Invalid nokvault file format")
		return utils.NewError(utils.ErrInvalidFormat.Code, "Invalid nokvault file format", err)
	}

	// Derive old key
	oldKey, err := keyManager.DeriveKeyFromPasswordAndSalt(oldPassword, header.Salt[:])
	if err != nil {
		PrintError("Failed to derive old key")
		return err
	}
	defer utils.ZeroizeKey(oldKey)

	// Read encrypted data
	inputFile.Seek(int64(header.DataOffset), io.SeekStart)
	ciphertext, err := io.ReadAll(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read encrypted data: %w", err)
	}

	// Decrypt with old key
	plaintext, err := encryptionService.DecryptData(ciphertext, oldKey)
	if err != nil {
		PrintError("Decryption failed - incorrect old password")
		return utils.NewError(utils.ErrDecryptionFailed.Code, "Decryption failed", err)
	}

	if rotateKeyVerbose {
		PrintInfo("Successfully decrypted with old key")
	}

	// Generate new salt and derive new key
	newSalt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate new salt: %w", err)
	}

	newKey, _, err := keyManager.DeriveKeyFromPassword(newPassword)
	if err != nil {
		PrintError("Failed to derive new key")
		return err
	}
	defer utils.ZeroizeKey(newKey)

	// Encrypt with new key
	newCiphertext, err := encryptionService.EncryptData(plaintext, newKey)
	if err != nil {
		PrintError("Encryption with new key failed")
		return err
	}

	// Create temporary output file
	tempPath := inputPath + ".tmp"
	outputFile, err := os.Create(tempPath)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer outputFile.Close()

	// Write header with new salt
	if err := fileHandler.WriteHeader(outputFile, newSalt, metadata); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write encrypted data
	if _, err := outputFile.Write(newCiphertext); err != nil {
		return fmt.Errorf("failed to write encrypted data: %w", err)
	}
	outputFile.Close()

	// Atomic replace
	if err := os.Rename(tempPath, inputPath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to replace file: %w", err)
	}

	PrintSuccess(fmt.Sprintf("Key rotated successfully: %s", inputPath))
	return nil
}
