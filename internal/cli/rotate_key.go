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
	Long: `Re-key a nokvault encrypted file by decrypting it with the old password
and re-encrypting it with a new password (new salt + ciphertext).

This is useful for password changes or key rotation policies. The operation
rewrites the file in place via a temporary file and rename.`,
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
	rotateKeyCmd.Flags().StringVarP(&rotateKeyOldPassword, "old-password", "o", "", "Removed: passwords on argv are refused (use --old-keyfile or prompt)")
	rotateKeyCmd.Flags().StringVarP(&rotateKeyNewPassword, "new-password", "n", "", "Removed: passwords on argv are refused (use --new-keyfile or prompt)")
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

	// Read header
	fileHandler := core.NewFileHandler()
	header, metadata, err := fileHandler.ReadHeaderWithMetadata(inputFile)
	if err != nil {
		inputFile.Close()
		PrintError("Invalid nokvault file format")
		return utils.NewError(utils.ErrInvalidFormat.Code, "Invalid nokvault file format", err)
	}

	// Derive old key using header KDF parameters
	keyManager.SetArgon2Params(header.Argon2Params())
	oldKey, err := keyManager.DeriveKeyFromPasswordAndSalt(oldPassword, header.Salt[:])
	if err != nil {
		PrintError("Failed to derive old key")
		return err
	}
	defer utils.ZeroizeKey(oldKey)

	// Read encrypted data
	if _, err := inputFile.Seek(int64(header.DataOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek encrypted data: %w", err)
	}
	ciphertext, err := io.ReadAll(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read encrypted data: %w", err)
	}
	// Close before replace — Windows cannot rename over a file that is still open.
	if err := inputFile.Close(); err != nil {
		return fmt.Errorf("failed to close input file: %w", err)
	}

	// Decrypt with old key
	plaintext, err := encryptionService.DecryptData(ciphertext, oldKey)
	if err != nil {
		PrintError("Decryption failed - incorrect old password")
		return utils.NewError(utils.ErrDecryptionFailed.Code, "Decryption failed", err)
	}
	defer utils.ZeroizePassword(plaintext)

	if rotateKeyVerbose {
		PrintInfo("Successfully decrypted with old key")
	}

	// Re-key with encrypt-side params from runtime config.
	if err := applyKDFConfig(keyManager); err != nil {
		return fmt.Errorf("invalid key derivation configuration: %w", err)
	}

	// Generate new salt and derive new key from that same salt (must match header).
	newSalt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate new salt: %w", err)
	}

	newKey, err := keyManager.DeriveKeyFromPasswordAndSalt(newPassword, newSalt)
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

	// Create temporary output via atomic write helper
	if err := utils.AtomicWriteFunc(inputPath, 0o600, func(outputFile *os.File) error {
		if err := fileHandler.WriteHeader(outputFile, newSalt, metadata, keyManager.Params()); err != nil {
			return fmt.Errorf("failed to write header: %w", err)
		}
		if _, err := outputFile.Write(newCiphertext); err != nil {
			return fmt.Errorf("failed to write encrypted data: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	PrintSuccess(fmt.Sprintf("Key rotated successfully: %s", inputPath))
	return nil
}
