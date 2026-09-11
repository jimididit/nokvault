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

	if err := utils.ValidateNoSymlinkComponents(inputPath); err != nil {
		return err
	}

	if _, err := os.Lstat(inputPath); os.IsNotExist(err) {
		PrintError(fmt.Sprintf("Path does not exist: %s", inputPath))
		return utils.NewError(utils.ErrFileNotFound.Code, fmt.Sprintf("Path does not exist: %s", inputPath), err)
	} else if err != nil {
		return err
	}

	// Get old password
	oldPassword, err := utils.GetPassword(rotateKeyOldPassword, rotateKeyOldKeyfile, rotateKeyNoPrompt || JSONEnabled(), false)
	if err != nil {
		return utils.NewError(utils.ErrInvalidPassword.Code, "Failed to get old password", err)
	}
	defer utils.ZeroizePassword(oldPassword)

	// Get new password
	newPassword, err := utils.GetPassword(rotateKeyNewPassword, rotateKeyNewKeyfile, rotateKeyNoPrompt || JSONEnabled(), true)
	if err != nil {
		return utils.NewError(utils.ErrInvalidPassword.Code, "Failed to get new password", err)
	}
	defer utils.ZeroizePassword(newPassword)

	// Create encryption service
	encryptionService := core.NewEncryptionService()
	keyManager := encryptionService.GetKeyManager()

	// Open input file
	// #nosec G304 -- runRotateKey validates the user-selected input path before this open.
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	// Read header
	fileHandler := core.NewFileHandler()
	header, metadata, aad, err := fileHandler.ReadHeaderWithMetadata(inputFile)
	if err != nil {
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

	dataOffset, err := checkedDataOffset(header.DataOffset)
	if err != nil {
		return err
	}
	if _, err := inputFile.Seek(dataOffset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek encrypted data: %w", err)
	}
	plaintextFile, err := os.CreateTemp(filepath.Dir(inputPath), ".nokvault-rotate-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create rotation staging file: %w", err)
	}
	plaintextName := plaintextFile.Name()
	defer func() {
		_ = plaintextFile.Close()
		_ = os.Remove(plaintextName)
	}()

	if err := encryptionService.DecryptVaultPayload(plaintextFile, inputFile, oldKey, header.Version, aad); err != nil {
		PrintError("Decryption failed - incorrect old password")
		return utils.NewError(utils.ErrDecryptionFailed.Code, "Decryption failed", err)
	}

	compressFlag := header.Compress
	if header.Version < core.Version3 {
		if _, err := plaintextFile.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("failed to rewind decrypted payload: %w", err)
		}
		var magic [2]byte
		n, readErr := io.ReadFull(plaintextFile, magic[:])
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return fmt.Errorf("failed to inspect decrypted payload: %w", readErr)
		}
		if n == len(magic) && magic[0] == 0x1f && magic[1] == 0x8b {
			compressFlag = 1
		}
	}

	// Close before replace - Windows cannot rename over a file that is still open.
	if err := inputFile.Close(); err != nil {
		return fmt.Errorf("failed to close input file: %w", err)
	}

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

	// Create temporary output via atomic write helper
	if err := utils.AtomicWriteFunc(inputPath, 0o600, func(outputFile *os.File) error {
		if _, err := plaintextFile.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("failed to rewind decrypted payload: %w", err)
		}
		if err := encryptionService.EncryptVault(outputFile, plaintextFile, newKey, newSalt, metadata, compressFlag); err != nil {
			return fmt.Errorf("failed to encrypt rotated vault: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	if JSONEnabled() {
		return EmitResult("rotate-key", RotateKeyResult{Path: inputPath, Status: "rotated"})
	}
	PrintSuccess(fmt.Sprintf("Key rotated successfully: %s", inputPath))
	return nil
}
