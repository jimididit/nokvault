package cli

import (
	"fmt"
	"os"

	"github.com/jimididit/nokvault/internal/crypto"
	"github.com/spf13/cobra"
)

var (
	keygenOut       string
	keygenPublicOut string
	keygenForce     bool
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a NokVault X25519 identity",
	Long: `Generate a new X25519 identity for recipient-mode encryption.

The secret identity is written to a file (default: nokvault-identity.txt).
The public recipient string is printed to stdout and can optionally be
written to a separate file with --public-out.

Identity files MUST have mode 0600 (Unix) and contain the secret key.
Recipients can be shared freely.`,
	RunE: runKeygen,
}

func init() {
	keygenCmd.Flags().StringVarP(&keygenOut, "output", "o", "nokvault-identity.txt", "Secret identity file path")
	keygenCmd.Flags().StringVar(&keygenPublicOut, "public-out", "", "Optional public recipient file path")
	keygenCmd.Flags().BoolVar(&keygenForce, "force", false, "Overwrite existing identity file")
	rootCmd.AddCommand(keygenCmd)
}

func runKeygen(cmd *cobra.Command, args []string) error {
	// Generate identity
	identity, recipient, err := crypto.GenerateIdentity()
	if err != nil {
		return fmt.Errorf("failed to generate identity: %w", err)
	}

	// Write secret identity file
	if err := crypto.WriteIdentityFile(keygenOut, identity, keygenForce); err != nil {
		return err
	}

	PrintInfo(fmt.Sprintf("Identity written to: %s", keygenOut))

	// Encode recipient
	recipientStr, err := recipient.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode recipient: %w", err)
	}

	// Print recipient to stdout
	fmt.Println(recipientStr)

	// Optionally write public recipient file
	if keygenPublicOut != "" {
		content := "# nokvault recipient\n" + recipientStr + "\n"
		if err := os.WriteFile(keygenPublicOut, []byte(content), 0o600); err != nil {
			return fmt.Errorf("failed to write public recipient file: %w", err)
		}
		PrintInfo(fmt.Sprintf("Public recipient written to: %s", keygenPublicOut))
	}

	return nil
}
