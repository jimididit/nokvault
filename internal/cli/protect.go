package cli

import (
	"fmt"
	"os"

	"github.com/jimididit/nokvault/internal/utils"
	"github.com/spf13/cobra"
)

var protectCmd = &cobra.Command{
	Use:   "protect <path>",
	Short: "Protect a folder by creating an encrypted archive",
	Long: `Protect a folder by creating an encrypted .nokvault archive file.

This command creates a single encrypted archive file containing all files
from the specified directory. This is useful for backing up or sharing
entire directory structures securely.`,
	Args: cobra.ExactArgs(1),
	RunE: runProtect,
}

var (
	protectOutput   string
	protectPassword string
	protectKeyfile  string
	protectNoPrompt bool
	protectDryRun   bool
	protectVerbose  bool
)

func init() {
	protectCmd.Flags().StringVarP(&protectOutput, "output", "o", "", "Output archive file path")
	protectCmd.Flags().StringVarP(&protectPassword, "password", "p", "", "Encryption password")
	protectCmd.Flags().StringVarP(&protectKeyfile, "keyfile", "k", "", "Path to keyfile")
	protectCmd.Flags().BoolVar(&protectNoPrompt, "no-prompt", false, "Don't prompt for password")
	protectCmd.Flags().BoolVar(&protectDryRun, "dry-run", false, "Show what would be protected without actually protecting")
	protectCmd.Flags().BoolVarP(&protectVerbose, "verbose", "v", false, "Verbose output")

	rootCmd.AddCommand(protectCmd)
}

func runProtect(cmd *cobra.Command, args []string) error {
	inputPath := args[0]

	// Validate input path
	info, err := os.Stat(inputPath)
	if os.IsNotExist(err) {
		PrintError(fmt.Sprintf("Path does not exist: %s", inputPath))
		return utils.NewError(utils.ErrInvalidPath.Code, fmt.Sprintf("Path does not exist: %s", inputPath), err)
	}

	if !info.IsDir() {
		PrintError("protect command only works with directories. Use 'encrypt' for files.")
		return fmt.Errorf("protect command requires a directory")
	}

	// Determine output path
	outputPath := protectOutput
	if outputPath == "" {
		outputPath = inputPath + ".nokvault"
	}

	if protectDryRun {
		PrintInfo(fmt.Sprintf("Would protect directory: %s -> %s", inputPath, outputPath))
		return nil
	}

	PrintInfo("Directory protection (archive mode) is not yet fully implemented.")
	PrintInfo("For now, use 'encrypt' command on individual files.")
	return fmt.Errorf("directory protection not yet implemented - use 'encrypt' for files")

	// TODO: Implement directory archiving with compression
	// This will be implemented in Phase 2
}
