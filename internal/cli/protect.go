package cli

import (
	"github.com/jimididit/nokvault/internal/utils"
	"github.com/spf13/cobra"
)

var protectCmd = &cobra.Command{
	Use:    "protect <path>",
	Short:  "Unavailable encrypted archive command",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	RunE:   runProtect,
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
	protectCmd.Flags().StringVarP(&protectPassword, "password", "p", "", "Removed: passwords on argv are refused (use --keyfile or NOKVAULT_PASSWORD)")
	protectCmd.Flags().StringVarP(&protectKeyfile, "keyfile", "k", "", "Path to keyfile")
	protectCmd.Flags().BoolVar(&protectNoPrompt, "no-prompt", false, "Don't prompt for password")
	protectCmd.Flags().BoolVar(&protectDryRun, "dry-run", false, "Show what would be protected without actually protecting")
	protectCmd.Flags().BoolVarP(&protectVerbose, "verbose", "v", false, "Verbose output")

	rootCmd.AddCommand(protectCmd)
}

func runProtect(cmd *cobra.Command, args []string) error {
	return utils.NewErrorWithHint(
		"COMMAND_UNAVAILABLE",
		"protect archive mode is not implemented",
		nil,
		"Use 'nokvault encrypt <path>' to encrypt a file or directory.",
	)
}
