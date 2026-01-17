package cli

import (
	"fmt"
	"os"

	"github.com/jimididit/nokvault/internal/config"
	"github.com/spf13/cobra"
)

var (
	// Version is set during build
	Version = "dev"
	// Commit is set during build
	Commit = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "nokvault",
	Short: "A modern CLI tool for encrypting and protecting local folders",
	Long: `Nokvault is a comprehensive CLI tool for encrypting and protecting 
local folders and files. It provides beginner-friendly commands while offering 
advanced features for power users.

Features:
  - Simple encryption/decryption commands
  - Password and keyfile support
  - Multiple encryption algorithms
  - File watching and automation
  - Secure deletion
  - Cross-platform support (Windows, Linux, macOS)`,
	Version: fmt.Sprintf("%s (commit: %s)", Version, Commit),
}

// Execute runs the root command
func Execute() {
	// Load configuration
	cm := config.NewConfigManager()
	if err := cm.Load(); err != nil {
		// Config loading errors are non-fatal
		// Default config will be used
	}

	if err := rootCmd.Execute(); err != nil {
		PrintErrorWithHint(err)
		os.Exit(1)
	}
}

// GetRootCmd returns the root command (for testing)
func GetRootCmd() *cobra.Command {
	return rootCmd
}

// These functions are now in errors.go to avoid duplication
