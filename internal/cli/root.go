package cli

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

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
	Short: "A modern CLI tool for encrypting local files and folders",
	Long: `Nokvault is a comprehensive CLI tool for encrypting local files and
folders. It provides beginner-friendly commands while offering
advanced features for power users.

Features:
  - Simple encryption/decryption commands
  - Password and keyfile support
  - AES-256-GCM authenticated encryption
  - File watching and automation
  - Secure deletion
  - Cross-platform support (Windows, Linux, macOS)`,
	Version: fmt.Sprintf("%s (commit: %s)", Version, Commit),
}

var jsonOutput bool

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Emit stable machine-readable JSON output")
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		ConfigureOutput(cmd.OutOrStdout(), cmd.ErrOrStderr(), jsonOutput && isOperationalCommand(commandName(cmd)))
	}
	installRootHelpBanner(rootCmd)
}

// Run executes NokVault with injectable streams and returns its process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	// Load configuration
	cm := config.NewConfigManager()
	if err := cm.Load(); err != nil {
		// Config loading errors are non-fatal
		// Default config will be used
	}
	SetRuntimeConfig(cm.Get())

	rootCmd.SetArgs(args)
	rootCmd.SetOut(stdout)
	rootCmd.SetErr(stderr)
	ConfigureOutput(stdout, stderr, false)
	jsonRequested := requestsJSON(args)
	rootCmd.SilenceErrors = jsonRequested
	rootCmd.SilenceUsage = jsonRequested
	defer func() {
		rootCmd.SilenceErrors = false
		rootCmd.SilenceUsage = false
	}()

	command := commandNameForArgs(args)
	err := rootCmd.Execute()
	if err == nil {
		return 0
	}
	if isOutputError(err) {
		return 1
	}

	jsonMode := jsonOutput && isOperationalCommand(command)
	ConfigureOutput(stdout, stderr, jsonMode)
	if jsonMode {
		if emitErr := EmitTerminalError(command, err, commandVerbose(command)); emitErr != nil {
			return 1
		}
	} else {
		PrintErrorWithHint(err)
	}
	return 1
}

func requestsJSON(args []string) bool {
	requested := false
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if arg == "--json" {
			requested = true
			continue
		}
		if value, ok := strings.CutPrefix(arg, "--json="); ok {
			if parsed, err := strconv.ParseBool(value); err == nil {
				requested = parsed
			}
		}
	}
	return requested
}

// Execute runs the root command and exits with its status.
func Execute() {
	os.Exit(Run(os.Args[1:], os.Stdout, os.Stderr))
}

func commandName(cmd *cobra.Command) string {
	return strings.TrimPrefix(cmd.CommandPath(), rootCmd.Name()+" ")
}

func commandNameForArgs(args []string) string {
	cmd, _, err := rootCmd.Find(args)
	if err != nil {
		return rootCmd.Name()
	}
	return commandName(cmd)
}

func isOperationalCommand(command string) bool {
	switch command {
	case "encrypt", "decrypt", "secure-delete", "rotate-key", "watch", "schedule encrypt":
		return true
	default:
		return false
	}
}

func commandVerbose(command string) bool {
	switch command {
	case "encrypt":
		return encryptVerbose
	case "decrypt":
		return decryptVerbose
	case "secure-delete":
		return secureDeleteVerbose
	case "rotate-key":
		return rotateKeyVerbose
	case "watch":
		return watchVerbose
	case "schedule encrypt":
		return scheduleVerbose
	default:
		return false
	}
}

// GetRootCmd returns the root command (for testing)
func GetRootCmd() *cobra.Command {
	return rootCmd
}

// These functions are now in errors.go to avoid duplication
