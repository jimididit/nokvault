package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jimididit/nokvault/internal/core"
	"github.com/jimididit/nokvault/internal/utils"
	"github.com/spf13/cobra"
)

var scheduleCmd = &cobra.Command{
	Use:   "schedule",
	Short: "Schedule encryption operations",
	Long: `Schedule periodic encryption operations.

This command helps set up scheduled encryption tasks. For production use,
consider using system schedulers like cron (Linux/macOS) or Task Scheduler (Windows).`,
}

var (
	scheduleEncryptCmd = &cobra.Command{
		Use:   "encrypt <path>",
		Short: "Schedule periodic encryption of a path",
		Long: `Schedule periodic encryption of a file or directory.

Example: Encrypt a directory every hour
  nokvault schedule encrypt ./documents --interval 1h`,
		Args: cobra.ExactArgs(1),
		RunE: runScheduleEncrypt,
	}

	scheduleInterval time.Duration
	schedulePassword string
	scheduleKeyfile  string
	scheduleNoPrompt bool
	scheduleVerbose  bool
	scheduleCompress bool
)

func init() {
	scheduleEncryptCmd.Flags().DurationVarP(&scheduleInterval, "interval", "i", time.Hour, "Interval between encryption operations")
	scheduleEncryptCmd.Flags().StringVarP(&schedulePassword, "password", "p", "", "Encryption password")
	scheduleEncryptCmd.Flags().StringVarP(&scheduleKeyfile, "keyfile", "k", "", "Path to keyfile")
	scheduleEncryptCmd.Flags().BoolVar(&scheduleNoPrompt, "no-prompt", false, "Don't prompt for password")
	scheduleEncryptCmd.Flags().BoolVarP(&scheduleVerbose, "verbose", "v", false, "Verbose output")
	scheduleEncryptCmd.Flags().BoolVar(&scheduleCompress, "compress", false, "Enable compression")

	scheduleCmd.AddCommand(scheduleEncryptCmd)
	rootCmd.AddCommand(scheduleCmd)
}

func runScheduleEncrypt(cmd *cobra.Command, args []string) error {
	path := args[0]

	// Validate path
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return utils.NewError(utils.ErrFileNotFound.Code, fmt.Sprintf("Path does not exist: %s", path), err)
	}

	// Get password/key
	password, err := utils.GetPassword(schedulePassword, scheduleKeyfile, scheduleNoPrompt, false)
	if err != nil {
		return fmt.Errorf("failed to get password: %w", err)
	}
	defer utils.ZeroizePassword(password)

	// Create encryption service
	encryptionService := core.NewEncryptionService()
	keyManager := encryptionService.GetKeyManager()

	// Derive key
	key, salt, err := keyManager.DeriveKeyFromPassword(password)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}
	defer utils.ZeroizeKey(key)

	PrintInfo(fmt.Sprintf("Scheduling encryption of: %s", path))
	PrintInfo(fmt.Sprintf("Interval: %v", scheduleInterval))
	PrintInfo("Press Ctrl+C to stop...")

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Run initial encryption
	if err := performScheduledEncrypt(path, encryptionService, key, salt); err != nil {
		if scheduleVerbose {
			PrintError(fmt.Sprintf("Initial encryption failed: %v", err))
		}
	}

	// Schedule periodic encryption
	ticker := time.NewTicker(scheduleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := performScheduledEncrypt(path, encryptionService, key, salt); err != nil {
				if scheduleVerbose {
					PrintError(fmt.Sprintf("Scheduled encryption failed: %v", err))
				}
			} else {
				PrintSuccess(fmt.Sprintf("Scheduled encryption completed: %s", path))
			}
		case <-sigChan:
			PrintInfo("\nStopping scheduled encryption...")
			return nil
		}
	}
}

func performScheduledEncrypt(path string, encryptionService *core.EncryptionService, key, salt []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.IsDir() {
		// Encrypt directory
		outputPath := path + ".nokvault"
		encryptor := core.NewDirectoryEncryptor(encryptionService, scheduleVerbose)
		encryptor.SetCompression(scheduleCompress)
		return encryptor.EncryptDirectory(path, outputPath, key, salt, nil)
	}

	// Encrypt file
	outputPath := path + ".nokvault"
	return encryptFileWithCompression(path, outputPath, key, salt, encryptionService, scheduleCompress)
}
