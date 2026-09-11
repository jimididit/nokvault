package cli

import (
	"context"
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
	scheduleEncryptCmd.Flags().StringVarP(&schedulePassword, "password", "p", "", "Removed: passwords on argv are refused (use --keyfile or NOKVAULT_PASSWORD)")
	scheduleEncryptCmd.Flags().StringVarP(&scheduleKeyfile, "keyfile", "k", "", "Path to keyfile")
	scheduleEncryptCmd.Flags().BoolVar(&scheduleNoPrompt, "no-prompt", false, "Don't prompt for password")
	scheduleEncryptCmd.Flags().BoolVarP(&scheduleVerbose, "verbose", "v", false, "Verbose output")
	scheduleEncryptCmd.Flags().BoolVar(&scheduleCompress, "compress", false, "Enable compression")

	scheduleCmd.AddCommand(scheduleEncryptCmd)
	rootCmd.AddCommand(scheduleCmd)
}

func runScheduleEncrypt(cmd *cobra.Command, args []string) error {
	path := args[0]

	if err := utils.ValidateNoSymlinkComponents(path); err != nil {
		return err
	}

	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return utils.NewError(utils.ErrFileNotFound.Code, fmt.Sprintf("Path does not exist: %s", path), err)
	} else if err != nil {
		return err
	}

	outputPath, derErr := utils.DefaultVaultOutput(path)
	if derErr != nil {
		return utils.NewError(utils.ErrInvalidPath.Code, derErr.Error(), derErr)
	}
	if err := utils.ValidateNoSymlinkComponents(outputPath); err != nil {
		return err
	}
	if info.IsDir() {
		if err := preflightDirectoryEncryptOutputs(path, outputPath); err != nil {
			return err
		}
	}

	// Get password/key
	password, err := utils.GetPassword(schedulePassword, scheduleKeyfile, scheduleNoPrompt || JSONEnabled(), false)
	if err != nil {
		return utils.NewError(utils.ErrInvalidPassword.Code, "Failed to get schedule password", err)
	}
	defer utils.ZeroizePassword(password)

	// Create encryption service
	encryptionService := core.NewEncryptionService()
	keyManager := encryptionService.GetKeyManager()
	if err := applyKDFConfig(keyManager); err != nil {
		return fmt.Errorf("invalid key derivation configuration: %w", err)
	}

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
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := EmitEvent("schedule encrypt", "schedule.started", EventData{
		Path: path, TargetKind: targetKind(info), Interval: scheduleInterval.String(),
	}); err != nil {
		return err
	}

	// Schedule periodic encryption
	ticker := time.NewTicker(scheduleInterval)
	defer ticker.Stop()

	run := func() (EncryptResult, error) {
		return performScheduledEncryptResult(path, encryptionService, key, salt)
	}
	return runScheduleLoop(ctx, path, ticker.C, run)
}

func runScheduleLoop(
	ctx context.Context,
	path string,
	ticks <-chan time.Time,
	run func() (EncryptResult, error),
) error {
	if err := runScheduleTick(path, run, false); err != nil {
		return err
	}
	for {
		select {
		case _, ok := <-ticks:
			if !ok {
				return nil
			}
			if err := runScheduleTick(path, run, true); err != nil {
				return err
			}
		case <-ctx.Done():
			PrintInfo("\nStopping scheduled encryption...")
			return EmitEvent("schedule encrypt", "schedule.stopped", EventData{Path: path})
		}
	}
}

func runScheduleTick(path string, run func() (EncryptResult, error), announceHuman bool) error {
	if err := EmitEvent("schedule encrypt", "schedule.tick.started", EventData{Path: path}); err != nil {
		return err
	}
	result, err := run()
	if err != nil {
		if JSONEnabled() {
			return EmitEvent("schedule encrypt", "operation.failed", EventData{
				Path: path, Processed: result.Processed, Succeeded: result.Succeeded,
				Failed: result.Failed, Error: errorBody(err, scheduleVerbose),
			})
		}
		logScheduleEncryptError(err)
		return nil
	}
	if JSONEnabled() {
		return EmitEvent("schedule encrypt", "schedule.tick.completed", EventData{
			Path: path, Output: result.Output, Processed: result.Processed,
			Succeeded: result.Succeeded, Failed: result.Failed,
		})
	}
	if announceHuman {
		PrintSuccess(fmt.Sprintf("Scheduled encryption completed: %s", path))
	}
	return nil
}

func performScheduledEncrypt(path string, encryptionService *core.EncryptionService, key, salt []byte) error {
	_, err := performScheduledEncryptResult(path, encryptionService, key, salt)
	return err
}

func performScheduledEncryptResult(path string, encryptionService *core.EncryptionService, key, salt []byte) (EncryptResult, error) {
	result := EncryptResult{
		Input: path, Compression: scheduleCompress,
	}
	if err := utils.ValidateNoSymlinkComponents(path); err != nil {
		return result, err
	}

	info, err := os.Lstat(path)
	if err != nil {
		return result, err
	}
	result.TargetKind = targetKind(info)

	outputPath, derErr := utils.DefaultVaultOutput(path)
	if derErr != nil {
		return result, derErr
	}
	result.Output = outputPath
	if err := utils.ValidateNoSymlinkComponents(outputPath); err != nil {
		return result, err
	}

	if info.IsDir() {
		if err := preflightDirectoryEncryptOutputs(path, outputPath); err != nil {
			return result, err
		}
		totalFiles, err := core.NewFileHandler().CountFiles(path)
		if err != nil {
			return result, err
		}
		result.Processed = totalFiles
		encryptor := core.NewDirectoryEncryptor(encryptionService, scheduleVerbose)
		encryptor.SetCompression(scheduleCompress)
		if err := encryptor.EncryptDirectory(path, outputPath, key, salt, nil); err != nil {
			result.Failed = totalFiles
			return result, err
		}
		result.Succeeded = totalFiles
		return result, nil
	}

	return encryptFileWithCompression(path, outputPath, key, salt, encryptionService, scheduleCompress)
}
