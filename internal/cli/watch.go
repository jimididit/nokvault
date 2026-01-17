package cli

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/jimididit/nokvault/internal/core"
	"github.com/jimididit/nokvault/internal/utils"
	"github.com/spf13/cobra"
)

var watchCmd = &cobra.Command{
	Use:   "watch <path>",
	Short: "Watch a directory for file changes and optionally auto-encrypt",
	Long: `Watch a directory or file for changes and optionally automatically encrypt
new or modified files.

This is useful for automatically protecting files as they are created or modified.
The watcher will monitor the specified path and trigger encryption based on the
configured options.`,
	Args: cobra.ExactArgs(1),
	RunE: runWatch,
}

var (
	watchAutoEncrypt bool
	watchDelay       time.Duration
	watchExclude     []string
	watchRecursive   bool
	watchVerbose     bool
	watchPassword    string
	watchKeyfile     string
	watchNoPrompt    bool
)

func init() {
	watchCmd.Flags().BoolVar(&watchAutoEncrypt, "auto-encrypt", false, "Automatically encrypt files when they change")
	watchCmd.Flags().DurationVar(&watchDelay, "delay", 2*time.Second, "Delay before encrypting after file change")
	watchCmd.Flags().StringSliceVar(&watchExclude, "exclude", []string{}, "Patterns to exclude (e.g., '*.tmp')")
	watchCmd.Flags().BoolVar(&watchRecursive, "recursive", true, "Watch subdirectories recursively")
	watchCmd.Flags().BoolVarP(&watchVerbose, "verbose", "v", false, "Verbose output")
	watchCmd.Flags().StringVarP(&watchPassword, "password", "p", "", "Encryption password")
	watchCmd.Flags().StringVarP(&watchKeyfile, "keyfile", "k", "", "Path to keyfile")
	watchCmd.Flags().BoolVar(&watchNoPrompt, "no-prompt", false, "Don't prompt for password")

	rootCmd.AddCommand(watchCmd)
}

func runWatch(cmd *cobra.Command, args []string) error {
	watchPath := args[0]

	// Validate path
	info, err := os.Stat(watchPath)
	if os.IsNotExist(err) {
		return utils.NewError(utils.ErrFileNotFound.Code, fmt.Sprintf("Path does not exist: %s", watchPath), err)
	}

	// Create watcher
	watcher, err := core.NewFileWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	defer watcher.Stop()

	// Add path to watch
	if err := watcher.AddPath(watchPath); err != nil {
		return fmt.Errorf("failed to add path to watcher: %w", err)
	}

	PrintInfo(fmt.Sprintf("Watching: %s", watchPath))
	if watchAutoEncrypt {
		PrintInfo("Auto-encrypt enabled")
		if watchVerbose {
			PrintInfo(fmt.Sprintf("Encrypt delay: %v", watchDelay))
		}
	}

	// Setup auto-encrypt if enabled
	if watchAutoEncrypt {
		encryptionService := core.NewEncryptionService()
		keyManager := encryptionService.GetKeyManager()

		// Get password/key
		password, err := utils.GetPassword(watchPassword, watchKeyfile, watchNoPrompt, false)
		if err != nil {
			return fmt.Errorf("failed to get password: %w", err)
		}
		defer utils.ZeroizePassword(password)

		// Derive key (we'll use the same key for all files)
		key, salt, err := keyManager.DeriveKeyFromPassword(password)
		if err != nil {
			return fmt.Errorf("failed to derive key: %w", err)
		}
		defer utils.ZeroizeKey(key)

		// Setup encryption callback
		encryptCallback := createEncryptCallback(encryptionService, key, salt, watchDelay, watchExclude, watchVerbose)

		if info.IsDir() {
			watcher.OnEvent(watchPath, encryptCallback)
		} else {
			watcher.OnEvent(watchPath, encryptCallback)
		}
	}

	// Start watching
	if err := watcher.Start(); err != nil {
		return fmt.Errorf("failed to start watcher: %w", err)
	}

	PrintInfo("Press Ctrl+C to stop watching...")

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Wait for interrupt
	<-sigChan
	PrintInfo("\nStopping watcher...")

	return nil
}

// createEncryptCallback creates a callback function for auto-encryption
func createEncryptCallback(
	encryptionService *core.EncryptionService,
	key, salt []byte,
	delay time.Duration,
	excludePatterns []string,
	verbose bool,
) func(string, fsnotify.Event) {
	// Map to track pending encryptions (to debounce rapid changes)
	pendingEncryptions := make(map[string]*time.Timer)
	var mu sync.Mutex

	return func(filePath string, fsEvent fsnotify.Event) {

		// Only process write/create events
		if fsEvent.Op&fsnotify.Write == 0 && fsEvent.Op&fsnotify.Create == 0 {
			return
		}

		// Check if file should be excluded
		for _, pattern := range excludePatterns {
			matched, err := filepath.Match(pattern, filepath.Base(filePath))
			if err == nil && matched {
				if verbose {
					PrintInfo(fmt.Sprintf("Excluded: %s (matches %s)", filePath, pattern))
				}
				return
			}
		}

		// Only encrypt on write/create events
		// Note: We'll encrypt on any write event for simplicity
		shouldEncrypt := true

		if !shouldEncrypt {
			return
		}

		// Check if file exists and is not already encrypted
		info, err := os.Stat(filePath)
		if err != nil || info.IsDir() {
			return
		}

		// Skip if already encrypted
		if filepath.Ext(filePath) == ".nokvault" {
			return
		}

		// Cancel previous pending encryption for this file
		mu.Lock()
		if timer, exists := pendingEncryptions[filePath]; exists {
			timer.Stop()
		}
		mu.Unlock()

		// Schedule encryption after delay
		mu.Lock()
		timer := time.AfterFunc(delay, func() {
			mu.Lock()
			delete(pendingEncryptions, filePath)
			mu.Unlock()
			encryptFileAuto(filePath, encryptionService, key, salt, verbose)
		})

		pendingEncryptions[filePath] = timer
		mu.Unlock()

		if verbose {
			PrintInfo(fmt.Sprintf("Scheduled encryption: %s (after %v)", filePath, delay))
		}
	}
}

// encryptFileAuto encrypts a file automatically (helper for watch callback)
func encryptFileAuto(filePath string, encryptionService *core.EncryptionService, key, salt []byte, verbose bool) {
	outputPath := filePath + ".nokvault"

	fileHandler := core.NewFileHandler()
	metadata, err := fileHandler.ReadMetadata(filePath)
	if err != nil {
		if verbose {
			PrintError(fmt.Sprintf("Failed to read metadata for %s: %v", filePath, err))
		}
		return
	}

	// Read file data
	data, err := os.ReadFile(filePath)
	if err != nil {
		if verbose {
			PrintError(fmt.Sprintf("Failed to read file %s: %v", filePath, err))
		}
		return
	}

	// Encrypt data
	ciphertext, err := encryptionService.EncryptData(data, key)
	if err != nil {
		if verbose {
			PrintError(fmt.Sprintf("Encryption failed for %s: %v", filePath, err))
		}
		return
	}

	// Create output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		if verbose {
			PrintError(fmt.Sprintf("Failed to create output file %s: %v", outputPath, err))
		}
		return
	}
	defer outputFile.Close()

	// Write header with metadata
	if err := fileHandler.WriteHeader(outputFile, salt, metadata); err != nil {
		if verbose {
			PrintError(fmt.Sprintf("Failed to write header for %s: %v", outputPath, err))
		}
		return
	}

	// Write encrypted data
	if _, err := outputFile.Write(ciphertext); err != nil {
		if verbose {
			PrintError(fmt.Sprintf("Failed to write encrypted data for %s: %v", outputPath, err))
		}
		return
	}

	PrintSuccess(fmt.Sprintf("Auto-encrypted: %s -> %s", filePath, outputPath))
}
