package cli

import (
	"context"
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
	watchCmd.Flags().StringVarP(&watchPassword, "password", "p", "", "Removed: passwords on argv are refused (use --keyfile or NOKVAULT_PASSWORD)")
	watchCmd.Flags().StringVarP(&watchKeyfile, "keyfile", "k", "", "Path to keyfile")
	watchCmd.Flags().BoolVar(&watchNoPrompt, "no-prompt", false, "Don't prompt for password")

	rootCmd.AddCommand(watchCmd)
}

func runWatch(cmd *cobra.Command, args []string) error {
	watchPath := args[0]

	if err := utils.ValidateNoSymlinkComponents(watchPath); err != nil {
		return err
	}

	info, err := os.Lstat(watchPath)
	if os.IsNotExist(err) {
		return utils.NewError(utils.ErrFileNotFound.Code, fmt.Sprintf("Path does not exist: %s", watchPath), err)
	}
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	var callbackManager *watchCallbackManager

	// Setup auto-encrypt if enabled
	if watchAutoEncrypt {
		encryptionService := core.NewEncryptionService()
		keyManager := encryptionService.GetKeyManager()
		if err := applyKDFConfig(keyManager); err != nil {
			return fmt.Errorf("invalid key derivation configuration: %w", err)
		}

		// Get password/key
		password, err := utils.GetPassword(watchPassword, watchKeyfile, watchNoPrompt || JSONEnabled(), false)
		if err != nil {
			return utils.NewError(utils.ErrInvalidPassword.Code, "Failed to get watch password", err)
		}
		defer utils.ZeroizePassword(password)

		// Derive key (we'll use the same key for all files)
		key, salt, err := keyManager.DeriveKeyFromPassword(password)
		if err != nil {
			return fmt.Errorf("failed to derive key: %w", err)
		}
		defer utils.ZeroizeKey(key)

		// Setup encryption callback
		callbackManager = newWatchCallbackManager(
			ctx, stop, encryptionService, key, salt, watchDelay, watchExclude, watchVerbose,
		)
		defer callbackManager.Stop()

		if info.IsDir() {
			watcher.OnEvent(watchPath, callbackManager.Callback)
		} else {
			watcher.OnEvent(watchPath, callbackManager.Callback)
		}
	}

	// Start watching
	if err := watcher.Start(); err != nil {
		return fmt.Errorf("failed to start watcher: %w", err)
	}
	if err := EmitEvent("watch", "watch.started", EventData{
		Path: watchPath, TargetKind: targetKind(info),
	}); err != nil {
		return err
	}

	PrintInfo("Press Ctrl+C to stop watching...")

	// Wait for interrupt
	<-ctx.Done()
	if callbackManager != nil {
		callbackManager.Stop()
		if err := callbackManager.FatalError(); err != nil {
			return err
		}
	}
	PrintInfo("\nStopping watcher...")
	return EmitEvent("watch", "watch.stopped", EventData{Path: watchPath})
}

type pendingWatchEncryption struct {
	id    uint64
	timer *time.Timer
}

type watchCallbackManager struct {
	ctx             context.Context
	cancel          context.CancelFunc
	service         *core.EncryptionService
	key             []byte
	salt            []byte
	delay           time.Duration
	excludePatterns []string
	verbose         bool

	mu      sync.Mutex
	pending map[string]pendingWatchEncryption
	nextID  uint64
	closed  bool
	fatal   error
	wg      sync.WaitGroup
}

func newWatchCallbackManager(
	ctx context.Context,
	cancel context.CancelFunc,
	encryptionService *core.EncryptionService,
	key, salt []byte,
	delay time.Duration,
	excludePatterns []string,
	verbose bool,
) *watchCallbackManager {
	if cancel == nil {
		cancel = func() {}
	}
	return &watchCallbackManager{
		ctx: ctx, cancel: cancel, service: encryptionService, key: key, salt: salt,
		delay: delay, excludePatterns: excludePatterns, verbose: verbose,
		pending: make(map[string]pendingWatchEncryption),
	}
}

// createEncryptCallback retains the focused callback interface used by unit tests.
func createEncryptCallback(
	encryptionService *core.EncryptionService,
	key, salt []byte,
	delay time.Duration,
	excludePatterns []string,
	verbose bool,
) func(string, fsnotify.Event) {
	manager := newWatchCallbackManager(
		context.Background(), nil, encryptionService, key, salt, delay, excludePatterns, verbose,
	)
	return manager.Callback
}

func (m *watchCallbackManager) Callback(filePath string, fsEvent fsnotify.Event) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.wg.Add(1)
	m.mu.Unlock()
	defer m.wg.Done()

	if fsEvent.Op&fsnotify.Write == 0 && fsEvent.Op&fsnotify.Create == 0 {
		return
	}
	for _, pattern := range m.excludePatterns {
		matched, err := filepath.Match(pattern, filepath.Base(filePath))
		if err == nil && matched {
			if m.verbose {
				PrintInfo(fmt.Sprintf("Excluded: %s (matches %s)", filePath, pattern))
			}
			m.emit("file.excluded", EventData{Path: filePath, Pattern: pattern})
			return
		}
	}
	if err := utils.ValidateNoSymlinkComponents(filePath); err != nil {
		m.reportError(filePath, err)
		return
	}
	info, err := os.Lstat(filePath)
	if err != nil {
		m.reportError(filePath, err)
		return
	}
	if info.IsDir() || filepath.Ext(filePath) == ".nokvault" {
		return
	}
	if !m.emit("file.detected", EventData{Path: filePath, FilesystemOp: fsEvent.Op.String()}) {
		return
	}

	m.mu.Lock()
	if m.closed || m.ctx.Err() != nil {
		m.mu.Unlock()
		return
	}
	if old, exists := m.pending[filePath]; exists && old.timer.Stop() {
		m.wg.Done()
	}
	m.nextID++
	id := m.nextID
	m.wg.Add(1)
	timer := time.AfterFunc(m.delay, func() {
		defer m.wg.Done()
		m.runPending(filePath, id)
	})
	m.pending[filePath] = pendingWatchEncryption{id: id, timer: timer}
	m.mu.Unlock()

	if m.verbose {
		PrintInfo(fmt.Sprintf("Scheduled encryption: %s (after %v)", filePath, m.delay))
	}
	m.emit("encryption.scheduled", EventData{
		Path: filePath, Output: filePath + ".nokvault", Delay: m.delay.String(),
	})
}

func (m *watchCallbackManager) runPending(filePath string, id uint64) {
	m.mu.Lock()
	pending, current := m.pending[filePath]
	if current && pending.id == id {
		delete(m.pending, filePath)
	}
	closed := m.closed || m.ctx.Err() != nil || !current || pending.id != id
	m.mu.Unlock()
	if closed {
		return
	}

	outputPath, err := encryptFileAuto(filePath, m.service, m.key, m.salt)
	if err != nil {
		m.reportError(filePath, err)
		return
	}
	if JSONEnabled() {
		m.emit("encryption.completed", EventData{
			Path: filePath, Output: outputPath, Succeeded: 1, Processed: 1,
		})
	} else {
		PrintSuccess(fmt.Sprintf("Auto-encrypted: %s -> %s", filePath, outputPath))
	}
}

func (m *watchCallbackManager) emit(event string, data EventData) bool {
	if err := EmitEvent("watch", event, data); err != nil {
		m.fail(err)
		return false
	}
	return true
}

func (m *watchCallbackManager) reportError(path string, err error) {
	if JSONEnabled() {
		m.emit("operation.failed", EventData{
			Path: path, Error: errorBody(err, m.verbose),
		})
		return
	}
	reportWatchValidationError(err, m.verbose)
}

func (m *watchCallbackManager) fail(err error) {
	m.mu.Lock()
	if m.fatal == nil {
		m.fatal = err
		m.cancel()
	}
	m.mu.Unlock()
}

func (m *watchCallbackManager) Stop() {
	m.mu.Lock()
	m.closed = true
	for path, pending := range m.pending {
		if pending.timer.Stop() {
			m.wg.Done()
		}
		delete(m.pending, path)
	}
	m.mu.Unlock()
	m.wg.Wait()
}

func (m *watchCallbackManager) FatalError() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fatal
}

// encryptFileAuto encrypts a file automatically (helper for watch callback)
func encryptFileAuto(filePath string, encryptionService *core.EncryptionService, key, salt []byte) (string, error) {
	if err := utils.ValidateNoSymlinkComponents(filePath); err != nil {
		return "", err
	}

	outputPath := filePath + ".nokvault"
	if err := utils.ValidateNoSymlinkComponents(outputPath); err != nil {
		return "", err
	}

	fileHandler := core.NewFileHandler()
	metadata, err := fileHandler.ReadMetadata(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read metadata for %s: %w", filePath, err)
	}

	// Read file data
	// #nosec G304 -- watch validates filePath and its components before this read.
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	// Encrypt data
	ciphertext, err := encryptionService.EncryptData(data, key)
	if err != nil {
		return "", fmt.Errorf("encryption failed for %s: %w", filePath, err)
	}

	// Create output file
	if err := utils.AtomicWriteFunc(outputPath, 0o600, func(outputFile *os.File) error {
		if err := fileHandler.WriteHeader(outputFile, salt, metadata, encryptionService.GetKeyManager().Params()); err != nil {
			return err
		}
		_, err := outputFile.Write(ciphertext)
		return err
	}); err != nil {
		return "", fmt.Errorf("failed to write encrypted file %s: %w", outputPath, err)
	}

	return outputPath, nil
}

func targetKind(info os.FileInfo) string {
	if info.IsDir() {
		return "directory"
	}
	return "file"
}
