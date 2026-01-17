package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// FileWatcher watches files and directories for changes
type FileWatcher struct {
	watcher   *fsnotify.Watcher
	callbacks map[string][]func(string, fsnotify.Event)
	mu        sync.RWMutex
	running   bool
	done      chan bool
}

// NewFileWatcher creates a new file watcher
func NewFileWatcher() (*FileWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	return &FileWatcher{
		watcher:   watcher,
		callbacks: make(map[string][]func(string, fsnotify.Event)),
		done:      make(chan bool),
	}, nil
}

// AddPath adds a path to watch (file or directory)
func (fw *FileWatcher) AddPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat path: %w", err)
	}

	if info.IsDir() {
		// Watch directory and all subdirectories
		return fw.addDirectory(path)
	}

	// Watch single file
	return fw.watcher.Add(path)
}

// addDirectory recursively adds a directory and its subdirectories
func (fw *FileWatcher) addDirectory(dirPath string) error {
	if err := fw.watcher.Add(dirPath); err != nil {
		return fmt.Errorf("failed to add directory to watcher: %w", err)
	}

	// Walk directory and add subdirectories
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return fw.watcher.Add(path)
		}
		return nil
	})
}

// OnEvent registers a callback for file events
// Callback receives (filePath string, event fsnotify.Event)
func (fw *FileWatcher) OnEvent(path string, callback func(string, fsnotify.Event)) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	fw.callbacks[path] = append(fw.callbacks[path], callback)
}

// Start starts watching for file changes
func (fw *FileWatcher) Start() error {
	if fw.running {
		return fmt.Errorf("watcher is already running")
	}

	fw.running = true

	go fw.watchLoop()

	return nil
}

// Stop stops watching for file changes
func (fw *FileWatcher) Stop() error {
	if !fw.running {
		return nil
	}

	fw.running = false
	close(fw.done)

	return fw.watcher.Close()
}

// watchLoop processes file system events
func (fw *FileWatcher) watchLoop() {
	for {
		select {
		case event, ok := <-fw.watcher.Events:
			if !ok {
				return
			}
			fw.handleEvent(event)
		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return
			}
			fmt.Fprintf(os.Stderr, "Watcher error: %v\n", err)
		case <-fw.done:
			return
		}
	}
}

// handleEvent processes a file system event
func (fw *FileWatcher) handleEvent(event fsnotify.Event) {
	fw.mu.RLock()
	callbacks := fw.callbacks[event.Name]
	fw.mu.RUnlock()

	// Also check for directory-level callbacks
	dir := filepath.Dir(event.Name)
	fw.mu.RLock()
	dirCallbacks := fw.callbacks[dir]
	fw.mu.RUnlock()

	allCallbacks := append(callbacks, dirCallbacks...)

	for _, callback := range allCallbacks {
		callback(event.Name, event)
	}
}

// WatchConfig holds configuration for file watching
type WatchConfig struct {
	Path            string
	AutoEncrypt     bool
	EncryptDelay    time.Duration // Delay before encrypting after file change
	ExcludePatterns []string      // Patterns to exclude
	Recursive       bool
	Verbose         bool
}

// DefaultWatchConfig returns default watch configuration
func DefaultWatchConfig(path string) *WatchConfig {
	return &WatchConfig{
		Path:         path,
		AutoEncrypt:  false,
		EncryptDelay: 2 * time.Second,
		Recursive:    true,
		Verbose:      false,
	}
}
