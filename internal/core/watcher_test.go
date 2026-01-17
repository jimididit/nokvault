package core

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func TestFileWatcher_AddPath_File(t *testing.T) {
	fw, err := NewFileWatcher()
	if err != nil {
		t.Fatalf("Failed to create file watcher: %v", err)
	}
	defer fw.Stop()

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "nokvault-watcher-test-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Add file to watcher
	if err := fw.AddPath(tmpFile.Name()); err != nil {
		t.Fatalf("Failed to add file path: %v", err)
	}
}

func TestFileWatcher_AddPath_Directory(t *testing.T) {
	fw, err := NewFileWatcher()
	if err != nil {
		t.Fatalf("Failed to create file watcher: %v", err)
	}
	defer fw.Stop()

	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "nokvault-watcher-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Add directory to watcher
	if err := fw.AddPath(tmpDir); err != nil {
		t.Fatalf("Failed to add directory path: %v", err)
	}
}

func TestFileWatcher_OnEvent(t *testing.T) {
	fw, err := NewFileWatcher()
	if err != nil {
		t.Fatalf("Failed to create file watcher: %v", err)
	}
	defer fw.Stop()

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "nokvault-watcher-event-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Add file to watcher
	if err := fw.AddPath(tmpFile.Name()); err != nil {
		t.Fatalf("Failed to add file path: %v", err)
	}

	// Register callback
	var callbackCalled bool
	var callbackPath string
	var callbackMutex sync.Mutex

	fw.OnEvent(tmpFile.Name(), func(path string, event fsnotify.Event) {
		callbackMutex.Lock()
		defer callbackMutex.Unlock()
		callbackCalled = true
		callbackPath = path
		_ = event // Event is received but not used in this test
	})

	// Start watcher
	if err := fw.Start(); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}

	// Wait a bit for watcher to be ready
	time.Sleep(100 * time.Millisecond)

	// Modify file to trigger event
	if err := os.WriteFile(tmpFile.Name(), []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to write to file: %v", err)
	}

	// Wait for event (with timeout)
	timeout := time.After(2 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for file event")
		case <-ticker.C:
			callbackMutex.Lock()
			called := callbackCalled
			callbackMutex.Unlock()
			if called {
				// Verify callback was called with correct path
				callbackMutex.Lock()
				if callbackPath != tmpFile.Name() {
					t.Errorf("Callback called with wrong path. Expected %s, got %s",
						tmpFile.Name(), callbackPath)
				}
				callbackMutex.Unlock()
				return
			}
		}
	}
}

func TestFileWatcher_Start_Stop(t *testing.T) {
	fw, err := NewFileWatcher()
	if err != nil {
		t.Fatalf("Failed to create file watcher: %v", err)
	}

	// Start watcher
	if err := fw.Start(); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}

	// Try to start again (should fail)
	if err := fw.Start(); err == nil {
		t.Error("Expected error when starting watcher twice")
	}

	// Stop watcher
	if err := fw.Stop(); err != nil {
		t.Fatalf("Failed to stop watcher: %v", err)
	}

	// Stop again (should succeed)
	if err := fw.Stop(); err != nil {
		t.Errorf("Stopping stopped watcher should succeed: %v", err)
	}
}

func TestFileWatcher_AddPath_NonExistent(t *testing.T) {
	fw, err := NewFileWatcher()
	if err != nil {
		t.Fatalf("Failed to create file watcher: %v", err)
	}
	defer fw.Stop()

	nonExistentPath := filepath.Join(os.TempDir(), "nokvault-nonexistent-12345.txt")

	err = fw.AddPath(nonExistentPath)
	if err == nil {
		t.Error("Expected error when adding non-existent path")
	}
}

func TestFileWatcher_DirectoryEvents(t *testing.T) {
	fw, err := NewFileWatcher()
	if err != nil {
		t.Fatalf("Failed to create file watcher: %v", err)
	}
	defer fw.Stop()

	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "nokvault-watcher-dir-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Add directory to watcher
	if err := fw.AddPath(tmpDir); err != nil {
		t.Fatalf("Failed to add directory path: %v", err)
	}

	// Register callback for directory
	var eventsReceived []fsnotify.Event
	var eventsMutex sync.Mutex

	fw.OnEvent(tmpDir, func(path string, event fsnotify.Event) {
		eventsMutex.Lock()
		defer eventsMutex.Unlock()
		eventsReceived = append(eventsReceived, event)
	})

	// Start watcher
	if err := fw.Start(); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}

	// Wait for watcher to be ready
	time.Sleep(100 * time.Millisecond)

	// Create a new file in the directory
	newFile := filepath.Join(tmpDir, "newfile.txt")
	if err := os.WriteFile(newFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	defer os.Remove(newFile)

	// Wait for event
	timeout := time.After(2 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for directory event")
		case <-ticker.C:
			eventsMutex.Lock()
			received := len(eventsReceived) > 0
			eventsMutex.Unlock()
			if received {
				return
			}
		}
	}
}

func TestDefaultWatchConfig(t *testing.T) {
	path := "/test/path"
	config := DefaultWatchConfig(path)

	if config.Path != path {
		t.Errorf("Expected path %s, got %s", path, config.Path)
	}

	if config.AutoEncrypt {
		t.Error("AutoEncrypt should be false by default")
	}

	if config.EncryptDelay != 2*time.Second {
		t.Errorf("Expected default delay 2s, got %v", config.EncryptDelay)
	}

	if !config.Recursive {
		t.Error("Recursive should be true by default")
	}
}
