package core

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileWatcher_AddPath_File(t *testing.T) {
	fw, err := NewFileWatcher()
	require.NoError(t, err, "Failed to create file watcher")
	defer fw.Stop()

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "nokvault-watcher-test-*.txt")
	require.NoError(t, err, "Failed to create temp file")
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Add file to watcher
	err = fw.AddPath(tmpFile.Name())
	require.NoError(t, err, "Failed to add file path")
}

func TestFileWatcher_AddPath_Directory(t *testing.T) {
	fw, err := NewFileWatcher()
	require.NoError(t, err, "Failed to create file watcher")
	defer fw.Stop()

	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "nokvault-watcher-test-*")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tmpDir)

	// Add directory to watcher
	err = fw.AddPath(tmpDir)
	require.NoError(t, err, "Failed to add directory path")
}

func TestFileWatcher_OnEvent(t *testing.T) {
	fw, err := NewFileWatcher()
	require.NoError(t, err, "Failed to create file watcher")
	defer fw.Stop()

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "nokvault-watcher-event-*.txt")
	require.NoError(t, err, "Failed to create temp file")
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Add file to watcher
	err = fw.AddPath(tmpFile.Name())
	require.NoError(t, err, "Failed to add file path")

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
	err = fw.Start()
	require.NoError(t, err, "Failed to start watcher")

	// Wait a bit for watcher to be ready
	time.Sleep(100 * time.Millisecond)

	// Modify file to trigger event
	err = os.WriteFile(tmpFile.Name(), []byte("test content"), 0644)
	require.NoError(t, err, "Failed to write to file")

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
				assert.Equal(t, tmpFile.Name(), callbackPath, "Callback should be called with correct path")
				callbackMutex.Unlock()
				return
			}
		}
	}
}

func TestFileWatcher_Start_Stop(t *testing.T) {
	fw, err := NewFileWatcher()
	require.NoError(t, err, "Failed to create file watcher")

	// Start watcher
	err = fw.Start()
	require.NoError(t, err, "Failed to start watcher")

	// Try to start again (should fail)
	err = fw.Start()
	assert.Error(t, err, "Expected error when starting watcher twice")

	// Stop watcher
	err = fw.Stop()
	require.NoError(t, err, "Failed to stop watcher")

	// Stop again (should succeed)
	err = fw.Stop()
	assert.NoError(t, err, "Stopping stopped watcher should succeed")
}

func TestFileWatcher_AddPath_NonExistent(t *testing.T) {
	fw, err := NewFileWatcher()
	require.NoError(t, err, "Failed to create file watcher")
	defer fw.Stop()

	nonExistentPath := filepath.Join(os.TempDir(), "nokvault-nonexistent-12345.txt")

	err = fw.AddPath(nonExistentPath)
	assert.Error(t, err, "Expected error when adding non-existent path")
}

func TestFileWatcher_DirectoryEvents(t *testing.T) {
	fw, err := NewFileWatcher()
	require.NoError(t, err, "Failed to create file watcher")
	defer fw.Stop()

	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "nokvault-watcher-dir-*")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tmpDir)

	// Add directory to watcher
	err = fw.AddPath(tmpDir)
	require.NoError(t, err, "Failed to add directory path")

	// Register callback for directory
	var eventsReceived []fsnotify.Event
	var eventsMutex sync.Mutex

	fw.OnEvent(tmpDir, func(path string, event fsnotify.Event) {
		eventsMutex.Lock()
		defer eventsMutex.Unlock()
		eventsReceived = append(eventsReceived, event)
	})

	// Start watcher
	err = fw.Start()
	require.NoError(t, err, "Failed to start watcher")

	// Wait for watcher to be ready
	time.Sleep(100 * time.Millisecond)

	// Create a new file in the directory
	newFile := filepath.Join(tmpDir, "newfile.txt")
	err = os.WriteFile(newFile, []byte("test"), 0644)
	require.NoError(t, err, "Failed to create file")
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

	assert.Equal(t, path, config.Path, "Path should match")
	assert.False(t, config.AutoEncrypt, "AutoEncrypt should be false by default")
	assert.Equal(t, 2*time.Second, config.EncryptDelay, "Expected default delay 2s")
	assert.True(t, config.Recursive, "Recursive should be true by default")
}
