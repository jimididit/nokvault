package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

// AtomicWrite writes data to filePath via a temporary file in the same
// directory, fsyncs, closes, then renames into place (NV-006).
func AtomicWrite(filePath string, data []byte, perm os.FileMode) error {
	return AtomicWriteFunc(filePath, perm, func(f *os.File) error {
		_, err := f.Write(data)
		return err
	})
}

// AtomicWriteFunc creates a temp file next to filePath, runs write, syncs,
// closes, then renames over filePath. The write callback must not Close f.
func AtomicWriteFunc(filePath string, perm os.FileMode, write func(f *os.File) error) error {
	dir := filepath.Dir(filePath)
	if dir == "" || dir == "." {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".nokvault-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpName := tmp.Name()

	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if err := tmp.Chmod(perm); err != nil {
		// Best-effort on platforms that ignore chmod; continue.
		_ = err
	}

	if err := write(tmp); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("failed to sync temp file: %w", err)
	}
	// Close before rename — required on Windows when replacing.
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tmpName, filePath); err != nil {
		// Windows may refuse rename-over-existing; remove destination and retry.
		_ = os.Remove(filePath)
		if err2 := os.Rename(tmpName, filePath); err2 != nil {
			_ = os.Remove(tmpName)
			return fmt.Errorf("failed to replace target file: %w", err2)
		}
	}
	return nil
}

// SafeWrite is retained as an alias for AtomicWrite with mode 0600.
func SafeWrite(filePath string, data []byte) error {
	return AtomicWrite(filePath, data, 0o600)
}
