package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

// RecoveryHandler handles error recovery operations
type RecoveryHandler struct {
	backupDir string
}

// NewRecoveryHandler creates a new recovery handler
func NewRecoveryHandler() *RecoveryHandler {
	return &RecoveryHandler{
		backupDir: ".nokvault-backup",
	}
}

// CreateBackup creates a backup of a file before encryption
func (rh *RecoveryHandler) CreateBackup(filePath string) (string, error) {
	// Ensure backup directory exists
	if err := os.MkdirAll(rh.backupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create backup path
	backupPath := filepath.Join(rh.backupDir, filepath.Base(filePath)+".backup")

	// Copy file to backup
	sourceFile, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	backupFile, err := os.Create(backupPath)
	if err != nil {
		return "", fmt.Errorf("failed to create backup file: %w", err)
	}
	defer backupFile.Close()

	// Copy file contents
	if _, err := backupFile.ReadFrom(sourceFile); err != nil {
		return "", fmt.Errorf("failed to copy file: %w", err)
	}

	return backupPath, nil
}

// RestoreFromBackup restores a file from backup
func (rh *RecoveryHandler) RestoreFromBackup(backupPath, targetPath string) error {
	backupFile, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer backupFile.Close()

	targetFile, err := os.Create(targetPath)
	if err != nil {
		return fmt.Errorf("failed to create target file: %w", err)
	}
	defer targetFile.Close()

	if _, err := targetFile.ReadFrom(backupFile); err != nil {
		return fmt.Errorf("failed to restore file: %w", err)
	}

	return nil
}

// CleanupBackups removes backup files
func (rh *RecoveryHandler) CleanupBackups() error {
	return os.RemoveAll(rh.backupDir)
}

// VerifyFileIntegrity checks if a file exists and is readable
func VerifyFileIntegrity(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("file does not exist or is not accessible: %w", err)
	}

	if info.Size() == 0 {
		return fmt.Errorf("file is empty")
	}

	// Try to read first byte to verify readability
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("file is not readable: %w", err)
	}
	defer file.Close()

	buf := make([]byte, 1)
	if _, err := file.Read(buf); err != nil {
		return fmt.Errorf("file read test failed: %w", err)
	}

	return nil
}

// SafeWrite writes data to a file with atomic write (write to temp, then rename)
func SafeWrite(filePath string, data []byte) error {
	// Create temporary file in same directory
	tempPath := filePath + ".tmp"

	// Write to temp file
	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, filePath); err != nil {
		// Cleanup temp file on error
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}
