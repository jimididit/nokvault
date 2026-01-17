package core

import (
	"crypto/rand"
	"fmt"
	"os"
)

// SecureDeleteService handles secure file deletion
type SecureDeleteService struct {
	passes int
}

// NewSecureDeleteService creates a new secure delete service
func NewSecureDeleteService(passes int) *SecureDeleteService {
	if passes < 1 {
		passes = 3 // Default to 3 passes
	}
	return &SecureDeleteService{
		passes: passes,
	}
}

// Delete securely deletes a file by overwriting it multiple times
func (sds *SecureDeleteService) Delete(filePath string) error {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Get file size
	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	fileSize := stat.Size()

	if fileSize == 0 {
		// Empty file, just delete it
		file.Close()
		return os.Remove(filePath)
	}

	// Perform multiple overwrite passes
	for pass := 0; pass < sds.passes; pass++ {
		if err := sds.overwritePass(file, fileSize, pass); err != nil {
			return fmt.Errorf("overwrite pass %d failed: %w", pass+1, err)
		}
	}

	// Close file before deletion
	file.Close()

	// Delete the file
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	return nil
}

// overwritePass performs a single overwrite pass
func (sds *SecureDeleteService) overwritePass(file *os.File, size int64, pass int) error {
	// Seek to beginning
	if _, err := file.Seek(0, 0); err != nil {
		return err
	}

	// Different patterns for different passes
	var pattern []byte
	switch pass % 3 {
	case 0:
		// Random data
		pattern = make([]byte, size)
		if _, err := rand.Read(pattern); err != nil {
			return fmt.Errorf("failed to generate random data: %w", err)
		}
	case 1:
		// All zeros
		pattern = make([]byte, size)
	case 2:
		// All ones (0xFF)
		pattern = make([]byte, size)
		for i := range pattern {
			pattern[i] = 0xFF
		}
	}

	// Write pattern
	if _, err := file.Write(pattern); err != nil {
		return err
	}

	// Sync to disk
	if err := file.Sync(); err != nil {
		return err
	}

	return nil
}
