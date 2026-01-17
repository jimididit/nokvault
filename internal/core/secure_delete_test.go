package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecureDeleteService_Delete(t *testing.T) {
	sds := NewSecureDeleteService(3)

	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "nokvault-test-delete-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	testData := []byte("test content for secure deletion")
	if _, err := tmpFile.Write(testData); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}
	tmpFile.Close()

	filePath := tmpFile.Name()

	// Verify file exists
	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("File should exist before deletion: %v", err)
	}

	// Securely delete file
	if err := sds.Delete(filePath); err != nil {
		t.Fatalf("Secure delete failed: %v", err)
	}

	// Verify file is deleted
	if _, err := os.Stat(filePath); err == nil {
		t.Error("File should be deleted after secure delete")
	} else if !os.IsNotExist(err) {
		t.Errorf("Unexpected error checking file: %v", err)
	}
}

func TestSecureDeleteService_Delete_EmptyFile(t *testing.T) {
	sds := NewSecureDeleteService(3)

	// Create an empty temporary file
	tmpFile, err := os.CreateTemp("", "nokvault-test-empty-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()

	filePath := tmpFile.Name()

	// Securely delete empty file
	if err := sds.Delete(filePath); err != nil {
		t.Fatalf("Secure delete of empty file failed: %v", err)
	}

	// Verify file is deleted
	if _, err := os.Stat(filePath); err == nil {
		t.Error("File should be deleted after secure delete")
	} else if !os.IsNotExist(err) {
		t.Errorf("Unexpected error checking file: %v", err)
	}
}

func TestSecureDeleteService_Delete_NonExistentFile(t *testing.T) {
	sds := NewSecureDeleteService(3)

	nonExistentPath := filepath.Join(os.TempDir(), "nokvault-nonexistent-12345.txt")

	err := sds.Delete(nonExistentPath)
	if err == nil {
		t.Error("Expected error when deleting non-existent file")
	}
}

func TestSecureDeleteService_DefaultPasses(t *testing.T) {
	// Test with zero passes (should default to 3)
	sds := NewSecureDeleteService(0)

	if sds.passes != 3 {
		t.Errorf("Expected default 3 passes, got %d", sds.passes)
	}
}

func TestSecureDeleteService_CustomPasses(t *testing.T) {
	passes := 5
	sds := NewSecureDeleteService(passes)

	if sds.passes != passes {
		t.Errorf("Expected %d passes, got %d", passes, sds.passes)
	}
}

func TestSecureDeleteService_OverwritePasses(t *testing.T) {
	sds := NewSecureDeleteService(3)

	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "nokvault-test-passes-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	testData := make([]byte, 1024) // 1KB file
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	if _, err := tmpFile.Write(testData); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}
	tmpFile.Close()

	filePath := tmpFile.Name()

	// Securely delete file
	if err := sds.Delete(filePath); err != nil {
		t.Fatalf("Secure delete failed: %v", err)
	}

	// Verify file is deleted
	if _, err := os.Stat(filePath); err == nil {
		t.Error("File should be deleted after secure delete")
	} else if !os.IsNotExist(err) {
		t.Errorf("Unexpected error checking file: %v", err)
	}
}
