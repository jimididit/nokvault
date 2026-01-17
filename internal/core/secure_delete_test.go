package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureDeleteService_Delete(t *testing.T) {
	sds := NewSecureDeleteService(3)

	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "nokvault-test-delete-*.txt")
	require.NoError(t, err, "Failed to create temp file")

	testData := []byte("test content for secure deletion")
	_, err = tmpFile.Write(testData)
	require.NoError(t, err, "Failed to write test data")
	tmpFile.Close()

	filePath := tmpFile.Name()

	// Verify file exists
	_, err = os.Stat(filePath)
	require.NoError(t, err, "File should exist before deletion")

	// Securely delete file
	err = sds.Delete(filePath)
	require.NoError(t, err, "Secure delete should succeed")

	// Verify file is deleted
	_, err = os.Stat(filePath)
	assert.True(t, os.IsNotExist(err), "File should be deleted after secure delete")
}

func TestSecureDeleteService_Delete_EmptyFile(t *testing.T) {
	sds := NewSecureDeleteService(3)

	// Create an empty temporary file
	tmpFile, err := os.CreateTemp("", "nokvault-test-empty-*.txt")
	require.NoError(t, err, "Failed to create temp file")
	tmpFile.Close()

	filePath := tmpFile.Name()

	// Securely delete empty file
	err = sds.Delete(filePath)
	require.NoError(t, err, "Secure delete of empty file should succeed")

	// Verify file is deleted
	_, err = os.Stat(filePath)
	assert.True(t, os.IsNotExist(err), "File should be deleted after secure delete")
}

func TestSecureDeleteService_Delete_NonExistentFile(t *testing.T) {
	sds := NewSecureDeleteService(3)

	nonExistentPath := filepath.Join(os.TempDir(), "nokvault-nonexistent-12345.txt")

	err := sds.Delete(nonExistentPath)
	assert.Error(t, err, "Expected error when deleting non-existent file")
}

func TestSecureDeleteService_DefaultPasses(t *testing.T) {
	// Test with zero passes (should default to 3)
	sds := NewSecureDeleteService(0)

	assert.Equal(t, 3, sds.passes, "Expected default 3 passes")
}

func TestSecureDeleteService_CustomPasses(t *testing.T) {
	passes := 5
	sds := NewSecureDeleteService(passes)

	assert.Equal(t, passes, sds.passes, "Passes should match expected")
}

func TestSecureDeleteService_OverwritePasses(t *testing.T) {
	sds := NewSecureDeleteService(3)

	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "nokvault-test-passes-*.txt")
	require.NoError(t, err, "Failed to create temp file")

	testData := make([]byte, 1024) // 1KB file
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	_, err = tmpFile.Write(testData)
	require.NoError(t, err, "Failed to write test data")
	tmpFile.Close()

	filePath := tmpFile.Name()

	// Securely delete file
	err = sds.Delete(filePath)
	require.NoError(t, err, "Secure delete should succeed")

	// Verify file is deleted
	_, err = os.Stat(filePath)
	assert.True(t, os.IsNotExist(err), "File should be deleted after secure delete")
}
