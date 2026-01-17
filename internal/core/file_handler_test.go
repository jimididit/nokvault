package core

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileHandler_ReadMetadata(t *testing.T) {
	fh := NewFileHandler()

	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "nokvault-test-*.txt")
	require.NoError(t, err, "Failed to create temp file")
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	testData := []byte("test content")
	_, err = tmpFile.Write(testData)
	require.NoError(t, err, "Failed to write test data")
	tmpFile.Close()

	// Read metadata
	metadata, err := fh.ReadMetadata(tmpFile.Name())
	require.NoError(t, err, "Failed to read metadata")

	assert.Equal(t, filepath.Base(tmpFile.Name()), metadata.Name, "Name should match")
	assert.Equal(t, int64(len(testData)), metadata.Size, "Size should match")
	assert.False(t, metadata.IsDir, "File should not be marked as directory")
}

func TestFileHandler_WriteMetadata(t *testing.T) {
	fh := NewFileHandler()

	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "nokvault-test-*.txt")
	require.NoError(t, err, "Failed to create temp file")
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	originalModTime := time.Now().Add(-1 * time.Hour)
	metadata := &FileMetadata{
		Name:    "test.txt",
		Size:    100,
		Mode:    0644,
		ModTime: originalModTime,
		IsDir:   false,
	}

	// Write metadata
	err = fh.WriteMetadata(tmpFile.Name(), metadata)
	require.NoError(t, err, "Failed to write metadata")

	// Verify metadata was applied
	info, err := os.Stat(tmpFile.Name())
	require.NoError(t, err, "Failed to stat file")

	assert.Equal(t, originalModTime.Unix(), info.ModTime().Unix(), "ModTime should be set correctly")
}

func TestFileHandler_WriteHeader(t *testing.T) {
	fh := NewFileHandler()

	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}

	metadata := &FileMetadata{
		Name:    "test.txt",
		Size:    100,
		Mode:    0644,
		ModTime: time.Now(),
		IsDir:   false,
	}

	var buf bytes.Buffer

	// Write header with metadata
	err := fh.WriteHeader(&buf, salt, metadata)
	require.NoError(t, err, "Failed to write header")

	// Verify header can be read back
	header, readMetadata, err := fh.ReadHeaderWithMetadata(&buf)
	require.NoError(t, err, "Failed to read header")

	assert.Equal(t, NokvaultMagic, string(header.Magic[:]), "Magic should match")
	assert.Equal(t, uint16(CurrentVersion), header.Version, "Version should match")
	require.NotNil(t, readMetadata, "Expected metadata to be read")
	assert.Equal(t, metadata.Name, readMetadata.Name, "Metadata name should match")
}

func TestFileHandler_WriteHeader_NoMetadata(t *testing.T) {
	fh := NewFileHandler()

	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}

	var buf bytes.Buffer

	// Write header without metadata
	err := fh.WriteHeader(&buf, salt, nil)
	require.NoError(t, err, "Failed to write header")

	// Verify header can be read back
	header, metadata, err := fh.ReadHeaderWithMetadata(&buf)
	require.NoError(t, err, "Failed to read header")

	assert.Equal(t, NokvaultMagic, string(header.Magic[:]), "Magic should match")
	assert.Nil(t, metadata, "Expected no metadata when none was written")
}

func TestFileHandler_ReadHeader_InvalidMagic(t *testing.T) {
	fh := NewFileHandler()

	var buf bytes.Buffer
	buf.WriteString("INVALID")

	_, err := fh.ReadHeader(&buf)
	assert.Error(t, err, "Expected error for invalid magic number")
}

func TestFileHandler_ReadHeader_InvalidSalt(t *testing.T) {
	fh := NewFileHandler()

	var buf bytes.Buffer
	invalidSalt := make([]byte, 8) // Wrong size

	err := fh.WriteHeader(&buf, invalidSalt, nil)
	assert.Error(t, err, "Expected error for invalid salt size")
}

func TestFileHandler_EnsureDirectory(t *testing.T) {
	fh := NewFileHandler()

	tmpDir := filepath.Join(os.TempDir(), "nokvault-test-dir")
	defer os.RemoveAll(tmpDir)

	err := fh.EnsureDirectory(tmpDir)
	require.NoError(t, err, "Failed to create directory")

	info, err := os.Stat(tmpDir)
	require.NoError(t, err, "Directory was not created")

	assert.True(t, info.IsDir(), "Created path should be a directory")
}

func TestFileHandler_GetRelativePath(t *testing.T) {
	fh := NewFileHandler()

	base := "/base/path"
	target := "/base/path/sub/file.txt"

	relPath, err := fh.GetRelativePath(base, target)
	require.NoError(t, err, "Failed to get relative path")

	expected := filepath.Join("sub", "file.txt")
	assert.Equal(t, expected, relPath, "Relative path should match")
}

func TestFileHandler_CopyFile(t *testing.T) {
	fh := NewFileHandler()

	// Create source file
	srcFile, err := os.CreateTemp("", "nokvault-test-src-*.txt")
	require.NoError(t, err, "Failed to create source file")
	defer os.Remove(srcFile.Name())

	testData := []byte("test content for copy")
	_, err = srcFile.Write(testData)
	require.NoError(t, err, "Failed to write test data")
	srcFile.Close()

	// Create destination file path
	dstFile, err := os.CreateTemp("", "nokvault-test-dst-*.txt")
	require.NoError(t, err, "Failed to create destination file")
	dstPath := dstFile.Name()
	dstFile.Close()
	defer os.Remove(dstPath)

	// Copy file
	err = fh.CopyFile(srcFile.Name(), dstPath)
	require.NoError(t, err, "Failed to copy file")

	// Verify destination file contents
	copiedData, err := os.ReadFile(dstPath)
	require.NoError(t, err, "Failed to read copied file")

	assert.Equal(t, testData, copiedData, "Copied data should match original")
}

func TestFileHandler_WalkDirectory(t *testing.T) {
	fh := NewFileHandler()

	tmpDir, err := os.MkdirTemp("", "nokvault-test-walk-*")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tmpDir)

	// Create test files
	files := []string{"file1.txt", "file2.txt", "subdir/file3.txt"}
	for _, file := range files {
		filePath := filepath.Join(tmpDir, file)
		err := os.MkdirAll(filepath.Dir(filePath), 0755)
		require.NoError(t, err, "Failed to create subdirectory")
		err = os.WriteFile(filePath, []byte("test"), 0644)
		require.NoError(t, err, "Failed to create test file")
	}

	// Walk directory
	visitedFiles := make(map[string]bool)
	err = fh.WalkDirectory(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			relPath, _ := filepath.Rel(tmpDir, path)
			// Normalize path separators for cross-platform compatibility
			relPath = filepath.ToSlash(relPath)
			visitedFiles[relPath] = true
		}
		return nil
	})

	require.NoError(t, err, "WalkDirectory should succeed")

	// Verify all files were visited
	for _, file := range files {
		normalizedFile := filepath.ToSlash(file)
		assert.True(t, visitedFiles[normalizedFile], "File %s should be visited", normalizedFile)
	}
}

func TestFileHandler_CountFiles(t *testing.T) {
	fh := NewFileHandler()

	tmpDir, err := os.MkdirTemp("", "nokvault-test-count-*")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tmpDir)

	// Create test files
	files := []string{"file1.txt", "file2.txt", "subdir/file3.txt"}
	for _, file := range files {
		filePath := filepath.Join(tmpDir, file)
		err := os.MkdirAll(filepath.Dir(filePath), 0755)
		require.NoError(t, err, "Failed to create subdirectory")
		err = os.WriteFile(filePath, []byte("test"), 0644)
		require.NoError(t, err, "Failed to create test file")
	}

	count, err := fh.CountFiles(tmpDir)
	require.NoError(t, err, "CountFiles should succeed")

	assert.Equal(t, len(files), count, "File count should match")
}

func TestFileHandler_GetTotalSize(t *testing.T) {
	fh := NewFileHandler()

	tmpDir, err := os.MkdirTemp("", "nokvault-test-size-*")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tmpDir)

	// Create test files with known sizes
	files := map[string]int64{
		"file1.txt":        100,
		"file2.txt":        200,
		"subdir/file3.txt": 300,
	}

	var expectedTotal int64
	for file, size := range files {
		filePath := filepath.Join(tmpDir, file)
		err := os.MkdirAll(filepath.Dir(filePath), 0755)
		require.NoError(t, err, "Failed to create subdirectory")
		data := make([]byte, size)
		err = os.WriteFile(filePath, data, 0644)
		require.NoError(t, err, "Failed to create test file")
		expectedTotal += size
	}

	totalSize, err := fh.GetTotalSize(tmpDir)
	require.NoError(t, err, "GetTotalSize should succeed")

	assert.Equal(t, expectedTotal, totalSize, "Total size should match expected")
}
