package core

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileHandler_ReadMetadata(t *testing.T) {
	fh := NewFileHandler()

	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "nokvault-test-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	testData := []byte("test content")
	if _, err := tmpFile.Write(testData); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}
	tmpFile.Close()

	// Read metadata
	metadata, err := fh.ReadMetadata(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read metadata: %v", err)
	}

	if metadata.Name != filepath.Base(tmpFile.Name()) {
		t.Errorf("Expected name %s, got %s", filepath.Base(tmpFile.Name()), metadata.Name)
	}

	if metadata.Size != int64(len(testData)) {
		t.Errorf("Expected size %d, got %d", len(testData), metadata.Size)
	}

	if metadata.IsDir {
		t.Error("File should not be marked as directory")
	}
}

func TestFileHandler_WriteMetadata(t *testing.T) {
	fh := NewFileHandler()

	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "nokvault-test-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
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
	if err := fh.WriteMetadata(tmpFile.Name(), metadata); err != nil {
		t.Fatalf("Failed to write metadata: %v", err)
	}

	// Verify metadata was applied
	info, err := os.Stat(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}

	if info.ModTime().Unix() != originalModTime.Unix() {
		t.Errorf("ModTime not set correctly")
	}
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
	if err := fh.WriteHeader(&buf, salt, metadata); err != nil {
		t.Fatalf("Failed to write header: %v", err)
	}

	// Verify header can be read back
	header, readMetadata, err := fh.ReadHeaderWithMetadata(&buf)
	if err != nil {
		t.Fatalf("Failed to read header: %v", err)
	}

	if string(header.Magic[:]) != NokvaultMagic {
		t.Errorf("Expected magic %s, got %s", NokvaultMagic, string(header.Magic[:]))
	}

	if header.Version != CurrentVersion {
		t.Errorf("Expected version %d, got %d", CurrentVersion, header.Version)
	}

	if readMetadata == nil {
		t.Fatal("Expected metadata to be read")
	}

	if readMetadata.Name != metadata.Name {
		t.Errorf("Expected name %s, got %s", metadata.Name, readMetadata.Name)
	}
}

func TestFileHandler_WriteHeader_NoMetadata(t *testing.T) {
	fh := NewFileHandler()

	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}

	var buf bytes.Buffer

	// Write header without metadata
	if err := fh.WriteHeader(&buf, salt, nil); err != nil {
		t.Fatalf("Failed to write header: %v", err)
	}

	// Verify header can be read back
	header, metadata, err := fh.ReadHeaderWithMetadata(&buf)
	if err != nil {
		t.Fatalf("Failed to read header: %v", err)
	}

	if string(header.Magic[:]) != NokvaultMagic {
		t.Errorf("Expected magic %s, got %s", NokvaultMagic, string(header.Magic[:]))
	}

	if metadata != nil {
		t.Error("Expected no metadata when none was written")
	}
}

func TestFileHandler_ReadHeader_InvalidMagic(t *testing.T) {
	fh := NewFileHandler()

	var buf bytes.Buffer
	buf.WriteString("INVALID")

	_, err := fh.ReadHeader(&buf)
	if err == nil {
		t.Error("Expected error for invalid magic number")
	}
}

func TestFileHandler_ReadHeader_InvalidSalt(t *testing.T) {
	fh := NewFileHandler()

	var buf bytes.Buffer
	invalidSalt := make([]byte, 8) // Wrong size

	err := fh.WriteHeader(&buf, invalidSalt, nil)
	if err == nil {
		t.Error("Expected error for invalid salt size")
	}
}

func TestFileHandler_EnsureDirectory(t *testing.T) {
	fh := NewFileHandler()

	tmpDir := filepath.Join(os.TempDir(), "nokvault-test-dir")
	defer os.RemoveAll(tmpDir)

	if err := fh.EnsureDirectory(tmpDir); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	info, err := os.Stat(tmpDir)
	if err != nil {
		t.Fatalf("Directory was not created: %v", err)
	}

	if !info.IsDir() {
		t.Error("Created path is not a directory")
	}
}

func TestFileHandler_GetRelativePath(t *testing.T) {
	fh := NewFileHandler()

	base := "/base/path"
	target := "/base/path/sub/file.txt"

	relPath, err := fh.GetRelativePath(base, target)
	if err != nil {
		t.Fatalf("Failed to get relative path: %v", err)
	}

	expected := filepath.Join("sub", "file.txt")
	if relPath != expected {
		t.Errorf("Expected relative path %s, got %s", expected, relPath)
	}
}

func TestFileHandler_CopyFile(t *testing.T) {
	fh := NewFileHandler()

	// Create source file
	srcFile, err := os.CreateTemp("", "nokvault-test-src-*.txt")
	if err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}
	defer os.Remove(srcFile.Name())

	testData := []byte("test content for copy")
	if _, err := srcFile.Write(testData); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}
	srcFile.Close()

	// Create destination file path
	dstFile, err := os.CreateTemp("", "nokvault-test-dst-*.txt")
	if err != nil {
		t.Fatalf("Failed to create destination file: %v", err)
	}
	dstPath := dstFile.Name()
	dstFile.Close()
	defer os.Remove(dstPath)

	// Copy file
	if err := fh.CopyFile(srcFile.Name(), dstPath); err != nil {
		t.Fatalf("Failed to copy file: %v", err)
	}

	// Verify destination file contents
	copiedData, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("Failed to read copied file: %v", err)
	}

	if !bytes.Equal(copiedData, testData) {
		t.Errorf("Copied data doesn't match. Expected %s, got %s", string(testData), string(copiedData))
	}
}

func TestFileHandler_WalkDirectory(t *testing.T) {
	fh := NewFileHandler()

	tmpDir, err := os.MkdirTemp("", "nokvault-test-walk-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test files
	files := []string{"file1.txt", "file2.txt", "subdir/file3.txt"}
	for _, file := range files {
		filePath := filepath.Join(tmpDir, file)
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			t.Fatalf("Failed to create subdirectory: %v", err)
		}
		if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
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

	if err != nil {
		t.Fatalf("WalkDirectory failed: %v", err)
	}

	// Verify all files were visited
	for _, file := range files {
		normalizedFile := filepath.ToSlash(file)
		if !visitedFiles[normalizedFile] {
			t.Errorf("File %s was not visited. Visited files: %v", normalizedFile, visitedFiles)
		}
	}
}

func TestFileHandler_CountFiles(t *testing.T) {
	fh := NewFileHandler()

	tmpDir, err := os.MkdirTemp("", "nokvault-test-count-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test files
	files := []string{"file1.txt", "file2.txt", "subdir/file3.txt"}
	for _, file := range files {
		filePath := filepath.Join(tmpDir, file)
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			t.Fatalf("Failed to create subdirectory: %v", err)
		}
		if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	count, err := fh.CountFiles(tmpDir)
	if err != nil {
		t.Fatalf("CountFiles failed: %v", err)
	}

	if count != len(files) {
		t.Errorf("Expected %d files, got %d", len(files), count)
	}
}

func TestFileHandler_GetTotalSize(t *testing.T) {
	fh := NewFileHandler()

	tmpDir, err := os.MkdirTemp("", "nokvault-test-size-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test files with known sizes
	files := map[string]int64{
		"file1.txt": 100,
		"file2.txt": 200,
		"subdir/file3.txt": 300,
	}

	var expectedTotal int64
	for file, size := range files {
		filePath := filepath.Join(tmpDir, file)
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			t.Fatalf("Failed to create subdirectory: %v", err)
		}
		data := make([]byte, size)
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
		expectedTotal += size
	}

	totalSize, err := fh.GetTotalSize(tmpDir)
	if err != nil {
		t.Fatalf("GetTotalSize failed: %v", err)
	}

	if totalSize != expectedTotal {
		t.Errorf("Expected total size %d, got %d", expectedTotal, totalSize)
	}
}
