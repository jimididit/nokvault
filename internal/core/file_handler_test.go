package core

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jimididit/nokvault/internal/crypto"
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

	// Write metadata (clamp world-readable 0644 → 0600)
	err = fh.WriteMetadata(tmpFile.Name(), metadata, false)
	require.NoError(t, err, "Failed to write metadata")

	// Verify metadata was applied
	info, err := os.Stat(tmpFile.Name())
	require.NoError(t, err, "Failed to stat file")

	assert.Equal(t, originalModTime.Unix(), info.ModTime().Unix(), "ModTime should be set correctly")
	if probePermSupportsChmod(t, tmpFile.Name()) {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "mode should be clamped to 0600")
	}
}

func probePermSupportsChmod(t *testing.T, path string) bool {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm() == 0o600
}

func TestClampPersistedMode(t *testing.T) {
	assert.Equal(t, os.FileMode(0o600), ClampPersistedMode(0o644, false).Perm())
	assert.Equal(t, os.FileMode(0o600), ClampPersistedMode(0o777, false).Perm())
	assert.Equal(t, os.FileMode(0o400), ClampPersistedMode(0o400, false).Perm())
	assert.Equal(t, os.FileMode(0o700), ClampPersistedMode(0o755, true).Perm())
	assert.Equal(t, os.FileMode(0o500), ClampPersistedMode(0o555, true).Perm())
}

func TestFileHandler_WriteMetadata_PreserveMode(t *testing.T) {
	fh := NewFileHandler()
	tmpFile, err := os.CreateTemp("", "nokvault-test-*.txt")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if err := os.Chmod(tmpFile.Name(), 0o600); err != nil {
		t.Skipf("chmod not supported: %v", err)
	}
	probe, err := os.Stat(tmpFile.Name())
	require.NoError(t, err)
	if probe.Mode().Perm() != 0o600 {
		t.Skip("filesystem ignores unix permission bits")
	}

	metadata := &FileMetadata{
		Name:    "test.txt",
		Mode:    0o644,
		ModTime: time.Now(),
		IsDir:   false,
	}
	require.NoError(t, fh.WriteMetadata(tmpFile.Name(), metadata, true))
	info, err := os.Stat(tmpFile.Name())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
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
	err := fh.WriteHeader(&buf, salt, metadata, crypto.DefaultArgon2Params())
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
	err := fh.WriteHeader(&buf, salt, nil, crypto.DefaultArgon2Params())
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

	err := fh.WriteHeader(&buf, invalidSalt, nil, crypto.DefaultArgon2Params())
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

func TestFileHandler_WriteHeader_V2IncludesKDFParams(t *testing.T) {
	fh := NewFileHandler()
	salt := make([]byte, 16)
	params := &crypto.Argon2Params{Memory: 32768, Time: 2, Parallelism: 2, KeyLength: 32}

	var buf bytes.Buffer
	require.NoError(t, fh.WriteHeader(&buf, salt, nil, params))

	header, meta, err := fh.ReadHeaderWithMetadata(&buf)
	require.NoError(t, err)
	assert.Nil(t, meta)
	assert.Equal(t, uint16(2), header.Version)
	assert.Equal(t, uint32(32768), header.Memory)
	assert.Equal(t, uint32(2), header.Time)
	assert.Equal(t, uint8(2), header.Parallelism)
	assert.Equal(t, uint32(32), header.KeyLength)
	assert.Equal(t, uint64(HeaderWireSize(2)), header.DataOffset)
}

func TestFileHandler_ReadHeader_V1UsesDefaultKDFParams(t *testing.T) {
	// Hand-built v1 header: magic + version=1 + salt + metadataSize=0 + dataOffset=sizeof(v1)
	fh := NewFileHandler()
	var buf bytes.Buffer
	magic := [8]byte{}
	copy(magic[:], NokvaultMagic)
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, magic))
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, uint16(1)))
	salt := make([]byte, 16)
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, salt))
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, uint32(0)))
	v1Size := HeaderWireSize(1)
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, uint64(v1Size)))

	header, err := fh.ReadHeader(&buf)
	require.NoError(t, err)
	assert.Equal(t, uint16(1), header.Version)
	defs := crypto.DefaultArgon2Params()
	assert.Equal(t, defs.Memory, header.Memory)
	assert.Equal(t, defs.Time, header.Time)
	assert.Equal(t, defs.Parallelism, header.Parallelism)
	assert.Equal(t, defs.KeyLength, header.KeyLength)
}

func TestFileHandler_WriteHeader_RejectsInvalidParams(t *testing.T) {
	fh := NewFileHandler()
	salt := make([]byte, 16)
	err := fh.WriteHeader(&bytes.Buffer{}, salt, nil, &crypto.Argon2Params{
		Memory: 0, Time: 3, Parallelism: 4, KeyLength: 32,
	})
	assert.Error(t, err)
}

func TestValidateKDFParams(t *testing.T) {
	valid := crypto.DefaultArgon2Params()

	tests := []struct {
		name    string
		params  *crypto.Argon2Params
		wantErr string
	}{
		{name: "nil params", params: nil, wantErr: "kdf params are required"},
		{name: "zero memory", params: &crypto.Argon2Params{Memory: 0, Time: 3, Parallelism: 4, KeyLength: 32}, wantErr: "must be non-zero"},
		{name: "zero time", params: &crypto.Argon2Params{Memory: 65536, Time: 0, Parallelism: 4, KeyLength: 32}, wantErr: "must be non-zero"},
		{name: "zero parallelism", params: &crypto.Argon2Params{Memory: 65536, Time: 3, Parallelism: 0, KeyLength: 32}, wantErr: "must be non-zero"},
		{name: "wrong key length", params: &crypto.Argon2Params{Memory: 65536, Time: 3, Parallelism: 4, KeyLength: 16}, wantErr: "key length must be 32"},
		{name: "valid defaults", params: valid, wantErr: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKDFParams(tt.params)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestFileHandler_V1DecryptRoundTrip(t *testing.T) {
	password := []byte("v1-test-password")
	plaintext := []byte("v1 legacy file decrypt payload")
	defs := crypto.DefaultArgon2Params()

	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)

	km := NewKeyManager()
	km.SetArgon2Params(defs)
	key, err := km.DeriveKeyFromPasswordAndSalt(password, salt)
	require.NoError(t, err)

	es := NewEncryptionService()
	ciphertext, err := es.EncryptData(plaintext, key)
	require.NoError(t, err)

	var headerBuf bytes.Buffer
	magic := [8]byte{}
	copy(magic[:], NokvaultMagic)
	require.NoError(t, binary.Write(&headerBuf, binary.LittleEndian, magic))
	require.NoError(t, binary.Write(&headerBuf, binary.LittleEndian, uint16(1)))
	var saltArr [16]byte
	copy(saltArr[:], salt)
	require.NoError(t, binary.Write(&headerBuf, binary.LittleEndian, saltArr))
	require.NoError(t, binary.Write(&headerBuf, binary.LittleEndian, uint32(0)))
	v1Size := HeaderWireSize(1)
	require.NoError(t, binary.Write(&headerBuf, binary.LittleEndian, uint64(v1Size)))

	var fileBuf bytes.Buffer
	fileBuf.Write(headerBuf.Bytes())
	fileBuf.Write(ciphertext)

	fh := NewFileHandler()
	header, _, err := fh.ReadHeaderWithMetadata(bytes.NewReader(fileBuf.Bytes()))
	require.NoError(t, err)
	assert.Equal(t, uint16(1), header.Version)

	km2 := NewKeyManager()
	km2.SetArgon2Params(header.Argon2Params())
	decKey, err := km2.DeriveKeyFromPasswordAndSalt(password, header.Salt[:])
	require.NoError(t, err)

	payload := fileBuf.Bytes()[header.DataOffset:]
	got, err := es.DecryptData(payload, decKey)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}
