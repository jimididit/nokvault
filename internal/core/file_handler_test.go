package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jimididit/nokvault/internal/crypto"
	"github.com/jimididit/nokvault/internal/utils"
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

func TestFileHandler_ReadHeader_RejectsOversizedMetadataBeforeAllocation(t *testing.T) {
	fh := NewFileHandler()
	var buf bytes.Buffer
	require.NoError(t, fh.WriteHeader(&buf, make([]byte, 16), nil, crypto.DefaultArgon2Params()))

	raw := append([]byte(nil), buf.Bytes()...)
	binary.LittleEndian.PutUint32(raw[26:30], maxMetadataSize+1)
	binary.LittleEndian.PutUint64(raw[30:38], uint64(HeaderWireSize(Version2))+maxMetadataSize+1)

	_, _, err := fh.ReadHeaderWithMetadata(bytes.NewReader(raw))
	require.ErrorContains(t, err, "metadata size")
}

func TestFileHandler_ReadHeader_RejectsInconsistentDataOffset(t *testing.T) {
	fh := NewFileHandler()
	var buf bytes.Buffer
	require.NoError(t, fh.WriteHeader(&buf, make([]byte, 16), nil, crypto.DefaultArgon2Params()))

	for name, offset := range map[string]uint64{
		"below expected": uint64(HeaderWireSize(Version2) - 1),
		"above expected": uint64(HeaderWireSize(Version2) + 1),
	} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(nil), buf.Bytes()...)
			binary.LittleEndian.PutUint64(raw[30:38], offset)

			_, _, err := fh.ReadHeaderWithMetadata(bytes.NewReader(raw))
			require.ErrorContains(t, err, "invalid data offset")
		})
	}
}

func TestFileHandler_ReadHeader_RejectsEveryTruncatedPrefix(t *testing.T) {
	fh := NewFileHandler()

	var v1 bytes.Buffer
	magic := [8]byte{}
	copy(magic[:], NokvaultMagic)
	require.NoError(t, binary.Write(&v1, binary.LittleEndian, magic))
	require.NoError(t, binary.Write(&v1, binary.LittleEndian, Version1))
	require.NoError(t, binary.Write(&v1, binary.LittleEndian, [16]byte{}))
	require.NoError(t, binary.Write(&v1, binary.LittleEndian, uint32(0)))
	require.NoError(t, binary.Write(&v1, binary.LittleEndian, uint64(HeaderWireSize(Version1))))

	var v2 bytes.Buffer
	require.NoError(t, fh.WriteHeader(&v2, make([]byte, 16), nil, crypto.DefaultArgon2Params()))

	var v2Metadata bytes.Buffer
	require.NoError(t, fh.WriteHeader(&v2Metadata, make([]byte, 16), &FileMetadata{
		Name:         "evidence.txt",
		Size:         42,
		Mode:         0o600,
		ModTime:      time.Unix(1_700_000_000, 0).UTC(),
		RelativePath: "case/evidence.txt",
	}, crypto.DefaultArgon2Params()))

	fixtures := map[string][]byte{
		"v1":               v1.Bytes(),
		"v2":               v2.Bytes(),
		"v2 with metadata": v2Metadata.Bytes(),
	}
	for name, valid := range fixtures {
		t.Run(name, func(t *testing.T) {
			for length := 0; length < len(valid); length++ {
				_, _, err := fh.ReadHeaderWithMetadata(bytes.NewReader(valid[:length]))
				if err == nil {
					t.Fatalf("prefix length %d of %d unexpectedly parsed", length, len(valid))
				}
			}

			_, _, err := fh.ReadHeaderWithMetadata(bytes.NewReader(valid))
			require.NoError(t, err)
		})
	}
}

func TestFileHandler_ReadHeader_RejectsMalformedFields(t *testing.T) {
	fh := NewFileHandler()
	var valid bytes.Buffer
	require.NoError(t, fh.WriteHeader(&valid, make([]byte, 16), nil, crypto.DefaultArgon2Params()))

	mutate := func(fn func([]byte)) []byte {
		data := append([]byte(nil), valid.Bytes()...)
		fn(data)
		return data
	}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "unsupported version",
			data: mutate(func(data []byte) {
				binary.LittleEndian.PutUint16(data[8:10], 99)
			}),
		},
		{
			name: "memory above maximum",
			data: mutate(func(data []byte) {
				binary.LittleEndian.PutUint32(data[38:42], MaxKDFMemory+1)
			}),
		},
		{
			name: "time above maximum",
			data: mutate(func(data []byte) {
				binary.LittleEndian.PutUint32(data[42:46], MaxKDFTime+1)
			}),
		},
		{
			name: "parallelism above maximum",
			data: mutate(func(data []byte) {
				data[46] = MaxKDFParallelism + 1
			}),
		},
		{
			name: "truncated metadata",
			data: func() []byte {
				data := mutate(func(data []byte) {
					binary.LittleEndian.PutUint32(data[26:30], 4)
					binary.LittleEndian.PutUint64(data[30:38], uint64(HeaderWireSize(Version2)+4))
				})
				return append(data, []byte("{}")...)
			}(),
		},
		{
			name: "invalid metadata json",
			data: func() []byte {
				data := mutate(func(data []byte) {
					binary.LittleEndian.PutUint32(data[26:30], 1)
					binary.LittleEndian.PutUint64(data[30:38], uint64(HeaderWireSize(Version2)+1))
				})
				return append(data, '{')
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := fh.ReadHeaderWithMetadata(bytes.NewReader(tt.data))
			require.Error(t, err)
		})
	}
}

func TestFileHandler_EnsureDirectory(t *testing.T) {
	fh := NewFileHandler()

	tmpDir := filepath.Join(t.TempDir(), "output")

	err := fh.EnsureDirectory(tmpDir)
	require.NoError(t, err, "Failed to create directory")

	info, err := os.Stat(tmpDir)
	require.NoError(t, err, "Directory was not created")

	assert.True(t, info.IsDir(), "Created path should be a directory")
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0700), info.Mode().Perm())
	}
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

func TestFileHandler_WalkDirectory_RootSymlink(t *testing.T) {
	fh := NewFileHandler()
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "root-link")
	trySymlink(t, target, link)

	called := 0
	err := fh.WalkDirectory(link, func(path string, info os.FileInfo, err error) error {
		called++
		return nil
	})
	requireSymlinkDisallowed(t, err, link)
	assert.Equal(t, 0, called, "callback must not run for a symlink root")
}

func TestFileHandler_WalkDirectory_NestedFileSymlink(t *testing.T) {
	fh := NewFileHandler()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "regular.txt"), []byte("ok"), 0o644))
	target := filepath.Join(root, "target.txt")
	require.NoError(t, os.WriteFile(target, []byte("target"), 0o644))
	link := filepath.Join(root, "nested-link.txt")
	trySymlink(t, target, link)

	var visited []string
	err := fh.WalkDirectory(root, func(path string, info os.FileInfo, err error) error {
		visited = append(visited, path)
		return nil
	})
	requireSymlinkDisallowed(t, err, link)
	for _, path := range visited {
		if path == link {
			t.Fatalf("callback was invoked for nested file symlink %s", link)
		}
	}
}

func TestFileHandler_WalkDirectory_NestedDirectorySymlink(t *testing.T) {
	fh := NewFileHandler()
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(realDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(realDir, "inside.txt"), []byte("secret"), 0o644))
	link := filepath.Join(root, "nested-dir-link")
	trySymlink(t, realDir, link)

	var visited []string
	err := fh.WalkDirectory(root, func(path string, info os.FileInfo, err error) error {
		visited = append(visited, path)
		return nil
	})
	requireSymlinkDisallowed(t, err, link)
	for _, path := range visited {
		if path == link || strings.HasPrefix(path, link+string(os.PathSeparator)) {
			t.Fatalf("callback was invoked for nested directory symlink %s (visited %s)", link, path)
		}
	}
}

func TestFileHandler_CountFiles_NestedSymlink(t *testing.T) {
	fh := NewFileHandler()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "regular.txt"), []byte("ok"), 0o644))
	target := filepath.Join(root, "target.txt")
	require.NoError(t, os.WriteFile(target, []byte("target"), 0o644))
	link := filepath.Join(root, "nested-link.txt")
	trySymlink(t, target, link)

	_, err := fh.CountFiles(root)
	requireSymlinkDisallowed(t, err, link)
}

func TestFileHandler_GetTotalSize_NestedSymlink(t *testing.T) {
	fh := NewFileHandler()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "regular.txt"), []byte("ok"), 0o644))
	target := filepath.Join(root, "target.txt")
	require.NoError(t, os.WriteFile(target, []byte("target"), 0o644))
	link := filepath.Join(root, "nested-link.txt")
	trySymlink(t, target, link)

	_, err := fh.GetTotalSize(root)
	requireSymlinkDisallowed(t, err, link)
}

func TestFileHandler_classifyWalkPath_ReparseOverridesWalkError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	require.NoError(t, os.WriteFile(target, []byte("x"), 0o644))
	link := filepath.Join(dir, "link.txt")
	trySymlink(t, target, link)

	err := classifyWalkPath(link, os.ErrPermission)
	requireSymlinkDisallowed(t, err, link)
}

func TestFileHandler_classifyWalkPath_PropagatesNormalWalkError(t *testing.T) {
	dir := t.TempDir()
	err := classifyWalkPath(dir, os.ErrPermission)
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("got %v, want os.ErrPermission", err)
	}
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
		{name: "memory at maximum", params: &crypto.Argon2Params{Memory: MaxKDFMemory, Time: 3, Parallelism: 4, KeyLength: 32}, wantErr: ""},
		{name: "memory above maximum", params: &crypto.Argon2Params{Memory: MaxKDFMemory + 1, Time: 3, Parallelism: 4, KeyLength: 32}, wantErr: "memory"},
		{name: "time at maximum", params: &crypto.Argon2Params{Memory: 65536, Time: MaxKDFTime, Parallelism: 4, KeyLength: 32}, wantErr: ""},
		{name: "time above maximum", params: &crypto.Argon2Params{Memory: 65536, Time: MaxKDFTime + 1, Parallelism: 4, KeyLength: 32}, wantErr: "time"},
		{name: "parallelism at maximum", params: &crypto.Argon2Params{Memory: 65536, Time: 3, Parallelism: MaxKDFParallelism, KeyLength: 32}, wantErr: ""},
		{name: "parallelism above maximum", params: &crypto.Argon2Params{Memory: 65536, Time: 3, Parallelism: MaxKDFParallelism + 1, KeyLength: 32}, wantErr: "parallelism"},
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

func trySymlink(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		if isLinkCreationUnavailable(err) {
			t.Skipf("symlink privilege/support unavailable: %v", err)
		}
		t.Fatalf("symlink creation failed: %v", err)
	}
}

func isLinkCreationUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case 1314, 1, 50:
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "privilege") ||
		strings.Contains(msg, "not supported") ||
		strings.Contains(msg, "a required privilege is not held")
}

func requireSymlinkDisallowed(t *testing.T, err error, rejectedPath string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected SYMLINK_DISALLOWED, got nil")
	}
	var nv *utils.NokvaultError
	if !errors.As(err, &nv) {
		t.Fatalf("got %T %v, want *utils.NokvaultError with code SYMLINK_DISALLOWED", err, err)
	}
	if nv.Code != "SYMLINK_DISALLOWED" {
		t.Fatalf("got code %q, want SYMLINK_DISALLOWED (err=%v)", nv.Code, err)
	}
	absRejected, absErr := filepath.Abs(rejectedPath)
	if absErr != nil {
		absRejected = rejectedPath
	}
	if !strings.Contains(err.Error(), absRejected) && !strings.Contains(err.Error(), rejectedPath) {
		t.Fatalf("error %q does not name rejected path %s", err, rejectedPath)
	}
}
