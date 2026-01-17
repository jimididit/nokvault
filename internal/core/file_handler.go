package core

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// FileMetadata stores file metadata
type FileMetadata struct {
	Name         string    `json:"name"`
	Size         int64     `json:"size"`
	Mode         uint32    `json:"mode"`
	ModTime      time.Time `json:"mod_time"`
	IsDir        bool      `json:"is_dir"`
	RelativePath string    `json:"relative_path"`
}

// NokvaultHeader represents the header of a nokvault encrypted file
type NokvaultHeader struct {
	Magic        [8]byte // "NOKVAULT"
	Version      uint16
	Salt         [16]byte
	MetadataSize uint32 // Size of JSON metadata
	DataOffset   uint64 // Offset to encrypted data
}

const (
	// NokvaultMagic is the magic number for nokvault files
	NokvaultMagic = "NOKVAULT"
	// CurrentVersion is the current file format version
	CurrentVersion = 1
)

// FileHandler handles file operations
type FileHandler struct {
}

// NewFileHandler creates a new file handler
func NewFileHandler() *FileHandler {
	return &FileHandler{}
}

// ReadMetadata reads file metadata
func (fh *FileHandler) ReadMetadata(path string) (*FileMetadata, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	return &FileMetadata{
		Name:         info.Name(),
		Size:         info.Size(),
		Mode:         uint32(info.Mode()),
		ModTime:      info.ModTime(),
		IsDir:        info.IsDir(),
		RelativePath: info.Name(),
	}, nil
}

// WriteMetadata writes metadata to a file
func (fh *FileHandler) WriteMetadata(path string, metadata *FileMetadata) error {
	if metadata == nil {
		return nil
	}

	if err := os.Chmod(path, os.FileMode(metadata.Mode)); err != nil {
		return fmt.Errorf("failed to set file mode: %w", err)
	}

	if err := os.Chtimes(path, metadata.ModTime, metadata.ModTime); err != nil {
		return fmt.Errorf("failed to set file times: %w", err)
	}

	return nil
}

// WriteHeader writes a nokvault header to a file with optional metadata
func (fh *FileHandler) WriteHeader(writer io.Writer, salt []byte, metadata *FileMetadata) error {
	header := NokvaultHeader{
		Version: CurrentVersion,
	}

	copy(header.Magic[:], NokvaultMagic)
	if len(salt) != 16 {
		return fmt.Errorf("salt must be 16 bytes")
	}
	copy(header.Salt[:], salt)

	// Serialize metadata to JSON if provided
	var metadataJSON []byte
	if metadata != nil {
		var err error
		metadataJSON, err = json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("failed to serialize metadata: %w", err)
		}
		header.MetadataSize = uint32(len(metadataJSON))
	}

	// Calculate data offset (header size + metadata size)
	header.DataOffset = uint64(binary.Size(header)) + uint64(header.MetadataSize)

	// Write header
	if err := binary.Write(writer, binary.LittleEndian, &header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write metadata JSON if present
	if len(metadataJSON) > 0 {
		if _, err := writer.Write(metadataJSON); err != nil {
			return fmt.Errorf("failed to write metadata: %w", err)
		}
	}

	return nil
}

// ReadHeader reads a nokvault header from a file
func (fh *FileHandler) ReadHeader(reader io.Reader) (*NokvaultHeader, error) {
	header := &NokvaultHeader{}

	if err := binary.Read(reader, binary.LittleEndian, header); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Verify magic number
	if string(header.Magic[:]) != NokvaultMagic {
		return nil, fmt.Errorf("invalid magic number: not a nokvault file")
	}

	// Verify version
	if header.Version != CurrentVersion {
		return nil, fmt.Errorf("unsupported version: %d", header.Version)
	}

	return header, nil
}

// ReadHeaderWithMetadata reads header and metadata from a file
func (fh *FileHandler) ReadHeaderWithMetadata(reader io.Reader) (*NokvaultHeader, *FileMetadata, error) {
	header, err := fh.ReadHeader(reader)
	if err != nil {
		return nil, nil, err
	}

	// Read metadata if present
	var metadata *FileMetadata
	if header.MetadataSize > 0 {
		metadataJSON := make([]byte, header.MetadataSize)
		if _, err := io.ReadFull(reader, metadataJSON); err != nil {
			return nil, nil, fmt.Errorf("failed to read metadata: %w", err)
		}

		metadata = &FileMetadata{}
		if err := json.Unmarshal(metadataJSON, metadata); err != nil {
			return nil, nil, fmt.Errorf("failed to deserialize metadata: %w", err)
		}
	}

	return header, metadata, nil
}

// EnsureDirectory ensures a directory exists
func (fh *FileHandler) EnsureDirectory(path string) error {
	return os.MkdirAll(path, 0755)
}

// GetRelativePath returns the relative path from base
func (fh *FileHandler) GetRelativePath(base, target string) (string, error) {
	return filepath.Rel(base, target)
}

// CopyFile copies a file from src to dst
func (fh *FileHandler) CopyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	return nil
}

// WalkDirectory walks a directory and calls fn for each file
func (fh *FileHandler) WalkDirectory(root string, fn func(path string, info os.FileInfo, err error) error) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fn(path, info, err)
		}
		return fn(path, info, nil)
	})
}

// CountFiles counts the number of files in a directory (excluding directories)
func (fh *FileHandler) CountFiles(root string) (int, error) {
	count := 0
	err := fh.WalkDirectory(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			count++
		}
		return nil
	})
	return count, err
}

// GetTotalSize calculates the total size of all files in a directory
func (fh *FileHandler) GetTotalSize(root string) (int64, error) {
	var totalSize int64
	err := fh.WalkDirectory(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})
	return totalSize, err
}
