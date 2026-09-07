package core

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jimididit/nokvault/internal/crypto"
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

// NokvaultHeader is the in-memory header. Wire layout depends on Version.
type NokvaultHeader struct {
	Magic        [8]byte
	Version      uint16
	Salt         [16]byte
	MetadataSize uint32
	DataOffset   uint64
	Memory       uint32
	Time         uint32
	Parallelism  uint8
	KeyLength    uint32
}

const (
	NokvaultMagic  = "NOKVAULT"
	Version1       = uint16(1)
	Version2       = uint16(2)
	CurrentVersion = Version2
)

// HeaderWireSize returns on-disk header size for a format version (excluding JSON metadata).
func HeaderWireSize(version uint16) int {
	switch version {
	case Version1:
		return 8 + 2 + 16 + 4 + 8 // 38
	case Version2:
		return HeaderWireSize(Version1) + 4 + 4 + 1 + 3 + 4 // +16 = 54
	default:
		return -1
	}
}

func ValidateKDFParams(p *crypto.Argon2Params) error {
	if p == nil {
		return fmt.Errorf("kdf params are required")
	}
	if p.Memory == 0 || p.Time == 0 || p.Parallelism == 0 {
		return fmt.Errorf("invalid kdf params: memory, time, and parallelism must be non-zero")
	}
	if p.KeyLength != crypto.DefaultKeyLength {
		return fmt.Errorf("invalid kdf params: key length must be %d", crypto.DefaultKeyLength)
	}
	return nil
}

func (h *NokvaultHeader) Argon2Params() *crypto.Argon2Params {
	return &crypto.Argon2Params{
		Memory:      h.Memory,
		Time:        h.Time,
		Parallelism: h.Parallelism,
		KeyLength:   h.KeyLength,
	}
}

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
func (fh *FileHandler) WriteHeader(writer io.Writer, salt []byte, metadata *FileMetadata, params *crypto.Argon2Params) error {
	if err := ValidateKDFParams(params); err != nil {
		return err
	}
	if len(salt) != 16 {
		return fmt.Errorf("salt must be 16 bytes")
	}

	var metadataJSON []byte
	if metadata != nil {
		var err error
		metadataJSON, err = json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("failed to serialize metadata: %w", err)
		}
	}

	headerSize := HeaderWireSize(CurrentVersion)
	dataOffset := uint64(headerSize) + uint64(len(metadataJSON))

	var magic [8]byte
	copy(magic[:], NokvaultMagic)
	var saltArr [16]byte
	copy(saltArr[:], salt)

	if err := binary.Write(writer, binary.LittleEndian, magic); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if err := binary.Write(writer, binary.LittleEndian, CurrentVersion); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if err := binary.Write(writer, binary.LittleEndian, saltArr); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if err := binary.Write(writer, binary.LittleEndian, uint32(len(metadataJSON))); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if err := binary.Write(writer, binary.LittleEndian, dataOffset); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	// v2 KDF fields
	if err := binary.Write(writer, binary.LittleEndian, params.Memory); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if err := binary.Write(writer, binary.LittleEndian, params.Time); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if err := binary.Write(writer, binary.LittleEndian, params.Parallelism); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	pad := [3]byte{}
	if err := binary.Write(writer, binary.LittleEndian, pad); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if err := binary.Write(writer, binary.LittleEndian, params.KeyLength); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	if len(metadataJSON) > 0 {
		if _, err := writer.Write(metadataJSON); err != nil {
			return fmt.Errorf("failed to write metadata: %w", err)
		}
	}
	return nil
}

// ReadHeader reads a nokvault header from a file
func (fh *FileHandler) ReadHeader(reader io.Reader) (*NokvaultHeader, error) {
	h := &NokvaultHeader{}
	if err := binary.Read(reader, binary.LittleEndian, &h.Magic); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}
	if string(h.Magic[:]) != NokvaultMagic {
		return nil, fmt.Errorf("invalid magic number: not a nokvault file")
	}
	if err := binary.Read(reader, binary.LittleEndian, &h.Version); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &h.Salt); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &h.MetadataSize); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &h.DataOffset); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	switch h.Version {
	case Version1:
		defs := crypto.DefaultArgon2Params()
		h.Memory = defs.Memory
		h.Time = defs.Time
		h.Parallelism = defs.Parallelism
		h.KeyLength = defs.KeyLength
	case Version2:
		if err := binary.Read(reader, binary.LittleEndian, &h.Memory); err != nil {
			return nil, fmt.Errorf("failed to read header: %w", err)
		}
		if err := binary.Read(reader, binary.LittleEndian, &h.Time); err != nil {
			return nil, fmt.Errorf("failed to read header: %w", err)
		}
		if err := binary.Read(reader, binary.LittleEndian, &h.Parallelism); err != nil {
			return nil, fmt.Errorf("failed to read header: %w", err)
		}
		var pad [3]byte
		if err := binary.Read(reader, binary.LittleEndian, &pad); err != nil {
			return nil, fmt.Errorf("failed to read header: %w", err)
		}
		if err := binary.Read(reader, binary.LittleEndian, &h.KeyLength); err != nil {
			return nil, fmt.Errorf("failed to read header: %w", err)
		}
		if err := ValidateKDFParams(h.Argon2Params()); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported version: %d", h.Version)
	}
	return h, nil
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
