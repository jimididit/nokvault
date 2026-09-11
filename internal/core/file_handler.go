package core

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jimididit/nokvault/internal/crypto"
	"github.com/jimididit/nokvault/internal/utils"
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
	Compress     uint8
}

const (
	NokvaultMagic   = "NOKVAULT"
	Version1        = uint16(1)
	Version2        = uint16(2)
	Version3        = uint16(3)
	CurrentVersion  = Version3
	maxMetadataSize = 1 << 20

	MaxKDFMemory      uint32 = 256 * 1024
	MaxKDFTime        uint32 = 10
	MaxKDFParallelism uint8  = 16
)

// HeaderWireSize returns on-disk header size for a format version (excluding JSON metadata).
func HeaderWireSize(version uint16) int {
	switch version {
	case Version1:
		return 8 + 2 + 16 + 4 + 8 // 38
	case Version2:
		return HeaderWireSize(Version1) + 4 + 4 + 1 + 3 + 4 // +16 = 54
	case Version3:
		return HeaderWireSize(Version2) + 1 + 3 // +4 = 58
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
	if p.Memory > MaxKDFMemory {
		return fmt.Errorf("invalid kdf params: memory %d exceeds maximum %d KiB", p.Memory, MaxKDFMemory)
	}
	if p.Time > MaxKDFTime {
		return fmt.Errorf("invalid kdf params: time %d exceeds maximum %d", p.Time, MaxKDFTime)
	}
	if p.Parallelism > MaxKDFParallelism {
		return fmt.Errorf("invalid kdf params: parallelism %d exceeds maximum %d", p.Parallelism, MaxKDFParallelism)
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

// WriteMetadata writes metadata to a file. Modes are clamped to ≤0600 (files)
// or ≤0700 (dirs) unless preserveMode is true (NV-007).
func (fh *FileHandler) WriteMetadata(path string, metadata *FileMetadata, preserveMode bool) error {
	if metadata == nil {
		return nil
	}

	mode := os.FileMode(metadata.Mode)
	if !preserveMode {
		mode = ClampPersistedMode(mode, metadata.IsDir)
	}

	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("failed to set file mode: %w", err)
	}

	if err := os.Chtimes(path, metadata.ModTime, metadata.ModTime); err != nil {
		return fmt.Errorf("failed to set file times: %w", err)
	}

	return nil
}

// ClampPersistedMode clears group/other permission bits (and file execute),
// capping files at 0600 and directories at 0700.
func ClampPersistedMode(mode os.FileMode, isDir bool) os.FileMode {
	perm := mode.Perm()
	if isDir {
		perm &= 0o700
	} else {
		perm &= 0o600
	}
	return (mode &^ os.ModePerm) | perm
}

// WriteHeader writes a nokvault header with optional metadata and returns the
// exact bytes written, suitable for use as v3 payload AAD.
func (fh *FileHandler) WriteHeader(writer io.Writer, salt []byte, metadata *FileMetadata, params *crypto.Argon2Params, compress uint8) ([]byte, error) {
	if err := ValidateKDFParams(params); err != nil {
		return nil, err
	}
	if len(salt) != 16 {
		return nil, fmt.Errorf("salt must be 16 bytes")
	}
	if compress > 1 {
		return nil, fmt.Errorf("invalid compress value: %d", compress)
	}

	var metadataJSON []byte
	if metadata != nil {
		var err error
		metadataJSON, err = json.Marshal(metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize metadata: %w", err)
		}
	}

	if len(metadataJSON) > maxMetadataSize {
		return nil, fmt.Errorf("metadata exceeds maximum size of %d bytes", maxMetadataSize)
	}
	// #nosec G115 -- the explicit MaxUint32 bound above makes this conversion safe.
	metadataLength := uint32(len(metadataJSON))
	headerSize := HeaderWireSize(CurrentVersion)
	if headerSize < 0 {
		return nil, fmt.Errorf("unsupported header version: %d", CurrentVersion)
	}
	dataOffset := uint64(headerSize) + uint64(metadataLength)

	var magic [8]byte
	copy(magic[:], NokvaultMagic)
	var saltArr [16]byte
	copy(saltArr[:], salt)

	var wire bytes.Buffer
	writeField := func(value any) error {
		return binary.Write(&wire, binary.LittleEndian, value)
	}
	if err := writeField(magic); err != nil {
		return nil, fmt.Errorf("failed to build header: %w", err)
	}
	if err := writeField(CurrentVersion); err != nil {
		return nil, fmt.Errorf("failed to build header: %w", err)
	}
	if err := writeField(saltArr); err != nil {
		return nil, fmt.Errorf("failed to build header: %w", err)
	}
	if err := writeField(metadataLength); err != nil {
		return nil, fmt.Errorf("failed to build header: %w", err)
	}
	if err := writeField(dataOffset); err != nil {
		return nil, fmt.Errorf("failed to build header: %w", err)
	}
	if err := writeField(params.Memory); err != nil {
		return nil, fmt.Errorf("failed to build header: %w", err)
	}
	if err := writeField(params.Time); err != nil {
		return nil, fmt.Errorf("failed to build header: %w", err)
	}
	if err := writeField(params.Parallelism); err != nil {
		return nil, fmt.Errorf("failed to build header: %w", err)
	}
	pad := [3]byte{}
	if err := writeField(pad); err != nil {
		return nil, fmt.Errorf("failed to build header: %w", err)
	}
	if err := writeField(params.KeyLength); err != nil {
		return nil, fmt.Errorf("failed to build header: %w", err)
	}
	if err := writeField(compress); err != nil {
		return nil, fmt.Errorf("failed to build header: %w", err)
	}
	if err := writeField(pad); err != nil {
		return nil, fmt.Errorf("failed to build header: %w", err)
	}
	wire.Write(metadataJSON)

	aad := append([]byte(nil), wire.Bytes()...)
	n, err := writer.Write(aad)
	if err != nil {
		return nil, fmt.Errorf("failed to write header and metadata: %w", err)
	}
	if n != len(aad) {
		return nil, fmt.Errorf("failed to write header and metadata: %w", io.ErrShortWrite)
	}
	return aad, nil
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
	case Version2, Version3:
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
		if h.Version == Version3 {
			if err := binary.Read(reader, binary.LittleEndian, &h.Compress); err != nil {
				return nil, fmt.Errorf("failed to read header: %w", err)
			}
			var v3Pad [3]byte
			if err := binary.Read(reader, binary.LittleEndian, &v3Pad); err != nil {
				return nil, fmt.Errorf("failed to read header: %w", err)
			}
			if h.Compress > 1 {
				return nil, fmt.Errorf("invalid compress value: %d", h.Compress)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported version: %d", h.Version)
	}

	if h.MetadataSize > maxMetadataSize {
		return nil, fmt.Errorf("metadata size %d exceeds maximum of %d bytes", h.MetadataSize, maxMetadataSize)
	}
	headerSize := HeaderWireSize(h.Version)
	if headerSize < 0 {
		return nil, fmt.Errorf("unsupported version: %d", h.Version)
	}
	expectedDataOffset := uint64(headerSize) + uint64(h.MetadataSize)
	if h.DataOffset != expectedDataOffset {
		return nil, fmt.Errorf("invalid data offset %d (expected %d)", h.DataOffset, expectedDataOffset)
	}
	return h, nil
}

// ReadHeaderWithMetadata reads header and metadata from a file. For v3 it also
// returns the exact consumed header and metadata bytes used as payload AAD.
// Legacy formats return nil AAD.
func (fh *FileHandler) ReadHeaderWithMetadata(reader io.Reader) (*NokvaultHeader, *FileMetadata, []byte, error) {
	var consumed bytes.Buffer
	header, err := fh.ReadHeader(io.TeeReader(reader, &consumed))
	if err != nil {
		return nil, nil, nil, err
	}

	// Read metadata if present
	var metadata *FileMetadata
	if header.MetadataSize > 0 {
		metadataJSON := make([]byte, header.MetadataSize)
		if _, err := io.ReadFull(reader, metadataJSON); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to read metadata: %w", err)
		}
		consumed.Write(metadataJSON)

		metadata = &FileMetadata{}
		if err := json.Unmarshal(metadataJSON, metadata); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to deserialize metadata: %w", err)
		}
	}

	var aad []byte
	if header.Version == Version3 {
		aad = append([]byte(nil), consumed.Bytes()...)
	}
	return header, metadata, aad, nil
}

// EnsureDirectory ensures a directory exists
func (fh *FileHandler) EnsureDirectory(path string) error {
	return os.MkdirAll(path, 0700)
}

// GetRelativePath returns the relative path from base
func (fh *FileHandler) GetRelativePath(base, target string) (string, error) {
	return filepath.Rel(base, target)
}

// CopyFile copies a file from src to dst
func (fh *FileHandler) CopyFile(src, dst string) error {
	// #nosec G304 -- this low-level helper intentionally copies caller-selected paths.
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	// #nosec G304 -- this low-level helper intentionally copies caller-selected paths.
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

// WalkDirectory walks a directory and calls fn for each regular file or
// directory. Existing root components are validated first. Each walk entry is
// checked with ValidateNoSymlinkComponents before a filepath.Walk error is
// returned, so junction/reparse paths classify as SYMLINK_DISALLOWED. Ordinary
// walk errors still propagate when the path is not a redirect.
func (fh *FileHandler) WalkDirectory(root string, fn func(path string, info os.FileInfo, err error) error) error {
	if err := utils.ValidateNoSymlinkComponents(root); err != nil {
		return err
	}
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err := classifyWalkPath(path, err); err != nil {
			return err
		}
		return fn(path, info, nil)
	})
}

func classifyWalkPath(path string, walkErr error) error {
	if err := utils.ValidateNoSymlinkComponents(path); err != nil {
		return err
	}
	return walkErr
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
