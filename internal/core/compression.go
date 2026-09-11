package core

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
)

// CompressionService handles compression/decompression
type CompressionService struct {
}

// NewCompressionService creates a new compression service
func NewCompressionService() *CompressionService {
	return &CompressionService{}
}

// Compress compresses data using gzip
func (cs *CompressionService) Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)

	if _, err := writer.Write(data); err != nil {
		if closeErr := writer.Close(); closeErr != nil {
			return nil, fmt.Errorf("failed to write compressed data: %w (close error: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("failed to write compressed data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close compressor: %w", err)
	}

	return buf.Bytes(), nil
}

// Decompress decompresses gzip data
func (cs *CompressionService) Decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create decompressor: %w", err)
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress data: %w", err)
	}

	return decompressed, nil
}

// ShouldCompress determines if compression should be used based on data size and type
func (cs *CompressionService) ShouldCompress(data []byte, minSize int) bool {
	// Only compress if data is larger than minimum size
	if len(data) < minSize {
		return false
	}

	// Check if data is already compressed (heuristic: check for gzip magic number)
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return false
	}

	return true
}

// ShouldCompressFile determines if a file should be compressed based on size and gzip magic peek.
func (cs *CompressionService) ShouldCompressFile(path string, minSize int) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("failed to stat file: %w", err)
	}

	if info.Size() < int64(minSize) {
		return false, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	header := make([]byte, 2)
	n, err := f.Read(header)
	if err != nil && err != io.EOF {
		return false, fmt.Errorf("failed to peek file header: %w", err)
	}

	if n >= 2 && header[0] == 0x1f && header[1] == 0x8b {
		return false, nil
	}

	return true, nil
}

// GzipWriter returns a streaming gzip writer for the given destination.
func (cs *CompressionService) GzipWriter(w io.Writer) *gzip.Writer {
	return gzip.NewWriter(w)
}

// GzipReader returns a streaming gzip reader for the given source.
func (cs *CompressionService) GzipReader(r io.Reader) (*gzip.Reader, error) {
	return gzip.NewReader(r)
}
