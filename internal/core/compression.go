package core

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
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
		writer.Close()
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
