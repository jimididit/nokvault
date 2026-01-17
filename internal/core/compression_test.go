package core

import (
	"bytes"
	"testing"
)

func TestCompressionService_Compress_Decompress(t *testing.T) {
	cs := NewCompressionService()

	originalData := []byte("This is a test string that should compress well because it has repeated patterns. " +
		"This is a test string that should compress well because it has repeated patterns. " +
		"This is a test string that should compress well because it has repeated patterns.")

	// Compress
	compressed, err := cs.Compress(originalData)
	if err != nil {
		t.Fatalf("Compression failed: %v", err)
	}

	if len(compressed) == 0 {
		t.Error("Compressed data should not be empty")
	}

	// Verify compressed data is different from original
	if bytes.Equal(compressed, originalData) {
		t.Error("Compressed data should be different from original")
	}

	// Decompress
	decompressed, err := cs.Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompression failed: %v", err)
	}

	// Verify decompressed matches original
	if !bytes.Equal(decompressed, originalData) {
		t.Errorf("Decompressed data doesn't match original. Expected %d bytes, got %d bytes",
			len(originalData), len(decompressed))
	}
}

func TestCompressionService_Compress_EmptyData(t *testing.T) {
	cs := NewCompressionService()

	emptyData := []byte{}

	compressed, err := cs.Compress(emptyData)
	if err != nil {
		t.Fatalf("Compression of empty data failed: %v", err)
	}

	// Decompress empty data
	decompressed, err := cs.Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompression of empty data failed: %v", err)
	}

	if !bytes.Equal(decompressed, emptyData) {
		t.Error("Decompressed empty data should match original")
	}
}

func TestCompressionService_Decompress_InvalidData(t *testing.T) {
	cs := NewCompressionService()

	invalidData := []byte("This is not compressed data")

	_, err := cs.Decompress(invalidData)
	if err == nil {
		t.Error("Expected error when decompressing invalid data")
	}
}

func TestCompressionService_ShouldCompress(t *testing.T) {
	cs := NewCompressionService()

	tests := []struct {
		name     string
		data     []byte
		minSize  int
		expected bool
	}{
		{
			name:     "Small data below threshold",
			data:     []byte("small"),
			minSize:  100,
			expected: false,
		},
		{
			name:     "Large data above threshold",
			data:     make([]byte, 200),
			minSize:  100,
			expected: true,
		},
		{
			name:     "Already compressed data (gzip magic)",
			data:     []byte{0x1f, 0x8b, 0x08, 0x00},
			minSize:  10,
			expected: false,
		},
		{
			name:     "Data at threshold",
			data:     make([]byte, 100),
			minSize:  100,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cs.ShouldCompress(tt.data, tt.minSize)
			if result != tt.expected {
				t.Errorf("ShouldCompress(%d bytes, minSize=%d) = %v, want %v",
					len(tt.data), tt.minSize, result, tt.expected)
			}
		})
	}
}

func TestCompressionService_RoundTrip(t *testing.T) {
	cs := NewCompressionService()

	testCases := [][]byte{
		[]byte("simple string"),
		[]byte("string with\nnewlines\nand\ttabs"),
		bytes.Repeat([]byte("repeated pattern "), 100),
		make([]byte, 1000), // Large zero-filled data
	}

	for i, original := range testCases {
		t.Run(string(rune(i+'A')), func(t *testing.T) {
			compressed, err := cs.Compress(original)
			if err != nil {
				t.Fatalf("Compression failed: %v", err)
			}

			decompressed, err := cs.Decompress(compressed)
			if err != nil {
				t.Fatalf("Decompression failed: %v", err)
			}

			if !bytes.Equal(decompressed, original) {
				t.Errorf("Round trip failed. Original: %d bytes, Decompressed: %d bytes",
					len(original), len(decompressed))
			}
		})
	}
}
