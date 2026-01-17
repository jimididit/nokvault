package core

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompressionService_Compress_Decompress(t *testing.T) {
	cs := NewCompressionService()

	originalData := []byte("This is a test string that should compress well because it has repeated patterns. " +
		"This is a test string that should compress well because it has repeated patterns. " +
		"This is a test string that should compress well because it has repeated patterns.")

	// Compress
	compressed, err := cs.Compress(originalData)
	require.NoError(t, err, "Compression should succeed")

	assert.NotEmpty(t, compressed, "Compressed data should not be empty")
	assert.NotEqual(t, originalData, compressed, "Compressed data should be different from original")

	// Decompress
	decompressed, err := cs.Decompress(compressed)
	require.NoError(t, err, "Decompression should succeed")

	// Verify decompressed matches original
	assert.Equal(t, originalData, decompressed, "Decompressed data should match original")
}

func TestCompressionService_Compress_EmptyData(t *testing.T) {
	cs := NewCompressionService()

	emptyData := []byte{}

	compressed, err := cs.Compress(emptyData)
	require.NoError(t, err, "Compression of empty data should succeed")

	// Decompress empty data
	decompressed, err := cs.Decompress(compressed)
	require.NoError(t, err, "Decompression of empty data should succeed")

	assert.Equal(t, emptyData, decompressed, "Decompressed empty data should match original")
}

func TestCompressionService_Decompress_InvalidData(t *testing.T) {
	cs := NewCompressionService()

	invalidData := []byte("This is not compressed data")

	_, err := cs.Decompress(invalidData)
	assert.Error(t, err, "Expected error when decompressing invalid data")
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
			assert.Equal(t, tt.expected, result, "ShouldCompress result should match expected")
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
			require.NoError(t, err, "Compression should succeed")

			decompressed, err := cs.Decompress(compressed)
			require.NoError(t, err, "Decompression should succeed")

			assert.Equal(t, original, decompressed, "Round trip should preserve original data")
		})
	}
}
