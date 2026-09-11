package core

import (
	"fmt"
	"io"
	"testing"

	"github.com/jimididit/nokvault/internal/crypto"
	"github.com/stretchr/testify/require"
)

type boundedReadRequestReader struct {
	remaining int64
	maxRead   int
	readCalls int
}

func (r *boundedReadRequestReader) Read(p []byte) (int, error) {
	r.readCalls++
	if len(p) > r.maxRead {
		return 0, fmt.Errorf("oversized read request: got %d bytes, max %d", len(p), r.maxRead)
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}

	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	for i := 0; i < n; i++ {
		p[i] = byte(i)
	}
	r.remaining -= int64(n)
	return n, nil
}

func TestEncryptVault_StreamsLargeReaderInBoundedChunks(t *testing.T) {
	const plaintextSize = 8 * 1024 * 1024
	reader := &boundedReadRequestReader{
		remaining: plaintextSize,
		maxRead:   crypto.StreamChunkPlaintextSize,
	}

	err := NewEncryptionService().EncryptVault(
		io.Discard,
		reader,
		make([]byte, crypto.DefaultKeyLength),
		make([]byte, 16),
		&FileMetadata{Name: "large.bin", Size: plaintextSize},
		0,
	)

	require.NoError(t, err)
	require.Zero(t, reader.remaining)
	require.Greater(t, reader.readCalls, 1)
}
