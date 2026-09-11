package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func testAEAD(t *testing.T) cipher.AEAD {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return aead
}

func roundTrip(t *testing.T, plain, aad []byte) {
	t.Helper()
	aead := testAEAD(t)
	var enc bytes.Buffer
	require.NoError(t, EncryptSTREAM(&enc, bytes.NewReader(plain), aead, aad))
	var dec bytes.Buffer
	require.NoError(t, DecryptSTREAM(&dec, bytes.NewReader(enc.Bytes()), aead, aad))
	require.Equal(t, plain, dec.Bytes())
}

func TestSTREAM_Empty(t *testing.T)      { roundTrip(t, nil, nil) }
func TestSTREAM_OneByte(t *testing.T)    { roundTrip(t, []byte{0x42}, []byte("aad")) }
func TestSTREAM_ExactChunk(t *testing.T) { roundTrip(t, make([]byte, StreamChunkPlaintextSize), nil) }
func TestSTREAM_ChunkPlusOne(t *testing.T) {
	roundTrip(t, make([]byte, StreamChunkPlaintextSize+1), []byte{1, 2, 3})
}
func TestSTREAM_AADMismatchFails(t *testing.T) {
	aead := testAEAD(t)
	plain := []byte("hello")
	var enc bytes.Buffer
	require.NoError(t, EncryptSTREAM(&enc, bytes.NewReader(plain), aead, []byte("aad-a")))
	var dec bytes.Buffer
	err := DecryptSTREAM(&dec, bytes.NewReader(enc.Bytes()), aead, []byte("aad-b"))
	require.Error(t, err)
}
func TestSTREAM_TruncatedFails(t *testing.T) {
	aead := testAEAD(t)
	var enc bytes.Buffer
	require.NoError(t, EncryptSTREAM(&enc, bytes.NewReader(make([]byte, 100)), aead, nil))
	raw := enc.Bytes()
	require.Greater(t, len(raw), 10)
	var dec bytes.Buffer
	require.Error(t, DecryptSTREAM(&dec, bytes.NewReader(raw[:len(raw)/2]), aead, nil))
}

func TestSTREAM_WireLength(t *testing.T) {
	tests := []struct {
		name string
		size int
		want int
	}{
		{
			name: "empty",
			size: 0,
			want: StreamNoncePrefixSize + GCMTagSize,
		},
		{
			name: "exact chunk",
			size: StreamChunkPlaintextSize,
			want: StreamNoncePrefixSize +
				StreamChunkPlaintextSize + GCMTagSize +
				GCMTagSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aead := testAEAD(t)
			var enc bytes.Buffer
			require.NoError(t, EncryptSTREAM(
				&enc,
				io.LimitReader(bytes.NewReader(make([]byte, tt.size)), int64(tt.size)),
				aead,
				nil,
			))
			require.Len(t, enc.Bytes(), tt.want)
		})
	}
}
