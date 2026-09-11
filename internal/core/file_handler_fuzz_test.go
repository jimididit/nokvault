package core

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/jimididit/nokvault/internal/crypto"
)

func FuzzReadHeaderWithMetadata(f *testing.F) {
	v1 := fuzzV1Header()
	v2 := fuzzV2Header(nil)
	v2Metadata := fuzzV2Header(&FileMetadata{
		Name:         "evidence.txt",
		Size:         42,
		Mode:         0o600,
		ModTime:      time.Unix(1_700_000_000, 0).UTC(),
		RelativePath: "case/evidence.txt",
	})

	invalidMetadata := append([]byte(nil), v2...)
	binary.LittleEndian.PutUint32(invalidMetadata[26:30], 1)
	binary.LittleEndian.PutUint64(invalidMetadata[30:38], uint64(HeaderWireSize(Version3)+1))
	invalidMetadata = append(invalidMetadata, '{')

	f.Add(v1)
	f.Add(v2)
	f.Add(v2Metadata)
	f.Add(v2[:len(v2)-1])
	f.Add(invalidMetadata)
	f.Add([]byte("not a nokvault file"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2*maxMetadataSize {
			t.Skip()
		}

		header, metadata, err := NewFileHandler().ReadHeaderWithMetadata(bytes.NewReader(data))
		if err != nil {
			return
		}

		if string(header.Magic[:]) != NokvaultMagic {
			t.Fatalf("successful parse returned invalid magic %q", header.Magic)
		}
		headerSize := HeaderWireSize(header.Version)
		if headerSize < 0 {
			t.Fatalf("successful parse returned unknown version %d", header.Version)
		}
		if header.MetadataSize > maxMetadataSize {
			t.Fatalf("metadata size %d exceeds limit", header.MetadataSize)
		}
		expectedOffset := uint64(headerSize) + uint64(header.MetadataSize)
		if header.DataOffset != expectedOffset {
			t.Fatalf("data offset %d, expected %d", header.DataOffset, expectedOffset)
		}
		if header.DataOffset > uint64(len(data)) {
			t.Fatalf("successful parse offset %d exceeds input %d", header.DataOffset, len(data))
		}
		if err := ValidateKDFParams(header.Argon2Params()); err != nil {
			t.Fatalf("successful parse returned invalid KDF params: %v", err)
		}
		if header.MetadataSize == 0 && metadata != nil {
			t.Fatal("metadata returned when encoded size is zero")
		}
		if header.MetadataSize > 0 && metadata == nil {
			t.Fatal("metadata missing when encoded size is non-zero")
		}
	})
}

func FuzzEncryptedContainer(f *testing.F) {
	key := bytes.Repeat([]byte{0x42}, crypto.DefaultKeyLength)
	service := NewEncryptionService()
	ciphertext, err := service.EncryptData([]byte("known fuzz plaintext"), key)
	if err != nil {
		panic(err)
	}

	valid := append(fuzzV2Header(nil), ciphertext...)
	truncated := append([]byte(nil), valid[:len(valid)-1]...)
	corrupted := append([]byte(nil), valid...)
	corrupted[len(corrupted)-1] ^= 0xff

	f.Add(valid)
	f.Add(truncated)
	f.Add(corrupted)
	f.Add(fuzzV2Header(nil))
	f.Add([]byte("not a nokvault file"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2*maxMetadataSize {
			t.Skip()
		}

		header, _, err := NewFileHandler().ReadHeaderWithMetadata(bytes.NewReader(data))
		if err != nil {
			return
		}
		if header.DataOffset > uint64(len(data)) {
			return
		}

		_, _ = service.DecryptData(data[int(header.DataOffset):], key)
	})
}

func fuzzV1Header() []byte {
	var buf bytes.Buffer
	magic := [8]byte{}
	copy(magic[:], NokvaultMagic)
	mustBinaryWrite(&buf, magic)
	mustBinaryWrite(&buf, Version1)
	mustBinaryWrite(&buf, [16]byte{})
	mustBinaryWrite(&buf, uint32(0))
	mustBinaryWrite(&buf, uint64(HeaderWireSize(Version1)))
	return buf.Bytes()
}

func fuzzV2Header(metadata *FileMetadata) []byte {
	var buf bytes.Buffer
	if _, err := NewFileHandler().WriteHeader(&buf, make([]byte, 16), metadata, crypto.DefaultArgon2Params(), 0); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func mustBinaryWrite(buf *bytes.Buffer, value any) {
	if err := binary.Write(buf, binary.LittleEndian, value); err != nil {
		panic(err)
	}
}
