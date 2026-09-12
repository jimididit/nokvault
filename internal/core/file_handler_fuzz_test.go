package core

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/jimididit/nokvault/internal/crypto"
)

func FuzzReadHeaderWithMetadata(f *testing.F) {
	v1 := fuzzV1Header()
	v2 := fuzzV2Header()
	v3 := fuzzV3Vault(nil, []byte("known v3 fuzz plaintext"))
	v3Metadata := fuzzV3Vault(&FileMetadata{
		Name:         "evidence.txt",
		Size:         42,
		Mode:         0o600,
		ModTime:      time.Unix(1_700_000_000, 0).UTC(),
		RelativePath: "case/evidence.txt",
	}, []byte("metadata corpus"))
	v4 := fuzzV4Header()

	invalidMetadata := append([]byte(nil), v3...)
	binary.LittleEndian.PutUint32(invalidMetadata[26:30], 1)
	binary.LittleEndian.PutUint64(invalidMetadata[30:38], uint64(HeaderWireSize(Version3)+1))
	invalidMetadata = append(invalidMetadata[:HeaderWireSize(Version3)], '{')

	f.Add(v1)
	f.Add(v2)
	f.Add(v3)
	f.Add(v3Metadata)
	f.Add(v4)
	f.Add(v2[:len(v2)-1])
	f.Add(invalidMetadata)
	f.Add([]byte("not a nokvault file"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2*maxMetadataSize {
			t.Skip()
		}

		header, metadata, _, _, err := NewFileHandler().ReadHeaderWithMetadata(bytes.NewReader(data))
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
		if header.Version == Version4 {
			expectedOffset += uint64(header.RecipientCount) * uint64(crypto.X25519StanzaSize)
		}
		if header.DataOffset != expectedOffset {
			t.Fatalf("data offset %d, expected %d", header.DataOffset, expectedOffset)
		}
		if header.DataOffset > uint64(len(data)) {
			t.Fatalf("successful parse offset %d exceeds input %d", header.DataOffset, len(data))
		}
		// Skip KDF validation for v4 (recipient mode has zero KDF params)
		if header.Version != Version4 {
			if err := ValidateKDFParams(header.Argon2Params()); err != nil {
				t.Fatalf("successful parse returned invalid KDF params: %v", err)
			}
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

	valid := append(fuzzV2Header(), ciphertext...)
	validV3 := fuzzV3Vault(nil, []byte("known v3 fuzz plaintext"))
	truncated := append([]byte(nil), valid[:len(valid)-1]...)
	corrupted := append([]byte(nil), valid...)
	corrupted[len(corrupted)-1] ^= 0xff

	f.Add(valid)
	f.Add(validV3)
	f.Add(truncated)
	f.Add(corrupted)
	f.Add(fuzzV2Header())
	f.Add([]byte("not a nokvault file"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2*maxMetadataSize {
			t.Skip()
		}

		reader := bytes.NewReader(data)
		header, _, aad, _, err := NewFileHandler().ReadHeaderWithMetadata(reader)
		if err != nil {
			return
		}
		if header.DataOffset > uint64(len(data)) {
			return
		}

		_ = service.DecryptVaultPayload(io.Discard, reader, key, header.Version, aad)
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

func fuzzV2Header() []byte {
	var buf bytes.Buffer
	magic := [8]byte{}
	copy(magic[:], NokvaultMagic)
	params := crypto.DefaultArgon2Params()
	mustBinaryWrite(&buf, magic)
	mustBinaryWrite(&buf, Version2)
	mustBinaryWrite(&buf, [16]byte{})
	mustBinaryWrite(&buf, uint32(0))
	mustBinaryWrite(&buf, uint64(HeaderWireSize(Version2)))
	mustBinaryWrite(&buf, params.Memory)
	mustBinaryWrite(&buf, params.Time)
	mustBinaryWrite(&buf, params.Parallelism)
	mustBinaryWrite(&buf, [3]byte{})
	mustBinaryWrite(&buf, params.KeyLength)
	return buf.Bytes()
}

func fuzzV3Vault(metadata *FileMetadata, plaintext []byte) []byte {
	var buf bytes.Buffer
	key := bytes.Repeat([]byte{0x42}, crypto.DefaultKeyLength)
	if err := NewEncryptionService().EncryptVault(
		&buf,
		bytes.NewReader(plaintext),
		key,
		make([]byte, 16),
		metadata,
		0,
	); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func fuzzV4Header() []byte {
	var buf bytes.Buffer
	magic := [8]byte{}
	copy(magic[:], NokvaultMagic)
	mustBinaryWrite(&buf, magic)
	mustBinaryWrite(&buf, Version4)
	mustBinaryWrite(&buf, [16]byte{})           // zero salt
	mustBinaryWrite(&buf, uint32(0))            // zero metadata size
	mustBinaryWrite(&buf, uint64(HeaderWireSize(Version4)+crypto.X25519StanzaSize)) // dataOffset includes 1 stanza
	mustBinaryWrite(&buf, uint32(0))            // zero memory
	mustBinaryWrite(&buf, uint32(0))            // zero time
	mustBinaryWrite(&buf, uint8(0))             // zero parallelism
	mustBinaryWrite(&buf, [3]byte{})            // pad
	mustBinaryWrite(&buf, uint32(crypto.DefaultKeyLength)) // keyLength
	mustBinaryWrite(&buf, uint8(0))             // compress
	mustBinaryWrite(&buf, [3]byte{})            // pad
	mustBinaryWrite(&buf, uint16(1))            // recipientCount
	mustBinaryWrite(&buf, [2]byte{})            // pad2
	// Add one zero stanza (80 bytes)
	buf.Write(make([]byte, crypto.X25519StanzaSize))
	return buf.Bytes()
}

func mustBinaryWrite(buf *bytes.Buffer, value any) {
	if err := binary.Write(buf, binary.LittleEndian, value); err != nil {
		panic(err)
	}
}
