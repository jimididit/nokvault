package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	StreamChunkPlaintextSize = 64 * 1024
	StreamNoncePrefixSize    = 8
	streamLastChunkFlag      = uint32(1 << 31)
)

// EncryptSTREAM encrypts r as an age-style chunked STREAM.
func EncryptSTREAM(w io.Writer, r io.Reader, aead cipher.AEAD, aad []byte) error {
	if err := validateSTREAMAEAD(aead); err != nil {
		return err
	}

	prefix := make([]byte, StreamNoncePrefixSize)
	if _, err := io.ReadFull(rand.Reader, prefix); err != nil {
		return fmt.Errorf("stream nonce: %w", err)
	}
	if err := writeSTREAM(w, prefix); err != nil {
		return fmt.Errorf("write stream nonce: %w", err)
	}

	buf := make([]byte, StreamChunkPlaintextSize)
	var counter uint32
	for {
		n, err := io.ReadFull(r, buf)
		switch err {
		case nil:
			if err := sealSTREAMChunk(w, aead, aad, prefix, counter, buf, false); err != nil {
				return err
			}
			if counter == streamLastChunkFlag-1 {
				return fmt.Errorf("STREAM chunk counter exhausted")
			}
			counter++
		case io.EOF, io.ErrUnexpectedEOF:
			return sealSTREAMChunk(w, aead, aad, prefix, counter, buf[:n], true)
		default:
			return fmt.Errorf("read plaintext: %w", err)
		}
	}
}

func sealSTREAMChunk(
	w io.Writer,
	aead cipher.AEAD,
	aad, prefix []byte,
	counter uint32,
	plain []byte,
	last bool,
) error {
	nonce := make([]byte, NonceSize)
	copy(nonce, prefix)
	if last {
		counter |= streamLastChunkFlag
	}
	binary.BigEndian.PutUint32(nonce[StreamNoncePrefixSize:], counter)

	if err := writeSTREAM(w, aead.Seal(nil, nonce, plain, aad)); err != nil {
		return fmt.Errorf("write ciphertext chunk: %w", err)
	}
	return nil
}

// DecryptSTREAM decrypts an age-style chunked STREAM from r.
func DecryptSTREAM(w io.Writer, r io.Reader, aead cipher.AEAD, aad []byte) error {
	if err := validateSTREAMAEAD(aead); err != nil {
		return err
	}

	prefix := make([]byte, StreamNoncePrefixSize)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return fmt.Errorf("read stream nonce: %w", err)
	}

	sealedSize := StreamChunkPlaintextSize + aead.Overhead()
	buf := make([]byte, sealedSize)
	nonce := make([]byte, NonceSize)
	copy(nonce, prefix)

	var counter uint32
	for {
		n, err := io.ReadFull(r, buf)
		switch err {
		case nil:
			binary.BigEndian.PutUint32(nonce[StreamNoncePrefixSize:], counter)
			plain, openErr := aead.Open(nil, nonce, buf, aad)
			if openErr == nil {
				if len(plain) != StreamChunkPlaintextSize {
					return fmt.Errorf("non-final chunk plaintext length %d", len(plain))
				}
				if err := writeSTREAM(w, plain); err != nil {
					return fmt.Errorf("write plaintext chunk: %w", err)
				}
				if counter == streamLastChunkFlag-1 {
					return fmt.Errorf("STREAM chunk counter exhausted")
				}
				counter++
				continue
			}

			binary.BigEndian.PutUint32(
				nonce[StreamNoncePrefixSize:],
				counter|streamLastChunkFlag,
			)
			plain, lastErr := aead.Open(nil, nonce, buf, aad)
			if lastErr != nil {
				return fmt.Errorf("decrypt chunk: %w", openErr)
			}
			if len(plain) != StreamChunkPlaintextSize {
				return fmt.Errorf("final full chunk plaintext length %d", len(plain))
			}
			if err := writeSTREAM(w, plain); err != nil {
				return fmt.Errorf("write plaintext chunk: %w", err)
			}
			return nil

		case io.EOF:
			return fmt.Errorf("truncated stream: missing final chunk")

		case io.ErrUnexpectedEOF:
			binary.BigEndian.PutUint32(
				nonce[StreamNoncePrefixSize:],
				counter|streamLastChunkFlag,
			)
			plain, openErr := aead.Open(nil, nonce, buf[:n], aad)
			if openErr != nil {
				return fmt.Errorf("decrypt final chunk: %w", openErr)
			}
			if err := writeSTREAM(w, plain); err != nil {
				return fmt.Errorf("write plaintext chunk: %w", err)
			}
			return nil

		default:
			return fmt.Errorf("read ciphertext: %w", err)
		}
	}
}

func validateSTREAMAEAD(aead cipher.AEAD) error {
	if aead == nil {
		return fmt.Errorf("nil AEAD")
	}
	if aead.NonceSize() != NonceSize {
		return fmt.Errorf("unexpected nonce size %d", aead.NonceSize())
	}
	return nil
}

func writeSTREAM(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
