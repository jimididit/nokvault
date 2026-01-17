package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// Default Argon2 parameters
	DefaultMemory      = 64 * 1024 // 64 MB
	DefaultTime        = 3
	DefaultParallelism = 4
	DefaultKeyLength   = 32 // 32 bytes = 256 bits
	SaltLength         = 16 // 16 bytes for salt
)

// Argon2Params holds Argon2 key derivation parameters
type Argon2Params struct {
	Memory      uint32
	Time        uint32
	Parallelism uint8
	KeyLength   uint32
}

// DefaultArgon2Params returns default Argon2 parameters
func DefaultArgon2Params() *Argon2Params {
	return &Argon2Params{
		Memory:      DefaultMemory,
		Time:        DefaultTime,
		Parallelism: DefaultParallelism,
		KeyLength:   DefaultKeyLength,
	}
}

// DeriveKey derives a key from a password using Argon2id
func DeriveKey(password []byte, salt []byte, params *Argon2Params) ([]byte, error) {
	if len(salt) != SaltLength {
		return nil, fmt.Errorf("invalid salt length: expected %d, got %d", SaltLength, len(salt))
	}

	key := argon2.IDKey(password, salt, params.Time, params.Memory, params.Parallelism, params.KeyLength)
	return key, nil
}

// GenerateSalt generates a random salt
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// ConstantTimeCompare compares two byte slices in constant time
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// EncodeSalt encodes salt to base64 string
func EncodeSalt(salt []byte) string {
	return base64.StdEncoding.EncodeToString(salt)
}

// DecodeSalt decodes salt from base64 string
func DecodeSalt(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
