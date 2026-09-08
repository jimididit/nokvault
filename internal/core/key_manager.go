package core

import (
	"fmt"

	"github.com/jimididit/nokvault/internal/crypto"
)

// KeyManager handles key derivation and management
type KeyManager struct {
	params *crypto.Argon2Params
}

// NewKeyManager creates a new key manager
func NewKeyManager() *KeyManager {
	return &KeyManager{
		params: crypto.DefaultArgon2Params(),
	}
}

// DeriveKeyFromPassword derives an encryption key from a password
func (km *KeyManager) DeriveKeyFromPassword(password []byte) ([]byte, []byte, error) {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	key, err := crypto.DeriveKey(password, salt, km.params)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return key, salt, nil
}

// DeriveKeyFromPasswordAndSalt derives a key from password and existing salt
func (km *KeyManager) DeriveKeyFromPasswordAndSalt(password []byte, salt []byte) ([]byte, error) {
	key, err := crypto.DeriveKey(password, salt, km.params)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	return key, nil
}

// Params returns a copy of the current Argon2 parameters.
func (km *KeyManager) Params() *crypto.Argon2Params {
	if km.params == nil {
		return nil
	}
	p := *km.params
	return &p
}

// SetArgon2Params sets Argon2 parameters from a struct pointer.
func (km *KeyManager) SetArgon2Params(p *crypto.Argon2Params) {
	if p == nil {
		km.params = crypto.DefaultArgon2Params()
		return
	}
	km.params = &crypto.Argon2Params{
		Memory: p.Memory, Time: p.Time, Parallelism: p.Parallelism, KeyLength: p.KeyLength,
	}
}
