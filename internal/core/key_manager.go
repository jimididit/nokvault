package core

import (
	"crypto/subtle"
	"fmt"
	"time"

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

// VerifyPassword verifies a password against a derived key (constant-time comparison)
func (km *KeyManager) VerifyPassword(password []byte, salt []byte, expectedKey []byte) bool {
	derivedKey, err := km.DeriveKeyFromPasswordAndSalt(password, salt)
	if err != nil {
		return false
	}

	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(derivedKey, expectedKey) == 1
}

// SetParams sets custom Argon2 parameters
func (km *KeyManager) SetParams(memory uint32, time uint32, parallelism uint8, keyLength uint32) {
	km.params = &crypto.Argon2Params{
		Memory:      memory,
		Time:        time,
		Parallelism: parallelism,
		KeyLength:   keyLength,
	}
}

// CachedKey represents a cached encryption key
type CachedKey struct {
	Key       []byte
	ExpiresAt time.Time
}

// KeyCache manages cached keys with expiration
type KeyCache struct {
	cache map[string]*CachedKey
	ttl   time.Duration
}

// NewKeyCache creates a new key cache
func NewKeyCache(ttl time.Duration) *KeyCache {
	return &KeyCache{
		cache: make(map[string]*CachedKey),
		ttl:   ttl,
	}
}

// Get retrieves a cached key if it exists and hasn't expired
func (kc *KeyCache) Get(keyID string) ([]byte, bool) {
	cached, exists := kc.cache[keyID]
	if !exists {
		return nil, false
	}

	if time.Now().After(cached.ExpiresAt) {
		delete(kc.cache, keyID)
		return nil, false
	}

	return cached.Key, true
}

// Set stores a key in the cache
func (kc *KeyCache) Set(keyID string, key []byte) {
	kc.cache[keyID] = &CachedKey{
		Key:       key,
		ExpiresAt: time.Now().Add(kc.ttl),
	}
}

// Clear removes all cached keys
func (kc *KeyCache) Clear() {
	kc.cache = make(map[string]*CachedKey)
}
