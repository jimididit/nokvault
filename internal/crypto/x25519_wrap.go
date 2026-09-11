package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	X25519StanzaSize = 80
	MaxRecipients    = 20
	X25519HKDFInfo   = "nokvault.org/v4/X25519"
)

type X25519Stanza struct {
	EphemeralPK [32]byte
	Body        [48]byte
}

func WrapFileKey(fileKey []byte, recipients []*Recipient) ([]X25519Stanza, error) {
	if len(fileKey) != 32 {
		return nil, fmt.Errorf("file key must be 32 bytes")
	}
	if len(recipients) == 0 || len(recipients) > MaxRecipients {
		return nil, fmt.Errorf("recipient count must be 1..%d", MaxRecipients)
	}
	out := make([]X25519Stanza, 0, len(recipients))
	for _, r := range recipients {
		eph, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		peer, err := ecdh.X25519().NewPublicKey(r.Public[:])
		if err != nil {
			return nil, err
		}
		shared, err := eph.ECDH(peer)
		if err != nil {
			return nil, err
		}
		if isAllZero(shared) {
			return nil, errors.New("invalid X25519 shared secret")
		}
		wrapKey, err := deriveWrapKey(shared, eph.PublicKey().Bytes(), r.Public[:])
		if err != nil {
			return nil, err
		}
		aead, err := chacha20poly1305.New(wrapKey)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, chacha20poly1305.NonceSize) // 12 zero bytes
		body := aead.Seal(nil, nonce, fileKey, nil)
		var st X25519Stanza
		copy(st.EphemeralPK[:], eph.PublicKey().Bytes())
		copy(st.Body[:], body)
		out = append(out, st)
	}
	return out, nil
}

func UnwrapFileKey(stanzas []X25519Stanza, identities []*Identity) ([]byte, error) {
	for _, id := range identities {
		priv, err := ecdh.X25519().NewPrivateKey(id.Secret[:])
		if err != nil {
			continue
		}
		for _, st := range stanzas {
			ephPub, err := ecdh.X25519().NewPublicKey(st.EphemeralPK[:])
			if err != nil {
				continue
			}
			shared, err := priv.ECDH(ephPub)
			if err != nil || isAllZero(shared) {
				continue
			}
			rec := id.Recipient()
			wrapKey, err := deriveWrapKey(shared, st.EphemeralPK[:], rec.Public[:])
			if err != nil {
				continue
			}
			aead, err := chacha20poly1305.New(wrapKey)
			if err != nil {
				continue
			}
			nonce := make([]byte, chacha20poly1305.NonceSize)
			pt, err := aead.Open(nil, nonce, st.Body[:], nil)
			if err != nil || len(pt) != 32 {
				continue
			}
			out := make([]byte, 32)
			copy(out, pt)
			return out, nil
		}
	}
	return nil, errors.New("no identity could decrypt this vault")
}

func deriveWrapKey(shared, ephPK, recipientPK []byte) ([]byte, error) {
	salt := append(append([]byte{}, ephPK...), recipientPK...)
	r := hkdf.New(sha256.New, shared, salt, []byte(X25519HKDFInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func MarshalStanzas(stanzas []X25519Stanza) []byte {
	out := make([]byte, 0, len(stanzas)*X25519StanzaSize)
	for _, st := range stanzas {
		out = append(out, st.EphemeralPK[:]...)
		out = append(out, st.Body[:]...)
	}
	return out
}

func ParseStanzas(section []byte, count int) ([]X25519Stanza, error) {
	if count < 1 || count > MaxRecipients {
		return nil, fmt.Errorf("invalid recipient count %d", count)
	}
	if len(section) != count*X25519StanzaSize {
		return nil, fmt.Errorf("recipient section size mismatch")
	}
	out := make([]X25519Stanza, count)
	for i := 0; i < count; i++ {
		off := i * X25519StanzaSize
		copy(out[i].EphemeralPK[:], section[off:off+32])
		copy(out[i].Body[:], section[off+32:off+80])
	}
	return out, nil
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
