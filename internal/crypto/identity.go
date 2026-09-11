package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/jimididit/nokvault/internal/utils"
)

const (
	RecipientHRP = "nokvault"
	IdentityHRP  = "NOKVAULT-SECRET-KEY-"
)

const identityHRPBech32 = "nokvault-secret-key-"

type Identity struct {
	Secret [32]byte
}

type Recipient struct {
	Public [32]byte
}

func GenerateIdentity() (*Identity, *Recipient, error) {
	kp, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	var id Identity
	copy(id.Secret[:], kp.Bytes())
	var rec Recipient
	copy(rec.Public[:], kp.PublicKey().Bytes())
	return &id, &rec, nil
}

func (id Identity) Recipient() *Recipient {
	priv, err := ecdh.X25519().NewPrivateKey(id.Secret[:])
	if err != nil {
		return &Recipient{}
	}
	var rec Recipient
	copy(rec.Public[:], priv.PublicKey().Bytes())
	return &rec
}

func (r Recipient) Encode() (string, error) {
	return bech32Encode(RecipientHRP, r.Public[:])
}

func ParseRecipient(s string) (*Recipient, error) {
	hrp, data, err := bech32Decode(strings.TrimSpace(s))
	if err != nil || hrp != RecipientHRP || len(data) != 32 {
		return nil, fmt.Errorf("invalid nokvault recipient")
	}
	var r Recipient
	copy(r.Public[:], data)
	return &r, nil
}

func (id Identity) Encode() (string, error) {
	s, err := bech32Encode(identityHRPBech32, id.Secret[:])
	if err != nil {
		return "", err
	}
	return strings.ToUpper(s), nil
}

func ParseIdentity(s string) (*Identity, error) {
	s = strings.TrimSpace(s)
	hrp, data, err := bech32Decode(strings.ToLower(s))
	if err != nil || hrp != identityHRPBech32 || len(data) != 32 {
		return nil, fmt.Errorf("invalid nokvault identity")
	}
	var id Identity
	copy(id.Secret[:], data)
	return &id, nil
}

func WriteIdentityFile(path string, id *Identity, force bool) error {
	if err := utils.ValidateNoSymlinkComponents(path); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("identity file already exists: %s (use --force to overwrite)", path)
	}
	encoded, err := id.Encode()
	if err != nil {
		return err
	}
	content := "# nokvault identity\n" + encoded + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return err
	}
	// os.WriteFile preserves existing permissions when overwriting; enforce 0600.
	_ = os.Chmod(path, 0o600)
	return nil
}

func ReadIdentityFile(path string) (*Identity, error) {
	line, err := readSecretLine(path, "identity")
	if err != nil {
		return nil, err
	}
	return ParseIdentity(line)
}

func ReadRecipientFileOrString(s string) (*Recipient, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, RecipientHRP+"1") {
		return ParseRecipient(s)
	}
	line, err := readSecretLine(s, "recipient")
	if err != nil {
		return nil, err
	}
	return ParseRecipient(line)
}

func readSecretLine(path, kind string) (string, error) {
	if err := utils.ValidateNoSymlinkComponents(path); err != nil {
		return "", err
	}

	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("failed to stat %s file: %w", kind, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s file must not be a symlink: %s", kind, path)
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("%s file permissions are too open (got %04o, want 0600 or tighter): %s", kind, info.Mode().Perm(), path)
		}
	}

	// #nosec G304 -- secret files are intentionally user-selected and rejected above unless regular, non-symlink files.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read %s file: %w", kind, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line, nil
	}
	return "", fmt.Errorf("no %s found in file: %s", kind, path)
}
