package integration

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/jimididit/nokvault/internal/core"
	"github.com/jimididit/nokvault/internal/crypto"
)

// TestCLI_RotateKey_RoundTrip encrypts a file, rotates the password, then decrypts
// with the new password. Regression for NV-001 (header salt must match derived key).
func TestCLI_RotateKey_RoundTrip(t *testing.T) {
	oldPassword := "old-password-for-rotate-test"
	newPassword := "new-password-for-rotate-test"

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "secret.txt")
	plaintext := []byte("rotate-key round-trip payload")
	if err := os.WriteFile(inputPath, plaintext, 0600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	encryptedPath := inputPath + ".nokv"

	oldKeyfile := writeTempKeyfile(t, oldPassword)
	newKeyfile := writeTempKeyfile(t, newPassword)

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", inputPath, "--keyfile", oldKeyfile, "--no-prompt"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := os.Stat(encryptedPath); err != nil {
		t.Fatalf("encrypted file missing: %v", err)
	}

	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{
		"rotate-key", encryptedPath,
		"--old-keyfile", oldKeyfile,
		"--new-keyfile", newKeyfile,
		"--no-prompt",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rotate-key: %v", err)
	}

	decryptedPath := filepath.Join(tmpDir, "secret.decrypted.txt")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{
		"decrypt", encryptedPath,
		"--keyfile", newKeyfile,
		"--output", decryptedPath,
		"--no-prompt",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt after rotate with new password: %v", err)
	}

	got, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("plaintext mismatch after rotate: got %q want %q", got, plaintext)
	}

	// Old password must no longer work
	rootCmd = freshRootCmd(t)
	failPath := filepath.Join(tmpDir, "should-fail.txt")
	rootCmd.SetArgs([]string{
		"decrypt", encryptedPath,
		"--keyfile", oldKeyfile,
		"--output", failPath,
		"--no-prompt",
	})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected decrypt with old password to fail after rotate")
	}
}

// TestCLI_RotateKey_LegacyFakeGzipMagic rotates a v1 vault whose plaintext begins with
// gzip magic but is not a valid gzip stream. Rotate must not set Compress=1.
func TestCLI_RotateKey_LegacyFakeGzipMagic(t *testing.T) {
	oldPassword := "old-password-fake-gzip"
	newPassword := "new-password-fake-gzip"
	plaintext := []byte{0x1f, 0x8b, 'n', 'o', 't', ' ', 'g', 'z', 'i', 'p'}

	tmpDir := t.TempDir()
	encryptedPath := filepath.Join(tmpDir, "fake-gzip.nokv")
	if err := writeLegacyV1Vault(t, encryptedPath, oldPassword, plaintext); err != nil {
		t.Fatalf("write legacy vault: %v", err)
	}

	oldKeyfile := writeTempKeyfile(t, oldPassword)
	newKeyfile := writeTempKeyfile(t, newPassword)

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{
		"rotate-key", encryptedPath,
		"--old-keyfile", oldKeyfile,
		"--new-keyfile", newKeyfile,
		"--no-prompt",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rotate-key: %v", err)
	}

	header, err := readVaultHeader(t, encryptedPath)
	if err != nil {
		t.Fatalf("read rotated header: %v", err)
	}
	if header.Compress != 0 {
		t.Fatalf("expected Compress=0 for fake gzip magic, got %d", header.Compress)
	}

	decryptedPath := filepath.Join(tmpDir, "fake-gzip.out")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{
		"decrypt", encryptedPath,
		"--keyfile", newKeyfile,
		"--output", decryptedPath,
		"--no-prompt",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt after rotate: %v", err)
	}

	got, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
	}
}

func writeLegacyV1Vault(t *testing.T, path, password string, plaintext []byte) error {
	t.Helper()

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}

	km := core.NewKeyManager()
	km.SetArgon2Params(crypto.DefaultArgon2Params())
	key, err := km.DeriveKeyFromPasswordAndSalt([]byte(password), salt)
	if err != nil {
		return err
	}

	es := core.NewEncryptionService()
	ciphertext, err := es.EncryptData(plaintext, key)
	if err != nil {
		return err
	}

	var headerBuf bytes.Buffer
	magic := [8]byte{}
	copy(magic[:], core.NokvaultMagic)
	if err := binary.Write(&headerBuf, binary.LittleEndian, magic); err != nil {
		return err
	}
	if err := binary.Write(&headerBuf, binary.LittleEndian, uint16(1)); err != nil {
		return err
	}
	var saltArr [16]byte
	copy(saltArr[:], salt)
	if err := binary.Write(&headerBuf, binary.LittleEndian, saltArr); err != nil {
		return err
	}
	if err := binary.Write(&headerBuf, binary.LittleEndian, uint32(0)); err != nil {
		return err
	}
	v1Size := core.HeaderWireSize(1)
	if err := binary.Write(&headerBuf, binary.LittleEndian, uint64(v1Size)); err != nil {
		return err
	}

	var fileBuf bytes.Buffer
	fileBuf.Write(headerBuf.Bytes())
	fileBuf.Write(ciphertext)

	return os.WriteFile(path, fileBuf.Bytes(), 0o600)
}

func readVaultHeader(t *testing.T, path string) (*core.NokvaultHeader, error) {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fh := core.NewFileHandler()
	header, _, _, err := fh.ReadHeaderWithMetadata(f)
	return header, err
}
