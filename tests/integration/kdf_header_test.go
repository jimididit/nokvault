package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jimididit/nokvault/internal/cli"
	"github.com/jimididit/nokvault/internal/config"
	"github.com/jimididit/nokvault/internal/core"
)

func TestCLI_EncryptDecrypt_CustomKDFParams(t *testing.T) {
	password := "custom-kdf-test-password"

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "secret.txt")
	plaintext := []byte("custom kdf params round-trip payload")
	if err := os.WriteFile(inputPath, plaintext, 0600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	encryptedPath := inputPath + ".nokvault"

	rootCmd := freshRootCmd(t)
	cfg := config.DefaultConfig()
	cfg.KeyDerivation.MemoryCost = 32768
	cfg.KeyDerivation.TimeCost = 2
	cfg.KeyDerivation.Parallelism = 2
	cli.SetRuntimeConfig(cfg)
	defer cli.ClearRuntimeConfig()

	os.Setenv("NOKVAULT_PASSWORD", password)
	t.Cleanup(func() { os.Unsetenv("NOKVAULT_PASSWORD") })

	rootCmd.SetArgs([]string{"encrypt", inputPath, "--no-prompt"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := os.Stat(encryptedPath); err != nil {
		t.Fatalf("encrypted file missing: %v", err)
	}

	encFile, err := os.Open(encryptedPath)
	if err != nil {
		t.Fatalf("open encrypted: %v", err)
	}
	defer encFile.Close()

	fh := core.NewFileHandler()
	header, _, err := fh.ReadHeaderWithMetadata(encFile)
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if header.Version != core.Version2 {
		t.Fatalf("expected header version 2, got %d", header.Version)
	}
	if header.Memory != 32768 {
		t.Fatalf("expected Memory=32768 in header, got %d", header.Memory)
	}
	if header.Time != 2 {
		t.Fatalf("expected Time=2 in header, got %d", header.Time)
	}
	if header.Parallelism != 2 {
		t.Fatalf("expected Parallelism=2 in header, got %d", header.Parallelism)
	}

	differentCfg := config.DefaultConfig()
	differentCfg.KeyDerivation.MemoryCost = 65536
	differentCfg.KeyDerivation.TimeCost = 4
	differentCfg.KeyDerivation.Parallelism = 8
	cli.SetRuntimeConfig(differentCfg)

	decryptedPath := filepath.Join(tmpDir, "secret.decrypted.txt")
	rootCmd = freshRootCmd(t)
	cli.SetRuntimeConfig(differentCfg)

	rootCmd.SetArgs([]string{
		"decrypt", encryptedPath,
		"--output", decryptedPath,
		"--no-prompt",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt with mismatched runtime config: %v", err)
	}

	got, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
	}
}
