package integration

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCLI_Decrypt_ClampsRestoredMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission clamping not observable on Windows")
	}

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "secret.txt")
	content := []byte("mode clamp payload")
	if err := os.WriteFile(inputPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	keyfile := writeTempKeyfile(t, "mode-clamp-password")
	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", inputPath, "--keyfile", keyfile, "--no-prompt"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	encrypted := inputPath + ".nokvault"
	decrypted := filepath.Join(tmpDir, "out.txt")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{
		"decrypt", encrypted,
		"--keyfile", keyfile,
		"--output", decrypted,
		"--no-prompt",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	info, err := os.Stat(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected clamped mode 0600, got %04o", info.Mode().Perm())
	}

	// With --preserve-mode, original 0644 should return
	decrypted2 := filepath.Join(tmpDir, "out-preserve.txt")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{
		"decrypt", encrypted,
		"--keyfile", keyfile,
		"--output", decrypted2,
		"--preserve-mode",
		"--no-prompt",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("decrypt preserve: %v", err)
	}
	info2, err := os.Stat(decrypted2)
	if err != nil {
		t.Fatal(err)
	}
	if info2.Mode().Perm() != 0o644 {
		t.Fatalf("expected preserved mode 0644, got %04o", info2.Mode().Perm())
	}
}
