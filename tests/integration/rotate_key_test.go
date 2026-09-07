package integration

import (
	"os"
	"path/filepath"
	"testing"
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
	encryptedPath := inputPath + ".nokvault"

	rootCmd := freshRootCmd(t)
	os.Setenv("NOKVAULT_PASSWORD", oldPassword)
	t.Cleanup(func() { os.Unsetenv("NOKVAULT_PASSWORD") })

	rootCmd.SetArgs([]string{"encrypt", inputPath, "--no-prompt"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := os.Stat(encryptedPath); err != nil {
		t.Fatalf("encrypted file missing: %v", err)
	}

	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{
		"rotate-key", encryptedPath,
		"--old-password", oldPassword,
		"--new-password", newPassword,
		"--no-prompt",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rotate-key: %v", err)
	}

	decryptedPath := filepath.Join(tmpDir, "secret.decrypted.txt")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{
		"decrypt", encryptedPath,
		"--password", newPassword,
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
		"--password", oldPassword,
		"--output", failPath,
		"--no-prompt",
	})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected decrypt with old password to fail after rotate")
	}
}
