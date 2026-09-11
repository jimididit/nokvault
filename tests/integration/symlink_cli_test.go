package integration

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/jimididit/nokvault/internal/utils"
)

func isLinkCreationUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case 1314, 1, 50:
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "privilege") ||
		strings.Contains(msg, "not supported") ||
		strings.Contains(msg, "a required privilege is not held")
}

func trySymlink(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		if isLinkCreationUnavailable(err) {
			t.Skipf("symlink privilege/support unavailable: %v", err)
		}
		t.Fatalf("symlink creation failed: %v", err)
	}
}

func requireSymlinkDisallowed(t *testing.T, err error, link string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected SYMLINK_DISALLOWED, got nil")
	}
	var nv *utils.NokvaultError
	if !errors.As(err, &nv) {
		t.Fatalf("got %T %v, want *NokvaultError SYMLINK_DISALLOWED", err, err)
	}
	if nv.Code != "SYMLINK_DISALLOWED" {
		t.Fatalf("got code %q, want SYMLINK_DISALLOWED (err=%v)", nv.Code, err)
	}
	if !strings.Contains(err.Error(), link) {
		t.Fatalf("error %q should name rejected path %s", err, link)
	}
}

func TestCLI_Encrypt_RejectsSymlinkInput(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "input-link.txt")
	trySymlink(t, target, link)

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", link, "--dry-run"})
	requireSymlinkDisallowed(t, rootCmd.Execute(), link)
}

func TestCLI_Encrypt_RejectsSymlinkOutput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(input, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "out-target.txt")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	outLink := filepath.Join(dir, "out-link.txt")
	trySymlink(t, target, outLink)

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", input, "--output", outLink, "--dry-run"})
	requireSymlinkDisallowed(t, rootCmd.Execute(), outLink)

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" {
		t.Fatalf("output target changed: %q", got)
	}
}

func TestCLI_Decrypt_RejectsSymlinkOutput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "cipher.nokv")
	if err := os.WriteFile(input, []byte("not-a-real-cipher"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "out-target.txt")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	outLink := filepath.Join(dir, "out-link.txt")
	trySymlink(t, target, outLink)

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"decrypt", input, "--output", outLink, "--dry-run"})
	requireSymlinkDisallowed(t, rootCmd.Execute(), outLink)

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" {
		t.Fatalf("output target changed: %q", got)
	}
}

func TestCLI_RotateKey_RejectsSymlinkInput(t *testing.T) {
	t.Setenv("NOKVAULT_PASSWORD", "")
	dir := t.TempDir()
	target := filepath.Join(dir, "cipher.nokv")
	if err := os.WriteFile(target, []byte("not-a-real-cipher"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "rotate-link.nokv")
	trySymlink(t, target, link)

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"rotate-key", link, "--no-prompt"})
	err := rootCmd.Execute()
	requireSymlinkDisallowed(t, err, link)
	if strings.Contains(err.Error(), "no password provided") {
		t.Fatalf("rotate-key checked password before symlink policy: %v", err)
	}
}

func TestCLI_SecureDelete_RejectsSymlinkPreservesLinkAndTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("must-survive"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "delete-link.txt")
	trySymlink(t, target, link)

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"secure-delete", link, "--yes"})
	requireSymlinkDisallowed(t, rootCmd.Execute(), link)

	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("symlink was removed: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected symlink to remain: %s", link)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("target was removed or unreadable: %v", err)
	}
	if string(got) != "must-survive" {
		t.Fatalf("target contents changed: %q", got)
	}
}
