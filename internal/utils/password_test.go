package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGetPassword_RefusesPasswordFlag(t *testing.T) {
	t.Setenv("NOKVAULT_PASSWORD", "")
	_, err := GetPassword("secret-on-argv", "", true, false)
	if err == nil {
		t.Fatal("expected error when password flag is set")
	}
	if err != ErrPasswordFlagRefused {
		t.Fatalf("got %v, want ErrPasswordFlagRefused", err)
	}
}

func TestGetPassword_FlagRefusedEvenWithKeyfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("from-keyfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := GetPassword("still-on-argv", path, true, false)
	if err != ErrPasswordFlagRefused {
		t.Fatalf("got %v, want ErrPasswordFlagRefused", err)
	}
}

func TestGetPassword_FromKeyfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("from-keyfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := GetPassword("", path, true, false)
	if err != nil {
		t.Fatalf("GetPassword: %v", err)
	}
	if string(got) != "from-keyfile" {
		t.Fatalf("got %q", got)
	}
}

func TestGetPassword_KeyfileRejectsOpenPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits not enforced on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := GetPassword("", path, true, false)
	if err == nil {
		t.Fatal("expected error for world-readable keyfile")
	}
}

func TestGetPassword_KeyfileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	_, err := GetPassword("", link, true, false)
	if err == nil {
		t.Fatal("expected error for symlink keyfile")
	}
}

func TestGetPassword_FromEnv(t *testing.T) {
	t.Setenv("NOKVAULT_PASSWORD", "env-secret")
	got, err := GetPassword("", "", true, false)
	if err != nil {
		t.Fatalf("GetPassword: %v", err)
	}
	if string(got) != "env-secret" {
		t.Fatalf("got %q", got)
	}
}
