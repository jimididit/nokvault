package utils

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultVaultOutput_TrailingSlash(t *testing.T) {
	t.Parallel()
	out, err := DefaultVaultOutput("test/")
	if err != nil {
		t.Fatalf("DefaultVaultOutput: %v", err)
	}
	want := "test" + VaultExt
	if out != want {
		t.Fatalf("got %q, want %q", out, want)
	}
}

func TestDefaultVaultOutput_DotSlash(t *testing.T) {
	t.Parallel()
	out, err := DefaultVaultOutput("./test/")
	if err != nil {
		t.Fatalf("DefaultVaultOutput: %v", err)
	}
	want := "test" + VaultExt
	if out != want {
		t.Fatalf("got %q, want %q", out, want)
	}
}

func TestDefaultVaultOutput_RejectsDot(t *testing.T) {
	t.Parallel()
	if _, err := DefaultVaultOutput("."); err == nil {
		t.Fatal("expected error for \".\"")
	}
	if _, err := DefaultVaultOutput(".."); err == nil {
		t.Fatal("expected error for \"..\"")
	}
}

func TestStripVaultExt_Both(t *testing.T) {
	t.Parallel()
	got, ok := StripVaultExt("a.txt" + VaultExt)
	if !ok || got != "a.txt" {
		t.Fatalf("VaultExt: got %q ok=%v", got, ok)
	}
	got, ok = StripVaultExt("a.txt" + LegacyVaultExt)
	if !ok || got != "a.txt" {
		t.Fatalf("LegacyVaultExt: got %q ok=%v", got, ok)
	}
	if _, ok := StripVaultExt("a.txt"); ok {
		t.Fatal("expected false for plain path")
	}
}

func TestIsVaultPath(t *testing.T) {
	t.Parallel()
	if !IsVaultPath(filepath.Join("dir", "f"+VaultExt)) {
		t.Fatal("expected vault path")
	}
	if !IsVaultPath("f" + LegacyVaultExt) {
		t.Fatal("expected legacy vault path")
	}
	if IsVaultPath("f.txt") {
		t.Fatal("plain path should not be vault")
	}
}

func TestDefaultVaultOutput_WindowsSlash(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "windows" {
		t.Skip("windows separators")
	}
	out, err := DefaultVaultOutput(`test\`)
	if err != nil {
		t.Fatalf("DefaultVaultOutput: %v", err)
	}
	if out != "test"+VaultExt {
		t.Fatalf("got %q", out)
	}
}
