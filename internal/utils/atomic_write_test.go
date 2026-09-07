package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWrite_ReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.nokvault")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(path, []byte("new-content"), 0o600); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new-content" {
		t.Fatalf("got %q", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" || len(e.Name()) > 10 && e.Name()[:9] == ".nokvault" {
			// CreateTemp names are .nokvault-*.tmp — ensure none left
			if filepath.Ext(e.Name()) == ".tmp" {
				t.Fatalf("leftover temp file: %s", e.Name())
			}
		}
	}
}

func TestAtomicWriteFunc_WritesViaCallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	err := AtomicWriteFunc(path, 0o600, func(f *os.File) error {
		_, err := f.Write([]byte("callback-data"))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "callback-data" {
		t.Fatalf("got %q", got)
	}
}

func TestAtomicWriteFuncNoReplace_RefusesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := AtomicWriteFuncNoReplace(path, 0o600, func(f *os.File) error {
		_, err := f.Write([]byte("new"))
		return err
	})
	if err == nil {
		t.Fatal("expected existing destination to be refused")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "old" {
		t.Fatalf("existing destination changed: got %q", got)
	}
}

func TestAtomicWriteFuncNoReplace_RefusesDestinationCreatedDuringWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")

	err := AtomicWriteFuncNoReplace(path, 0o600, func(f *os.File) error {
		if _, err := f.Write([]byte("generated")); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("competitor"), 0o600)
	})
	if err == nil {
		t.Fatal("expected concurrently-created destination to be refused")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "competitor" {
		t.Fatalf("concurrently-created destination changed: got %q", got)
	}
}

func TestAtomicWrite_DoesNotReplaceDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "destination")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := AtomicWrite(path, []byte("new"), 0o600); err == nil {
		t.Fatal("expected directory destination to be refused")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("destination directory was removed: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("destination was replaced with a file")
	}
}

func TestSafeWrite_Alias(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "safe.txt")
	if err := SafeWrite(path, []byte("ok")); err != nil {
		t.Fatal(err)
	}
}
