package utils

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func trySymlink(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
}

func requireErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error, got nil", code)
	}
	var nv *NokvaultError
	if !errors.As(err, &nv) {
		t.Fatalf("got %T %v, want *NokvaultError with code %s", err, err, code)
	}
	if nv.Code != code {
		t.Fatalf("got code %q, want %q (err=%v)", nv.Code, code, err)
	}
}

func TestValidateNoSymlinkComponents(t *testing.T) {
	dir := t.TempDir()

	regular := filepath.Join(dir, "regular.txt")
	if err := os.WriteFile(regular, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}

	parent := filepath.Join(dir, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	missingLeaf := filepath.Join(parent, "missing.txt")

	t.Run("regular existing path", func(t *testing.T) {
		if err := ValidateNoSymlinkComponents(regular); err != nil {
			t.Fatalf("ValidateNoSymlinkComponents: %v", err)
		}
	})

	t.Run("missing leaf under regular parents", func(t *testing.T) {
		if err := ValidateNoSymlinkComponents(missingLeaf); err != nil {
			t.Fatalf("ValidateNoSymlinkComponents: %v", err)
		}
	})

	t.Run("symlink leaf", func(t *testing.T) {
		link := filepath.Join(dir, "leaf.link")
		trySymlink(t, regular, link)
		err := ValidateNoSymlinkComponents(link)
		requireErrorCode(t, err, "SYMLINK_DISALLOWED")
		if !strings.Contains(err.Error(), link) {
			t.Fatalf("error %q does not name rejected path %q", err, link)
		}
	})

	t.Run("symlink parent", func(t *testing.T) {
		realDir := filepath.Join(dir, "real-parent")
		if err := os.Mkdir(realDir, 0o700); err != nil {
			t.Fatal(err)
		}
		nested := filepath.Join(realDir, "child.txt")
		if err := os.WriteFile(nested, []byte("ok"), 0o600); err != nil {
			t.Fatal(err)
		}
		linkDir := filepath.Join(dir, "parent.link")
		trySymlink(t, realDir, linkDir)
		throughLink := filepath.Join(linkDir, "child.txt")
		err := ValidateNoSymlinkComponents(throughLink)
		requireErrorCode(t, err, "SYMLINK_DISALLOWED")
		if !strings.Contains(err.Error(), linkDir) {
			t.Fatalf("error %q does not name rejected parent %q", err, linkDir)
		}
	})
}

func TestSafeJoin(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "out")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Run("normal nested safe join", func(t *testing.T) {
		got, err := SafeJoin(root, filepath.Join("nested", "file.txt"))
		if err != nil {
			t.Fatalf("SafeJoin: %v", err)
		}
		want, err := filepath.Abs(filepath.Join(root, "nested", "file.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("absolute relative path", func(t *testing.T) {
		abs := filepath.Join(dir, "elsewhere")
		_, err := SafeJoin(root, abs)
		requireErrorCode(t, err, "PATH_ESCAPE")
	})

	t.Run("dotdot", func(t *testing.T) {
		_, err := SafeJoin(root, "..")
		requireErrorCode(t, err, "PATH_ESCAPE")
	})

	t.Run("nested dotdot", func(t *testing.T) {
		_, err := SafeJoin(root, filepath.Join("nested", "..", "..", "escape"))
		requireErrorCode(t, err, "PATH_ESCAPE")
	})

	t.Run("sibling prefix trap", func(t *testing.T) {
		sibling := filepath.Join(dir, "out-evil")
		if err := os.Mkdir(sibling, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := SafeJoin(root, filepath.Join("..", "out-evil", "secret"))
		requireErrorCode(t, err, "PATH_ESCAPE")
	})

	t.Run("symlinked root", func(t *testing.T) {
		realRoot := filepath.Join(dir, "real-root")
		if err := os.Mkdir(realRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		linkRoot := filepath.Join(dir, "root.link")
		trySymlink(t, realRoot, linkRoot)
		_, err := SafeJoin(linkRoot, "file.txt")
		requireErrorCode(t, err, "SYMLINK_DISALLOWED")
		if !strings.Contains(err.Error(), linkRoot) {
			t.Fatalf("error %q does not name rejected root %q", err, linkRoot)
		}
	})

	t.Run("symlinked output parent", func(t *testing.T) {
		realParent := filepath.Join(dir, "real-out-parent")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		linkParent := filepath.Join(root, "parent.link")
		trySymlink(t, realParent, linkParent)
		_, err := SafeJoin(root, filepath.Join("parent.link", "file.txt"))
		requireErrorCode(t, err, "SYMLINK_DISALLOWED")
		if !strings.Contains(err.Error(), linkParent) {
			t.Fatalf("error %q does not name rejected parent %q", err, linkParent)
		}
	})
}
