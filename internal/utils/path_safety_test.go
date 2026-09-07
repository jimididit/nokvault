package utils

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func isLinkCreationUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case 1314: // ERROR_PRIVILEGE_NOT_HELD
			return true
		case 1: // ERROR_INVALID_FUNCTION
			return true
		case 50: // ERROR_NOT_SUPPORTED
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

func tryJunction(t *testing.T, oldname, newname string) {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("junctions are a Windows reparse feature")
	}
	out, err := exec.Command("cmd", "/c", "mklink", "/J", newname, oldname).CombinedOutput()
	if err != nil {
		msg := strings.ToLower(string(out) + err.Error())
		if isLinkCreationUnavailable(err) ||
			strings.Contains(msg, "privilege") ||
			strings.Contains(msg, "not supported") ||
			strings.Contains(msg, "cannot create") {
			t.Skipf("junction creation unavailable: %v: %s", err, out)
		}
		t.Fatalf("junction creation failed: %v: %s", err, out)
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
		var nv *NokvaultError
		if !errors.As(err, &nv) {
			t.Fatalf("got %T", err)
		}
		if !strings.Contains(nv.GetHint(), "Symlinks are not followed.") {
			t.Fatalf("hint %q is not the full symlink hint", nv.GetHint())
		}
	})

	t.Run("windows junction", func(t *testing.T) {
		realDir := filepath.Join(dir, "junction-target")
		if err := os.Mkdir(realDir, 0o700); err != nil {
			t.Fatal(err)
		}
		junction := filepath.Join(dir, "junction.link")
		tryJunction(t, realDir, junction)
		err := ValidateNoSymlinkComponents(filepath.Join(junction, "child.txt"))
		requireErrorCode(t, err, "SYMLINK_DISALLOWED")
		if !strings.Contains(err.Error(), junction) {
			t.Fatalf("error %q does not name rejected junction %q", err, junction)
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

	t.Run("reserved device names", func(t *testing.T) {
		for _, rel := range []string{"NUL", "CON", "COM1", filepath.Join("nested", "NUL")} {
			_, err := SafeJoin(root, rel)
			requireErrorCode(t, err, "PATH_ESCAPE")
		}
	})

	t.Run("non-local relative", func(t *testing.T) {
		_, err := SafeJoin(root, filepath.Join("foo", "..", "..", "outside"))
		requireErrorCode(t, err, "PATH_ESCAPE")
	})

	t.Run("rooted backslash", func(t *testing.T) {
		_, err := SafeJoin(root, `\outside`)
		requireErrorCode(t, err, "PATH_ESCAPE")
	})

	t.Run("drive-relative", func(t *testing.T) {
		if runtime.GOOS != "windows" {
			t.Skip("drive-relative volumes are a Windows path form")
		}
		_, err := SafeJoin(root, `C:windows`)
		requireErrorCode(t, err, "PATH_ESCAPE")
	})

	t.Run("volume-qualified", func(t *testing.T) {
		if runtime.GOOS != "windows" {
			t.Skip("volume-qualified paths are a Windows path form")
		}
		_, err := SafeJoin(root, `\\?\C:\Windows`)
		requireErrorCode(t, err, "PATH_ESCAPE")
	})

	t.Run("rel failure is path escape", func(t *testing.T) {
		if runtime.GOOS != "windows" {
			t.Skip("cross-volume Rel failures are a Windows path form")
		}
		_, err := SafeJoin(root, `D:escape`)
		requireErrorCode(t, err, "PATH_ESCAPE")
	})
}
