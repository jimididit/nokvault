package integration

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jimididit/nokvault/internal/utils"
)

func requirePathEscape(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected PATH_ESCAPE, got nil")
	}
	var nv *utils.NokvaultError
	if !errors.As(err, &nv) {
		t.Fatalf("got %T %v, want *NokvaultError PATH_ESCAPE", err, err)
	}
	if nv.Code != "PATH_ESCAPE" {
		t.Fatalf("got code %q, want PATH_ESCAPE (err=%v)", nv.Code, err)
	}
}

func TestCLI_DirectoryEncrypt_NestedFileSymlinkAbortsWithoutCiphertext(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "tree")
	if err := os.Mkdir(input, 0o700); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(input, "keep.txt")
	if err := os.WriteFile(regular, []byte("plain"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(input, "target.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(input, "nested.link")
	trySymlink(t, target, link)

	output := filepath.Join(dir, "tree.out")
	keyfile := writeTempKeyfile(t, "containment-encrypt-password")

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", input, "--output", output, "--dry-run"})
	requireSymlinkDisallowed(t, rootCmd.Execute(), link)

	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", input, "--output", output, "--keyfile", keyfile, "--no-prompt"})
	requireSymlinkDisallowed(t, rootCmd.Execute(), link)

	if _, err := os.Lstat(filepath.Join(output, "nested.link.nokv")); !os.IsNotExist(err) {
		t.Fatalf("nested symlink must not produce ciphertext: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(output, "keep.txt.nokv")); !os.IsNotExist(err) {
		t.Fatalf("aborted directory encrypt must not write sibling ciphertext: %v", err)
	}
}

func TestCLI_DirectoryDecrypt_RejectsSymlinkedOutputParent(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "plain-tree")
	if err := os.Mkdir(input, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(input, "note.txt"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyfile := writeTempKeyfile(t, "containment-decrypt-password")
	encrypted := filepath.Join(dir, "plain-tree.nokv")

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", input, "--output", encrypted, "--keyfile", keyfile, "--no-prompt"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("setup encrypt: %v", err)
	}

	realParent := filepath.Join(dir, "real-out")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(realParent, "must-survive.txt")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(dir, "out-parent.link")
	trySymlink(t, realParent, linkParent)
	output := filepath.Join(linkParent, "restored")

	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"decrypt", encrypted, "--output", output, "--dry-run"})
	requireSymlinkDisallowed(t, rootCmd.Execute(), linkParent)

	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"decrypt", encrypted, "--output", output, "--keyfile", keyfile, "--no-prompt"})
	requireSymlinkDisallowed(t, rootCmd.Execute(), linkParent)

	if _, err := os.Lstat(filepath.Join(realParent, "restored")); !os.IsNotExist(err) {
		t.Fatalf("decrypt must not write through the symlink parent: %v", err)
	}
	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" {
		t.Fatalf("symlink target changed: %q", got)
	}
}

func TestCLI_SecureDelete_DryRunAndYesPreserveSymlinkAndTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("must-survive"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "delete-link.txt")
	trySymlink(t, target, link)

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"secure-delete", link, "--dry-run"})
	requireSymlinkDisallowed(t, rootCmd.Execute(), link)

	rootCmd = freshRootCmd(t)
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

func TestSafeJoin_LexicalEscapeCasesNeverSkip(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "out")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	cases := []string{
		"..",
		filepath.Join("nested", "..", "..", "escape"),
		filepath.Join("..", "out-evil", "secret"),
		"NUL",
		"CON",
		"COM1",
		filepath.Join("nested", "NUL"),
		`\outside`,
	}
	for _, rel := range cases {
		_, err := utils.SafeJoin(root, rel)
		requirePathEscape(t, err)
	}

	got, err := utils.SafeJoin(root, filepath.Join("nested", "file.txt"))
	if err != nil {
		t.Fatalf("safe join should succeed: %v", err)
	}
	want, err := filepath.Abs(filepath.Join(root, "nested", "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	if runtime.GOOS == "windows" {
		_, err := utils.SafeJoin(root, `C:windows`)
		requirePathEscape(t, err)
	}
}
