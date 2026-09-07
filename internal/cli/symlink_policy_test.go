package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/jimididit/nokvault/internal/core"
	"github.com/jimididit/nokvault/internal/utils"
	"github.com/stretchr/testify/require"
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
	require.Error(t, err)
	var nv *utils.NokvaultError
	require.ErrorAs(t, err, &nv)
	require.Equal(t, "SYMLINK_DISALLOWED", nv.Code)
	require.Contains(t, err.Error(), link)
}

func writeRegularFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func execCLI(t *testing.T, args ...string) error {
	t.Helper()
	ResetCLIStateForTest()
	t.Cleanup(ResetCLIStateForTest)
	rootCmd.SetArgs(args)
	return rootCmd.Execute()
}

func TestEncrypt_RejectsSymlinkInput(t *testing.T) {
	dir := t.TempDir()
	target := writeRegularFile(t, dir, "target.txt", "secret")
	link := filepath.Join(dir, "input-link.txt")
	trySymlink(t, target, link)

	err := execCLI(t, "encrypt", link, "--dry-run")
	requireSymlinkDisallowed(t, err, link)
}

func TestEncrypt_RejectsSymlinkOutput(t *testing.T) {
	dir := t.TempDir()
	input := writeRegularFile(t, dir, "plain.txt", "secret")
	target := writeRegularFile(t, dir, "out-target.txt", "keep")
	outLink := filepath.Join(dir, "out-link.txt")
	trySymlink(t, target, outLink)

	err := execCLI(t, "encrypt", input, "--output", outLink, "--dry-run")
	requireSymlinkDisallowed(t, err, outLink)
	got, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	require.Equal(t, "keep", string(got))
}

func TestDecrypt_RejectsSymlinkOutput(t *testing.T) {
	dir := t.TempDir()
	input := writeRegularFile(t, dir, "cipher.nokvault", "not-a-real-cipher")
	target := writeRegularFile(t, dir, "out-target.txt", "keep")
	outLink := filepath.Join(dir, "out-link.txt")
	trySymlink(t, target, outLink)

	err := execCLI(t, "decrypt", input, "--output", outLink, "--dry-run")
	requireSymlinkDisallowed(t, err, outLink)
	got, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	require.Equal(t, "keep", string(got))
}

func TestRotateKey_RejectsSymlinkBeforePassword(t *testing.T) {
	t.Setenv("NOKVAULT_PASSWORD", "")
	dir := t.TempDir()
	target := writeRegularFile(t, dir, "cipher.nokvault", "not-a-real-cipher")
	link := filepath.Join(dir, "rotate-link.nokvault")
	trySymlink(t, target, link)

	err := execCLI(t, "rotate-key", link, "--no-prompt")
	requireSymlinkDisallowed(t, err, link)
	require.NotContains(t, err.Error(), "no password provided")
}

func TestSecureDelete_RejectsSymlinkPreservesLinkAndTarget(t *testing.T) {
	dir := t.TempDir()
	target := writeRegularFile(t, dir, "target.txt", "must-survive")
	link := filepath.Join(dir, "delete-link.txt")
	trySymlink(t, target, link)

	err := execCLI(t, "secure-delete", link, "--yes")
	requireSymlinkDisallowed(t, err, link)

	info, statErr := os.Lstat(link)
	require.NoError(t, statErr)
	require.NotEqual(t, 0, info.Mode()&os.ModeSymlink)
	got, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	require.Equal(t, "must-survive", string(got))
}

func TestSchedule_RejectsSymlinkRoot(t *testing.T) {
	t.Setenv("NOKVAULT_PASSWORD", "")
	dir := t.TempDir()
	target := writeRegularFile(t, dir, "target.txt", "secret")
	link := filepath.Join(dir, "sched-link.txt")
	trySymlink(t, target, link)

	err := execCLI(t, "schedule", "encrypt", link, "--no-prompt")
	requireSymlinkDisallowed(t, err, link)
	require.NotContains(t, err.Error(), "no password provided")
}

func TestSchedule_PerformScheduledEncrypt_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := writeRegularFile(t, dir, "target.txt", "secret")
	link := filepath.Join(dir, "sched-run-link.txt")
	trySymlink(t, target, link)

	svc := core.NewEncryptionService()
	key, salt, err := svc.GetKeyManager().DeriveKeyFromPassword([]byte("schedule-symlink-test"))
	require.NoError(t, err)

	err = performScheduledEncrypt(link, svc, key, salt)
	requireSymlinkDisallowed(t, err, link)
	_, statErr := os.Lstat(link + ".nokvault")
	require.True(t, os.IsNotExist(statErr))
	got, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	require.Equal(t, "secret", string(got))
}

func TestWatch_RejectsSymlinkRoot(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	require.NoError(t, os.Mkdir(realDir, 0o700))
	link := filepath.Join(dir, "watch-link")
	trySymlink(t, realDir, link)

	done := make(chan error, 1)
	go func() {
		ResetCLIStateForTest()
		done <- runWatch(watchCmd, []string{link})
	}()

	select {
	case err := <-done:
		requireSymlinkDisallowed(t, err, link)
	case <-time.After(2 * time.Second):
		t.Fatal("runWatch did not reject symlink root")
	}
}

func TestWatch_CallbackRejectsSymlinkEvent(t *testing.T) {
	dir := t.TempDir()
	target := writeRegularFile(t, dir, "target.txt", "watch-target")
	link := filepath.Join(dir, "event-link.txt")
	trySymlink(t, target, link)

	svc := core.NewEncryptionService()
	key, salt, err := svc.GetKeyManager().DeriveKeyFromPassword([]byte("watch-symlink-test"))
	require.NoError(t, err)

	cb := createEncryptCallback(svc, key, salt, 30*time.Millisecond, nil, true)
	cb(link, fsnotify.Event{Name: link, Op: fsnotify.Write})
	time.Sleep(80 * time.Millisecond)

	_, statErr := os.Lstat(link + ".nokvault")
	require.True(t, os.IsNotExist(statErr), "symlink event must not be scheduled for encryption")
	got, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	require.Equal(t, "watch-target", string(got))
}

func TestWatch_DelayedEncryptRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	regular := writeRegularFile(t, dir, "watched.txt", "original")
	target := writeRegularFile(t, dir, "swap-target.txt", "swap-target")

	svc := core.NewEncryptionService()
	key, salt, err := svc.GetKeyManager().DeriveKeyFromPassword([]byte("watch-delayed-symlink-test"))
	require.NoError(t, err)

	cb := createEncryptCallback(svc, key, salt, 120*time.Millisecond, nil, true)
	cb(regular, fsnotify.Event{Name: regular, Op: fsnotify.Write})

	require.NoError(t, os.Remove(regular))
	trySymlink(t, target, regular)

	time.Sleep(250 * time.Millisecond)

	_, statErr := os.Lstat(regular + ".nokvault")
	require.True(t, os.IsNotExist(statErr), "delayed encrypt must revalidate and refuse a swapped symlink")
	got, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	require.Equal(t, "swap-target", string(got))
}
