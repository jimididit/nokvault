package cli

import (
	"errors"
	"fmt"
	"io"
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

func requirePathEscape(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var nv *utils.NokvaultError
	require.ErrorAs(t, err, &nv)
	require.Equal(t, "PATH_ESCAPE", nv.Code)
	require.NotContains(t, err.Error(), "directory decryption completed")
}

func captureStderr(t *testing.T) func() string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	done := make(chan string, 1)
	t.Cleanup(func() {
		os.Stderr = old
		_ = w.Close()
		_ = r.Close()
	})
	return func() string {
		os.Stderr = old
		require.NoError(t, w.Close())
		b, readErr := io.ReadAll(r)
		require.NoError(t, readErr)
		_ = r.Close()
		text := string(b)
		done <- text
		return text
	}
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

func TestEncrypt_Directory_RejectsNestedOutputSymlinkBeforePassword(t *testing.T) {
	t.Setenv("NOKVAULT_PASSWORD", "")
	dir := t.TempDir()
	inDir := filepath.Join(dir, "in")
	require.NoError(t, os.MkdirAll(filepath.Join(inDir, "nested"), 0o700))
	writeRegularFile(t, filepath.Join(inDir, "nested"), "file.txt", "secret")

	outDir := filepath.Join(dir, "out")
	require.NoError(t, os.Mkdir(outDir, 0o700))
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	link := filepath.Join(outDir, "nested")
	trySymlink(t, target, link)

	err := execCLI(t, "encrypt", inDir, "--output", outDir, "--no-prompt")
	requireSymlinkDisallowed(t, err, link)
	require.NotContains(t, err.Error(), "no password provided")
}

func TestDecrypt_Directory_RejectsNestedOutputSymlinkBeforePassword(t *testing.T) {
	t.Setenv("NOKVAULT_PASSWORD", "")
	dir := t.TempDir()
	inDir := filepath.Join(dir, "in")
	require.NoError(t, os.MkdirAll(filepath.Join(inDir, "nested"), 0o700))
	writeRegularFile(t, filepath.Join(inDir, "nested"), "file.nokvault", "not-a-real-cipher")

	outDir := filepath.Join(dir, "out")
	require.NoError(t, os.Mkdir(outDir, 0o700))
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	link := filepath.Join(outDir, "nested")
	trySymlink(t, target, link)

	err := execCLI(t, "decrypt", inDir, "--output", outDir, "--no-prompt")
	requireSymlinkDisallowed(t, err, link)
	require.NotContains(t, err.Error(), "no password provided")
}

func TestSchedule_RejectsGeneratedOutputBeforePassword(t *testing.T) {
	t.Setenv("NOKVAULT_PASSWORD", "")
	dir := t.TempDir()
	input := writeRegularFile(t, dir, "secret.txt", "secret")
	target := writeRegularFile(t, dir, "out-target.txt", "keep")
	outLink := input + ".nokvault"
	trySymlink(t, target, outLink)

	err := execCLI(t, "schedule", "encrypt", input, "--no-prompt")
	requireSymlinkDisallowed(t, err, outLink)
	require.NotContains(t, err.Error(), "no password provided")
	got, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	require.Equal(t, "keep", string(got))
}

func TestDecrypt_Directory_NonStrictPreservesSymlinkDisallowed(t *testing.T) {
	dir := t.TempDir()
	inDir := filepath.Join(dir, "vault")
	require.NoError(t, os.MkdirAll(filepath.Join(inDir, "nested"), 0o700))
	writeRegularFile(t, filepath.Join(inDir, "nested"), "file.nokvault", "not-a-real-cipher")
	writeRegularFile(t, inDir, "other.nokvault", "also-not-a-cipher")

	outDir := filepath.Join(dir, "out")
	require.NoError(t, os.Mkdir(outDir, 0o700))
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	link := filepath.Join(outDir, "nested")
	trySymlink(t, target, link)

	ResetCLIStateForTest()
	t.Cleanup(ResetCLIStateForTest)
	decryptStrict = false

	err := decryptDirectory(inDir, outDir, []byte("unused-password"), core.NewEncryptionService())
	requireSymlinkDisallowed(t, err, link)
	require.NotContains(t, err.Error(), "directory decryption completed")
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

func TestSchedule_PerformScheduledEncrypt_RePreflightsNestedOutputs(t *testing.T) {
	dir := t.TempDir()
	inDir := filepath.Join(dir, "in")
	require.NoError(t, os.MkdirAll(filepath.Join(inDir, "nested"), 0o700))
	writeRegularFile(t, inDir, "a.txt", "payload-a")
	writeRegularFile(t, filepath.Join(inDir, "nested"), "z.txt", "payload-z")

	outRoot := inDir + ".nokvault"
	require.NoError(t, os.MkdirAll(filepath.Join(outRoot, "nested"), 0o700))
	sentinel := filepath.Join(outRoot, "a.txt.nokvault")
	require.NoError(t, os.WriteFile(sentinel, []byte("keep-me"), 0o600))

	target := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	require.NoError(t, os.Remove(filepath.Join(outRoot, "nested")))
	link := filepath.Join(outRoot, "nested")
	trySymlink(t, target, link)

	svc := core.NewEncryptionService()
	key, salt, err := svc.GetKeyManager().DeriveKeyFromPassword([]byte("schedule-repreflight-test"))
	require.NoError(t, err)

	err = performScheduledEncrypt(inDir, svc, key, salt)
	requireSymlinkDisallowed(t, err, link)

	got, readErr := os.ReadFile(sentinel)
	require.NoError(t, readErr)
	require.Equal(t, "keep-me", string(got), "earlier lexical output must not be rewritten")

	_, statErr := os.Lstat(filepath.Join(target, "z.txt.nokvault"))
	require.True(t, os.IsNotExist(statErr), "must not write through the symlink")
	info, lerr := os.Lstat(link)
	require.NoError(t, lerr)
	require.NotEqual(t, 0, info.Mode()&os.ModeSymlink)
}

func TestSchedule_Directory_RejectsNestedOutputBeforePassword(t *testing.T) {
	t.Setenv("NOKVAULT_PASSWORD", "")
	dir := t.TempDir()
	inDir := filepath.Join(dir, "in")
	require.NoError(t, os.MkdirAll(filepath.Join(inDir, "nested"), 0o700))
	writeRegularFile(t, filepath.Join(inDir, "nested"), "file.txt", "secret")

	outRoot := inDir + ".nokvault"
	require.NoError(t, os.Mkdir(outRoot, 0o700))
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	link := filepath.Join(outRoot, "nested")
	trySymlink(t, target, link)

	err := execCLI(t, "schedule", "encrypt", inDir, "--no-prompt")
	requireSymlinkDisallowed(t, err, link)
	require.NotContains(t, err.Error(), "no password provided")
}

func TestSchedule_ReportsPathPolicyWithoutVerbose(t *testing.T) {
	ResetCLIStateForTest()
	t.Cleanup(ResetCLIStateForTest)
	scheduleVerbose = false

	policyErr := utils.NewErrorWithHint(
		utils.ErrSymlinkDisallowed.Code,
		"Symlink paths are not allowed: scheduled-link",
		nil,
		"Use a regular file or directory path. Symlinks are not followed.",
	)
	readPolicy := captureStderr(t)
	logScheduleEncryptError(policyErr)
	policyOut := readPolicy()
	require.Contains(t, policyOut, "SYMLINK_DISALLOWED")
	require.Contains(t, policyOut, "scheduled-link")

	escapeErr := utils.NewErrorWithHint(
		utils.ErrPathEscape.Code,
		"Path escapes the output root: ..",
		nil,
		"Use a relative path that stays inside the selected output directory.",
	)
	readEscape := captureStderr(t)
	logScheduleEncryptError(escapeErr)
	require.Contains(t, readEscape(), "PATH_ESCAPE")

	readOrdinary := captureStderr(t)
	logScheduleEncryptError(fmt.Errorf("disk full"))
	require.Empty(t, readOrdinary(), "ordinary schedule errors stay quiet without --verbose")
}

func TestProtect_RejectsSymlinkInputBeforeDryRun(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	require.NoError(t, os.Mkdir(realDir, 0o700))
	link := filepath.Join(dir, "protect-link")
	trySymlink(t, realDir, link)

	err := execCLI(t, "protect", link, "--dry-run")
	requireSymlinkDisallowed(t, err, link)
}

func TestProtect_RejectsSymlinkOutputBeforeDryRun(t *testing.T) {
	dir := t.TempDir()
	inDir := filepath.Join(dir, "in")
	require.NoError(t, os.Mkdir(inDir, 0o700))
	target := writeRegularFile(t, dir, "out-target", "keep")
	outLink := filepath.Join(dir, "out-link.nokvault")
	trySymlink(t, target, outLink)

	err := execCLI(t, "protect", inDir, "--output", outLink, "--dry-run")
	requireSymlinkDisallowed(t, err, outLink)
	got, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	require.Equal(t, "keep", string(got))
}

func TestProtect_RejectsSymlinkBeforeUnimplemented(t *testing.T) {
	t.Setenv("NOKVAULT_PASSWORD", "")
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	require.NoError(t, os.Mkdir(realDir, 0o700))
	link := filepath.Join(dir, "protect-input-link")
	trySymlink(t, realDir, link)

	err := execCLI(t, "protect", link, "--no-prompt")
	requireSymlinkDisallowed(t, err, link)
	require.NotContains(t, err.Error(), "not yet implemented")
}

func TestDecrypt_Directory_NonStrictPreservesPathEscape(t *testing.T) {
	dir := t.TempDir()
	inDir := filepath.Join(dir, "vault")
	require.NoError(t, os.Mkdir(inDir, 0o700))
	writeRegularFile(t, inDir, "...nokvault", "not-a-real-cipher")
	writeRegularFile(t, inDir, "other.nokvault", "also-not-a-cipher")
	outDir := filepath.Join(dir, "out")
	require.NoError(t, os.Mkdir(outDir, 0o700))

	ResetCLIStateForTest()
	t.Cleanup(ResetCLIStateForTest)
	decryptStrict = false

	err := decryptDirectory(inDir, outDir, []byte("unused-password"), core.NewEncryptionService())
	requirePathEscape(t, err)
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

func TestReportWatchValidationError(t *testing.T) {
	policyErr := utils.NewErrorWithHint(
		utils.ErrSymlinkDisallowed.Code,
		"Symlink paths are not allowed: watch-link",
		nil,
		"Use a regular file or directory path. Symlinks are not followed.",
	)
	ordinary := os.ErrPermission

	t.Run("policy_verbose_off_visible", func(t *testing.T) {
		read := captureStderr(t)
		reportWatchValidationError(policyErr, false)
		out := read()
		require.Contains(t, out, "SYMLINK_DISALLOWED")
	})
	t.Run("policy_verbose_on_visible", func(t *testing.T) {
		read := captureStderr(t)
		reportWatchValidationError(policyErr, true)
		out := read()
		require.Contains(t, out, "SYMLINK_DISALLOWED")
	})
	t.Run("ordinary_verbose_off_silent", func(t *testing.T) {
		read := captureStderr(t)
		reportWatchValidationError(ordinary, false)
		require.Empty(t, read())
	})
	t.Run("ordinary_verbose_on_visible", func(t *testing.T) {
		read := captureStderr(t)
		reportWatchValidationError(ordinary, true)
		out := read()
		require.Contains(t, out, ordinary.Error())
	})
}

func TestWatch_CallbackReportsPolicyWithVerbose(t *testing.T) {
	dir := t.TempDir()
	target := writeRegularFile(t, dir, "target.txt", "watch-target")
	link := filepath.Join(dir, "verbose-event-link.txt")
	trySymlink(t, target, link)

	svc := core.NewEncryptionService()
	key, salt, err := svc.GetKeyManager().DeriveKeyFromPassword([]byte("watch-verbose-policy-test"))
	require.NoError(t, err)

	readStderr := captureStderr(t)
	cb := createEncryptCallback(svc, key, salt, 30*time.Millisecond, nil, true)
	cb(link, fsnotify.Event{Name: link, Op: fsnotify.Write})
	output := readStderr()

	require.Contains(t, output, "SYMLINK_DISALLOWED")
	require.Contains(t, output, link)
}

func TestWatch_CallbackOrdinaryValidationSilentWithoutVerbose(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "gone.txt")

	svc := core.NewEncryptionService()
	key, salt, err := svc.GetKeyManager().DeriveKeyFromPassword([]byte("watch-ordinary-quiet-test"))
	require.NoError(t, err)

	readStderr := captureStderr(t)
	cb := createEncryptCallback(svc, key, salt, 30*time.Millisecond, nil, false)
	cb(missing, fsnotify.Event{Name: missing, Op: fsnotify.Write})
	require.Empty(t, readStderr())
}

func TestWatch_CallbackOrdinaryValidationReportsWhenVerbose(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "gone.txt")

	svc := core.NewEncryptionService()
	key, salt, err := svc.GetKeyManager().DeriveKeyFromPassword([]byte("watch-ordinary-verbose-test"))
	require.NoError(t, err)

	readStderr := captureStderr(t)
	cb := createEncryptCallback(svc, key, salt, 30*time.Millisecond, nil, true)
	cb(missing, fsnotify.Event{Name: missing, Op: fsnotify.Write})
	output := readStderr()
	require.Contains(t, output, "gone.txt")
}

func TestWatch_CallbackReportsPolicyWithoutVerbose(t *testing.T) {
	dir := t.TempDir()
	target := writeRegularFile(t, dir, "target.txt", "watch-target")
	link := filepath.Join(dir, "quiet-event-link.txt")
	trySymlink(t, target, link)

	svc := core.NewEncryptionService()
	key, salt, err := svc.GetKeyManager().DeriveKeyFromPassword([]byte("watch-quiet-policy-test"))
	require.NoError(t, err)

	readStderr := captureStderr(t)
	cb := createEncryptCallback(svc, key, salt, 30*time.Millisecond, nil, false)
	cb(link, fsnotify.Event{Name: link, Op: fsnotify.Write})
	output := readStderr()

	require.Contains(t, output, "SYMLINK_DISALLOWED")
	require.Contains(t, output, link)
	_, statErr := os.Lstat(link + ".nokvault")
	require.True(t, os.IsNotExist(statErr), "symlink event must not be scheduled for encryption")
}

func TestWatch_DelayedEncryptReportsPolicyWithoutVerbose(t *testing.T) {
	dir := t.TempDir()
	regular := writeRegularFile(t, dir, "watched.txt", "original")
	target := writeRegularFile(t, dir, "swap-target.txt", "swap-target")

	svc := core.NewEncryptionService()
	key, salt, err := svc.GetKeyManager().DeriveKeyFromPassword([]byte("watch-quiet-delayed-test"))
	require.NoError(t, err)

	readStderr := captureStderr(t)
	cb := createEncryptCallback(svc, key, salt, 80*time.Millisecond, nil, false)
	cb(regular, fsnotify.Event{Name: regular, Op: fsnotify.Write})

	require.NoError(t, os.Remove(regular))
	trySymlink(t, target, regular)

	time.Sleep(200 * time.Millisecond)
	output := readStderr()

	require.Contains(t, output, "SYMLINK_DISALLOWED")
	_, statErr := os.Lstat(regular + ".nokvault")
	require.True(t, os.IsNotExist(statErr))
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
