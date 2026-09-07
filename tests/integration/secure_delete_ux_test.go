package integration

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCLI_SecureDelete_RequiresYesNonInteractive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(path, []byte("secret"), 0o600))

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"secure-delete", path})
	err := rootCmd.Execute()
	require.Error(t, err)
	_, statErr := os.Stat(path)
	require.NoError(t, statErr, "file must still exist without --yes")
}

func TestCLI_SecureDelete_YesDeletes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(path, []byte("secret"), 0o600))

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"secure-delete", path, "--yes"})
	require.NoError(t, rootCmd.Execute())
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestCLI_SecureDelete_DryRunPreserves(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.txt")
	second := filepath.Join(dir, "nested", "second.txt")
	require.NoError(t, os.MkdirAll(filepath.Dir(second), 0o700))
	require.NoError(t, os.WriteFile(first, []byte("first"), 0o600))
	require.NoError(t, os.WriteFile(second, []byte("second"), 0o600))

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"secure-delete", dir, "--dry-run"})

	oldStdout := os.Stdout
	readPipe, writePipe, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = writePipe
	t.Cleanup(func() { os.Stdout = oldStdout })

	require.NoError(t, rootCmd.Execute())
	require.NoError(t, writePipe.Close())
	os.Stdout = oldStdout
	output, err := io.ReadAll(readPipe)
	require.NoError(t, err)
	require.NoError(t, readPipe.Close())

	text := string(output)
	require.Contains(t, text, first)
	require.Contains(t, text, second)
	require.NotContains(t, text, "Would securely delete: "+dir+"\n",
		"directory dry-run should list files, not directories")
	require.Equal(t, 2, strings.Count(text, "Would securely delete:"))

	_, err = os.Stat(first)
	require.NoError(t, err, "dry-run must not delete the first file")
	_, err = os.Stat(second)
	require.NoError(t, err, "dry-run must not delete the nested file")
}
