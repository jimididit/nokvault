package integration

import (
	"os"
	"path/filepath"
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
	path := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(path, []byte("secret"), 0o600))

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"secure-delete", path, "--dry-run"})
	require.NoError(t, rootCmd.Execute())
	_, err := os.Stat(path)
	require.NoError(t, err, "dry-run must not delete")
}
