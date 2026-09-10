package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jimididit/nokvault/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestEncrypt_TrailingSlashDefaultOutputIsSibling(t *testing.T) {
	ResetCLIStateForTest()
	dir := t.TempDir()
	src := filepath.Join(dir, "testdir")
	require.NoError(t, os.Mkdir(src, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(src, "a.txt"), []byte("hello"), 0o600))

	keyfile := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(keyfile, []byte("test-keyfile-material"), 0o600))

	// Trailing slash must not create src/.nokv
	input := src + string(os.PathSeparator)
	rootCmd.SetArgs([]string{"encrypt", input, "--keyfile", keyfile, "--no-prompt"})
	require.NoError(t, rootCmd.Execute())

	sibling := src + utils.VaultExt
	inside := filepath.Join(src, utils.VaultExt)
	_, err := os.Lstat(sibling)
	require.NoError(t, err, "expected sibling vault dir %s", sibling)
	_, err = os.Lstat(inside)
	require.True(t, os.IsNotExist(err), "must not create vault inside source tree")
}

func TestDecrypt_AcceptsLegacyVaultExt(t *testing.T) {
	ResetCLIStateForTest()
	dir := t.TempDir()
	plain := filepath.Join(dir, "legacy.txt")
	require.NoError(t, os.WriteFile(plain, []byte("legacy-plain"), 0o600))
	keyfile := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(keyfile, []byte("test-keyfile-material"), 0o600))

	legacyOut := plain + utils.LegacyVaultExt
	rootCmd.SetArgs([]string{"encrypt", plain, "--keyfile", keyfile, "--no-prompt", "--output", legacyOut})
	require.NoError(t, rootCmd.Execute())

	ResetCLIStateForTest()
	outDir := filepath.Join(dir, "out")
	require.NoError(t, os.Mkdir(outDir, 0o700))
	restored := filepath.Join(outDir, "legacy.txt")
	rootCmd.SetArgs([]string{"decrypt", legacyOut, "--keyfile", keyfile, "--no-prompt", "--output", restored})
	require.NoError(t, rootCmd.Execute())

	got, err := os.ReadFile(restored)
	require.NoError(t, err)
	require.Equal(t, []byte("legacy-plain"), got)
}
