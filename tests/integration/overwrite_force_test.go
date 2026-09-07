package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCLI_Encrypt_RefuseOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "a.txt")
	require.NoError(t, os.WriteFile(input, []byte("one"), 0o600))
	keyfile := writeTempKeyfile(t, "force-test-password")

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", input, "--keyfile", keyfile, "--no-prompt"})
	require.NoError(t, rootCmd.Execute())

	require.NoError(t, os.WriteFile(input, []byte("two"), 0o600))
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", input, "--keyfile", keyfile, "--no-prompt"})
	require.Error(t, rootCmd.Execute(), "second encrypt without --force must fail")

	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", input, "--keyfile", keyfile, "--no-prompt", "--force"})
	require.NoError(t, rootCmd.Execute())
}

func TestCLI_Decrypt_RefuseOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "a.txt")
	require.NoError(t, os.WriteFile(input, []byte("payload"), 0o600))
	keyfile := writeTempKeyfile(t, "force-decrypt-password")

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", input, "--keyfile", keyfile, "--no-prompt"})
	require.NoError(t, rootCmd.Execute())

	enc := input + ".nokvault"
	out := filepath.Join(dir, "out.txt")
	require.NoError(t, os.WriteFile(out, []byte("existing"), 0o600))

	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"decrypt", enc, "--keyfile", keyfile, "--output", out, "--no-prompt"})
	require.Error(t, rootCmd.Execute())

	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"decrypt", enc, "--keyfile", keyfile, "--output", out, "--no-prompt", "--force"})
	require.NoError(t, rootCmd.Execute())
	got, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Equal(t, "payload", string(got))
}

func TestCLI_Decrypt_StrictAbortsEarly(t *testing.T) {
	dir := t.TempDir()
	inDir := filepath.Join(dir, "vault")
	outDir := filepath.Join(dir, "plain")
	require.NoError(t, os.MkdirAll(inDir, 0o700))
	keyfile := writeTempKeyfile(t, "strict-test-password")

	good := filepath.Join(dir, "good.txt")
	require.NoError(t, os.WriteFile(good, []byte("ok"), 0o600))
	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", good, "--keyfile", keyfile, "--no-prompt", "--output", filepath.Join(inDir, "a.txt.nokvault")})
	require.NoError(t, rootCmd.Execute())

	// Plant a corrupt vault that sorts after a.txt on most filesystems... use z_bad so good decrypts first
	require.NoError(t, os.WriteFile(filepath.Join(inDir, "z_bad.nokvault"), []byte("not-a-vault"), 0o600))

	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{
		"decrypt", inDir,
		"--output", outDir,
		"--keyfile", keyfile,
		"--no-prompt",
		"--strict",
	})
	require.Error(t, rootCmd.Execute())

	// a.txt should have been written before abort
	_, err := os.Stat(filepath.Join(outDir, "a.txt"))
	require.NoError(t, err, "successful file before failure should remain")
}
