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

func TestCLI_Encrypt_ForceDoesNotReplaceDirectory(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "a.txt")
	outputDir := filepath.Join(dir, "existing-directory")
	require.NoError(t, os.WriteFile(input, []byte("payload"), 0o600))
	require.NoError(t, os.Mkdir(outputDir, 0o700))
	keyfile := writeTempKeyfile(t, "force-directory-password")

	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{
		"encrypt", input,
		"--output", outputDir,
		"--keyfile", keyfile,
		"--no-prompt",
		"--force",
	})
	require.Error(t, rootCmd.Execute())

	info, err := os.Stat(outputDir)
	require.NoError(t, err, "output directory must remain")
	require.True(t, info.IsDir(), "output directory must not become a file")
}

func TestCLI_Decrypt_StrictAbortsEarly(t *testing.T) {
	dir := t.TempDir()
	inDir := filepath.Join(dir, "vault")
	strictOutDir := filepath.Join(dir, "strict-plain")
	continueOutDir := filepath.Join(dir, "continue-plain")
	require.NoError(t, os.MkdirAll(inDir, 0o700))
	keyfile := writeTempKeyfile(t, "strict-test-password")

	good := filepath.Join(dir, "good.txt")
	require.NoError(t, os.WriteFile(good, []byte("ok"), 0o600))
	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", good, "--keyfile", keyfile, "--no-prompt", "--output", filepath.Join(inDir, "z_good.txt.nokvault")})
	require.NoError(t, rootCmd.Execute())

	// filepath.Walk is lexical: the corrupt file must be encountered first.
	require.NoError(t, os.WriteFile(filepath.Join(inDir, "a_bad.nokvault"), []byte("not-a-vault"), 0o600))

	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{
		"decrypt", inDir,
		"--output", strictOutDir,
		"--keyfile", keyfile,
		"--no-prompt",
		"--strict",
	})
	require.Error(t, rootCmd.Execute())

	_, err := os.Stat(filepath.Join(strictOutDir, "z_good.txt"))
	require.True(t, os.IsNotExist(err), "strict mode must not process files after the first failure")

	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{
		"decrypt", inDir,
		"--output", continueOutDir,
		"--keyfile", keyfile,
		"--no-prompt",
	})
	require.Error(t, rootCmd.Execute(), "continue mode still reports the corrupt file")
	_, err = os.Stat(filepath.Join(continueOutDir, "z_good.txt"))
	require.NoError(t, err, "default mode must continue to later valid files")
}
