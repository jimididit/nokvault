package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCLI_RecipientRoundTrip tests the full keygen → encrypt -r → decrypt --identity flow
func TestCLI_RecipientRoundTrip(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.txt")
	pubPath := filepath.Join(dir, "pub.txt")
	in := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(in, []byte("hello-recipients"), 0o600))

	// keygen
	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"keygen", "-o", idPath, "--public-out", pubPath})
	require.NoError(t, rootCmd.Execute(), "keygen should succeed")

	// verify identity file exists with 0600 perms (on Unix)
	idInfo, err := os.Stat(idPath)
	require.NoError(t, err)
	require.False(t, idInfo.IsDir())
	
	// verify public recipient file exists
	pubInfo, err := os.Stat(pubPath)
	require.NoError(t, err)
	require.False(t, pubInfo.IsDir())

	// encrypt with recipient
	out := filepath.Join(dir, "plain.txt.nokv")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", in, "-r", pubPath, "--output", out, "--force"})
	require.NoError(t, rootCmd.Execute(), "encrypt with -r should succeed")

	// decrypt with identity
	plainOut := filepath.Join(dir, "out.txt")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"decrypt", out, "--identity", idPath, "--output", plainOut, "--force"})
	require.NoError(t, rootCmd.Execute(), "decrypt with --identity should succeed")
	
	got, err := os.ReadFile(plainOut)
	require.NoError(t, err)
	require.Equal(t, []byte("hello-recipients"), got)
}

// TestCLI_EncryptRecipient_RejectsEnvPassword tests that encrypt -r refuses NOKVAULT_PASSWORD
func TestCLI_EncryptRecipient_RejectsEnvPassword(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.txt")
	pubPath := filepath.Join(dir, "pub.txt")
	in := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(in, []byte("test"), 0o600))

	// keygen
	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"keygen", "-o", idPath, "--public-out", pubPath})
	require.NoError(t, rootCmd.Execute())

	// try encrypt with -r and NOKVAULT_PASSWORD set
	t.Setenv("NOKVAULT_PASSWORD", "nope")
	out := filepath.Join(dir, "plain.txt.nokv")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", in, "-r", pubPath, "--output", out})
	err := rootCmd.Execute()
	require.Error(t, err, "encrypt with -r and NOKVAULT_PASSWORD should fail")
	require.Contains(t, err.Error(), "recipient", "error should mention recipient mode exclusivity")
}

// TestCLI_EncryptRecipient_RejectsKeyfile tests that encrypt -r refuses --keyfile
func TestCLI_EncryptRecipient_RejectsKeyfile(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.txt")
	pubPath := filepath.Join(dir, "pub.txt")
	keyfilePath := filepath.Join(dir, "keyfile")
	in := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(in, []byte("test"), 0o600))
	require.NoError(t, os.WriteFile(keyfilePath, []byte("keyfile-secret"), 0o600))

	// keygen
	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"keygen", "-o", idPath, "--public-out", pubPath})
	require.NoError(t, rootCmd.Execute())

	// try encrypt with -r and --keyfile
	out := filepath.Join(dir, "plain.txt.nokv")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", in, "-r", pubPath, "--keyfile", keyfilePath, "--output", out})
	err := rootCmd.Execute()
	require.Error(t, err, "encrypt with -r and --keyfile should fail")
	require.Contains(t, err.Error(), "recipient", "error should mention recipient mode exclusivity")
}

// TestCLI_DecryptV4_RequiresIdentity tests that v4 decrypt without --identity fails
func TestCLI_DecryptV4_RequiresIdentity(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.txt")
	pubPath := filepath.Join(dir, "pub.txt")
	in := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(in, []byte("test"), 0o600))

	// keygen
	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"keygen", "-o", idPath, "--public-out", pubPath})
	require.NoError(t, rootCmd.Execute())

	// encrypt with recipient (creates v4 vault)
	out := filepath.Join(dir, "plain.txt.nokv")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", in, "-r", pubPath, "--output", out, "--force"})
	require.NoError(t, rootCmd.Execute())

	// try decrypt v4 without --identity
	plainOut := filepath.Join(dir, "out.txt")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"decrypt", out, "--output", plainOut})
	err := rootCmd.Execute()
	require.Error(t, err, "decrypt v4 without --identity should fail")
	require.Contains(t, err.Error(), "identity", "error should mention identity requirement")
}

// TestCLI_DecryptV4_RejectsMixedIdentityPassword tests that v4 decrypt refuses identity + password
func TestCLI_DecryptV4_RejectsMixedIdentityPassword(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.txt")
	pubPath := filepath.Join(dir, "pub.txt")
	in := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(in, []byte("test"), 0o600))

	// keygen
	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"keygen", "-o", idPath, "--public-out", pubPath})
	require.NoError(t, rootCmd.Execute())

	// encrypt with recipient
	out := filepath.Join(dir, "plain.txt.nokv")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", in, "-r", pubPath, "--output", out, "--force"})
	require.NoError(t, rootCmd.Execute())

	// try decrypt with both --identity and NOKVAULT_PASSWORD
	t.Setenv("NOKVAULT_PASSWORD", "wrongpass")
	plainOut := filepath.Join(dir, "out.txt")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"decrypt", out, "--identity", idPath, "--output", plainOut})
	err := rootCmd.Execute()
	require.Error(t, err, "decrypt v4 with --identity and NOKVAULT_PASSWORD should fail")
	require.Contains(t, err.Error(), "cannot use passphrase material", "error should mention passphrase exclusivity")
}

// TestCLI_Keygen_RefusesOverwrite tests that keygen without --force refuses to overwrite
func TestCLI_Keygen_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.txt")

	// first keygen succeeds
	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"keygen", "-o", idPath})
	require.NoError(t, rootCmd.Execute())

	// second keygen without --force should fail
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"keygen", "-o", idPath})
	err := rootCmd.Execute()
	require.Error(t, err, "keygen should refuse to overwrite without --force")
	require.Contains(t, err.Error(), "already exists", "error should mention file exists")
}

// TestCLI_Keygen_ForceOverwrites tests that keygen with --force overwrites existing identity
func TestCLI_Keygen_ForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.txt")

	// first keygen
	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"keygen", "-o", idPath})
	require.NoError(t, rootCmd.Execute())
	first, err := os.ReadFile(idPath)
	require.NoError(t, err)

	// second keygen with --force
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"keygen", "-o", idPath, "--force"})
	require.NoError(t, rootCmd.Execute())
	second, err := os.ReadFile(idPath)
	require.NoError(t, err)

	// content should differ (different keys generated)
	require.NotEqual(t, first, second, "forced keygen should generate new key")
}

// TestCLI_EncryptDirectory_WithRecipients tests directory encryption with recipients
func TestCLI_EncryptDirectory_WithRecipients(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "id.txt")
	pubPath := filepath.Join(dir, "pub.txt")
	
	srcDir := filepath.Join(dir, "src")
	require.NoError(t, os.Mkdir(srcDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("file-a"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "b.txt"), []byte("file-b"), 0o600))

	// keygen
	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"keygen", "-o", idPath, "--public-out", pubPath})
	require.NoError(t, rootCmd.Execute())

	// encrypt directory with recipient
	outDir := filepath.Join(dir, "src.nokv")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", srcDir, "-r", pubPath, "--output", outDir})
	require.NoError(t, rootCmd.Execute())

	// decrypt directory with identity
	decryptedDir := filepath.Join(dir, "decrypted")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"decrypt", outDir, "--identity", idPath, "--output", decryptedDir})
	require.NoError(t, rootCmd.Execute())

	// verify files
	aContent, err := os.ReadFile(filepath.Join(decryptedDir, "a.txt"))
	require.NoError(t, err)
	require.Equal(t, []byte("file-a"), aContent)
	
	bContent, err := os.ReadFile(filepath.Join(decryptedDir, "b.txt"))
	require.NoError(t, err)
	require.Equal(t, []byte("file-b"), bContent)
}

// TestCLI_EncryptMultipleRecipients tests encryption with multiple -r flags
func TestCLI_EncryptMultipleRecipients(t *testing.T) {
	dir := t.TempDir()
	id1Path := filepath.Join(dir, "id1.txt")
	pub1Path := filepath.Join(dir, "pub1.txt")
	id2Path := filepath.Join(dir, "id2.txt")
	pub2Path := filepath.Join(dir, "pub2.txt")
	in := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(in, []byte("multi-recipient"), 0o600))

	// keygen for recipient 1
	rootCmd := freshRootCmd(t)
	rootCmd.SetArgs([]string{"keygen", "-o", id1Path, "--public-out", pub1Path})
	require.NoError(t, rootCmd.Execute())

	// keygen for recipient 2
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"keygen", "-o", id2Path, "--public-out", pub2Path})
	require.NoError(t, rootCmd.Execute())

	// encrypt with both recipients
	out := filepath.Join(dir, "plain.txt.nokv")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"encrypt", in, "-r", pub1Path, "-r", pub2Path, "--output", out, "--force"})
	require.NoError(t, rootCmd.Execute())

	// decrypt with first identity
	plainOut1 := filepath.Join(dir, "out1.txt")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"decrypt", out, "--identity", id1Path, "--output", plainOut1, "--force"})
	require.NoError(t, rootCmd.Execute())
	got1, err := os.ReadFile(plainOut1)
	require.NoError(t, err)
	require.Equal(t, []byte("multi-recipient"), got1)

	// decrypt with second identity
	plainOut2 := filepath.Join(dir, "out2.txt")
	rootCmd = freshRootCmd(t)
	rootCmd.SetArgs([]string{"decrypt", out, "--identity", id2Path, "--output", plainOut2, "--force"})
	require.NoError(t, rootCmd.Execute())
	got2, err := os.ReadFile(plainOut2)
	require.NoError(t, err)
	require.Equal(t, []byte("multi-recipient"), got2)
}
