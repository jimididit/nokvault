package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jimididit/nokvault/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCLI_Encrypt_Help tests the encrypt command help output
func TestCLI_Encrypt_Help(t *testing.T) {
	rootCmd := cli.GetRootCmd()
	encryptCmd, _, err := rootCmd.Find([]string{"encrypt"})
	require.NoError(t, err, "Encrypt command should exist")
	assert.NotNil(t, encryptCmd, "Encrypt command should not be nil")
	assert.Equal(t, "encrypt <path>", encryptCmd.Use, "Command use should match")
}

// TestCLI_Decrypt_Help tests the decrypt command help output
func TestCLI_Decrypt_Help(t *testing.T) {
	rootCmd := cli.GetRootCmd()
	decryptCmd, _, err := rootCmd.Find([]string{"decrypt"})
	require.NoError(t, err, "Decrypt command should exist")
	assert.NotNil(t, decryptCmd, "Decrypt command should not be nil")
	assert.Equal(t, "decrypt <path>", decryptCmd.Use, "Command use should match")
}

// TestCLI_CommandsExist tests that all expected commands exist
func TestCLI_CommandsExist(t *testing.T) {
	rootCmd := cli.GetRootCmd()

	expectedCommands := []string{
		"encrypt",
		"decrypt",
		"protect",
		"secure-delete",
		"watch",
		"config",
		"rotate-key",
		"schedule",
	}

	for _, cmdName := range expectedCommands {
		cmd, _, err := rootCmd.Find([]string{cmdName})
		assert.NoError(t, err, "Command %s should exist", cmdName)
		assert.NotNil(t, cmd, "Command %s should not be nil", cmdName)
	}
}

// TestCLI_Encrypt_InvalidPath tests encrypt command with invalid path
func TestCLI_Encrypt_InvalidPath(t *testing.T) {
	rootCmd := cli.GetRootCmd()

	// Set up a non-existent path
	nonExistentPath := filepath.Join(os.TempDir(), "nokvault-nonexistent-test-12345")

	// Create a test command with the invalid path
	rootCmd.SetArgs([]string{"encrypt", nonExistentPath})

	// Execute should fail
	err := rootCmd.Execute()
	assert.Error(t, err, "Encrypt with invalid path should fail")
}

// TestCLI_Encrypt_MissingArgs tests encrypt command with missing arguments
func TestCLI_Encrypt_MissingArgs(t *testing.T) {
	rootCmd := cli.GetRootCmd()
	rootCmd.SetArgs([]string{"encrypt"})

	err := rootCmd.Execute()
	assert.Error(t, err, "Encrypt without path should fail")
}

// TestCLI_Decrypt_MissingArgs tests decrypt command with missing arguments
func TestCLI_Decrypt_MissingArgs(t *testing.T) {
	rootCmd := cli.GetRootCmd()
	rootCmd.SetArgs([]string{"decrypt"})

	err := rootCmd.Execute()
	assert.Error(t, err, "Decrypt without path should fail")
}

// TestCLI_SecureDelete_MissingArgs tests secure-delete command with missing arguments
func TestCLI_SecureDelete_MissingArgs(t *testing.T) {
	rootCmd := cli.GetRootCmd()
	rootCmd.SetArgs([]string{"secure-delete"})

	err := rootCmd.Execute()
	assert.Error(t, err, "Secure-delete without path should fail")
}

// TestCLI_Help tests the root help command
func TestCLI_Help(t *testing.T) {
	rootCmd := cli.GetRootCmd()
	rootCmd.SetArgs([]string{"--help"})

	// Help should not error
	err := rootCmd.Execute()
	assert.NoError(t, err, "Help command should succeed")
}

// TestCLI_Version tests the version command
func TestCLI_Version(t *testing.T) {
	rootCmd := cli.GetRootCmd()
	rootCmd.SetArgs([]string{"--version"})

	// Version should not error
	err := rootCmd.Execute()
	assert.NoError(t, err, "Version command should succeed")
}

// TestCLI_Config_Show tests config show command
func TestCLI_Config_Show(t *testing.T) {
	rootCmd := cli.GetRootCmd()
	rootCmd.SetArgs([]string{"config", "--show"})

	// Config show should not error (even if no config exists)
	err := rootCmd.Execute()
	assert.NoError(t, err, "Config show should succeed")
}

// Helper function to create a temporary test file
func createTempTestFile(t *testing.T, content string) string {
	tmpFile, err := os.CreateTemp("", "nokvault-test-*.txt")
	require.NoError(t, err, "Failed to create temp file")
	defer tmpFile.Close()

	_, err = tmpFile.WriteString(content)
	require.NoError(t, err, "Failed to write test content")

	return tmpFile.Name()
}

// Helper function to create a temporary test directory
func createTempTestDir(t *testing.T) string {
	tmpDir, err := os.MkdirTemp("", "nokvault-test-dir-*")
	require.NoError(t, err, "Failed to create temp directory")
	return tmpDir
}

// TestCLI_Encrypt_File_WithPassword tests encrypting a file with password
func TestCLI_Encrypt_File_WithPassword(t *testing.T) {
	// Create a temporary test file
	testFile := createTempTestFile(t, "test content for encryption")
	defer os.Remove(testFile)

	// Create output path
	outputFile := testFile + ".nokvault"
	defer os.Remove(outputFile)

	rootCmd := cli.GetRootCmd()
	rootCmd.SetArgs([]string{
		"encrypt",
		testFile,
		"--output", outputFile,
		"--password", "test-password-123",
		"--no-prompt",
	})

	err := rootCmd.Execute()
	assert.NoError(t, err, "Encrypt with password should succeed")

	// Verify encrypted file was created
	_, err = os.Stat(outputFile)
	assert.NoError(t, err, "Encrypted file should exist")
}

// TestCLI_Decrypt_File_WithPassword tests decrypting a file with password
func TestCLI_Decrypt_File_WithPassword(t *testing.T) {
	// First encrypt a file
	testFile := createTempTestFile(t, "test content for decryption")
	defer os.Remove(testFile)

	encryptedFile := testFile + ".nokvault"
	defer os.Remove(encryptedFile)

	rootCmd := cli.GetRootCmd()
	rootCmd.SetArgs([]string{
		"encrypt",
		testFile,
		"--output", encryptedFile,
		"--password", "test-password-123",
		"--no-prompt",
	})

	err := rootCmd.Execute()
	require.NoError(t, err, "Encrypt should succeed")

	// Now decrypt it
	decryptedFile := testFile + ".decrypted"
	defer os.Remove(decryptedFile)

	rootCmd.SetArgs([]string{
		"decrypt",
		encryptedFile,
		"--output", decryptedFile,
		"--password", "test-password-123",
		"--no-prompt",
	})

	err = rootCmd.Execute()
	assert.NoError(t, err, "Decrypt with password should succeed")

	// Verify decrypted file exists and has correct content
	decryptedContent, err := os.ReadFile(decryptedFile)
	require.NoError(t, err, "Failed to read decrypted file")
	assert.Equal(t, "test content for decryption", string(decryptedContent), "Decrypted content should match original")
}

// TestCLI_Encrypt_Directory tests encrypting a directory
func TestCLI_Encrypt_Directory(t *testing.T) {
	// Create a temporary test directory with files
	testDir := createTempTestDir(t)
	defer os.RemoveAll(testDir)

	// Create test files in directory
	testFile1 := filepath.Join(testDir, "file1.txt")
	err := os.WriteFile(testFile1, []byte("content 1"), 0644)
	require.NoError(t, err)

	testFile2 := filepath.Join(testDir, "file2.txt")
	err = os.WriteFile(testFile2, []byte("content 2"), 0644)
	require.NoError(t, err)

	// Create output directory
	outputDir := testDir + "-encrypted"
	defer os.RemoveAll(outputDir)

	rootCmd := cli.GetRootCmd()
	rootCmd.SetArgs([]string{
		"encrypt",
		testDir,
		"--output", outputDir,
		"--password", "test-password-123",
		"--no-prompt",
	})

	err = rootCmd.Execute()
	assert.NoError(t, err, "Encrypt directory should succeed")

	// Verify encrypted files exist
	encryptedFile1 := filepath.Join(outputDir, "file1.txt.nokvault")
	_, err = os.Stat(encryptedFile1)
	assert.NoError(t, err, "Encrypted file1 should exist")

	encryptedFile2 := filepath.Join(outputDir, "file2.txt.nokvault")
	_, err = os.Stat(encryptedFile2)
	assert.NoError(t, err, "Encrypted file2 should exist")
}

// TestCLI_Encrypt_WrongPassword tests encrypt/decrypt with wrong password
func TestCLI_Encrypt_WrongPassword(t *testing.T) {
	// Create and encrypt a file
	testFile := createTempTestFile(t, "test content")
	defer os.Remove(testFile)

	encryptedFile := testFile + ".nokvault"
	defer os.Remove(encryptedFile)

	rootCmd := cli.GetRootCmd()
	rootCmd.SetArgs([]string{
		"encrypt",
		testFile,
		"--output", encryptedFile,
		"--password", "correct-password",
		"--no-prompt",
	})

	err := rootCmd.Execute()
	require.NoError(t, err, "Encrypt should succeed")

	// Try to decrypt with wrong password
	decryptedFile := testFile + ".decrypted"
	defer os.Remove(decryptedFile)

	rootCmd.SetArgs([]string{
		"decrypt",
		encryptedFile,
		"--output", decryptedFile,
		"--password", "wrong-password",
		"--no-prompt",
	})

	err = rootCmd.Execute()
	assert.Error(t, err, "Decrypt with wrong password should fail")
}

// TestCLI_Commands_Flags tests that commands have expected flags
func TestCLI_Commands_Flags(t *testing.T) {
	rootCmd := cli.GetRootCmd()

	tests := []struct {
		command    string
		flagName   string
		shouldHave bool
	}{
		{"encrypt", "output", true},
		{"encrypt", "password", true},
		{"encrypt", "keyfile", true},
		{"encrypt", "no-prompt", true},
		{"decrypt", "output", true},
		{"decrypt", "password", true},
		{"decrypt", "keyfile", true},
		{"secure-delete", "passes", true},
		{"secure-delete", "verbose", true},
	}

	for _, tt := range tests {
		cmd, _, err := rootCmd.Find([]string{tt.command})
		require.NoError(t, err, "Command %s should exist", tt.command)

		if tt.shouldHave {
			flag := cmd.Flags().Lookup(tt.flagName)
			assert.NotNil(t, flag, "Command %s should have flag %s", tt.command, tt.flagName)
		}
	}
}
