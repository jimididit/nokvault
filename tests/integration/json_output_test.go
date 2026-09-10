package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jimididit/nokvault/internal/cli"
	"github.com/stretchr/testify/require"
)

func runJSONCLI(t *testing.T, args ...string) (int, cli.Record, string, string) {
	t.Helper()
	cli.ResetCLIStateForTest()
	t.Cleanup(cli.ResetCLIStateForTest)
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run(args, &stdout, &stderr)

	var record cli.Record
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &record), stdout.String())
	require.Equal(t, cli.JSONSchemaVersion, record.SchemaVersion)
	require.NotContains(t, stdout.String(), "\x1b[")
	require.NotContains(t, stdout.String(), "✓")
	require.NotContains(t, stdout.String(), "ℹ")
	require.Equal(t, 1, len(strings.Split(strings.TrimSpace(stdout.String()), "\n")))
	return exitCode, record, stdout.String(), stderr.String()
}

func resultData(t *testing.T, record cli.Record) map[string]any {
	t.Helper()
	data, ok := record.Data.(map[string]any)
	require.True(t, ok)
	return data
}

func TestJSONEncryptAndDecryptFile(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(input, []byte("payload"), 0o600))
	keyfile := writeTempKeyfile(t, "json-password")

	exitCode, record, _, stderr := runJSONCLI(
		t, "encrypt", input, "--keyfile", keyfile, "--no-prompt", "--json",
	)
	require.Zero(t, exitCode)
	require.Empty(t, stderr)
	require.Equal(t, "result", record.Type)
	require.Equal(t, "encrypt", record.Command)
	data := resultData(t, record)
	require.Equal(t, input, data["input"])
	require.Equal(t, input+".nokv", data["output"])
	require.Equal(t, "file", data["target_kind"])
	require.Equal(t, float64(1), data["processed"])
	require.Equal(t, float64(1), data["succeeded"])

	output := filepath.Join(dir, "roundtrip.txt")
	exitCode, record, _, stderr = runJSONCLI(
		t, "decrypt", input+".nokv", "--keyfile", keyfile,
		"--no-prompt", "--output", output, "--json",
	)
	require.Zero(t, exitCode)
	require.Empty(t, stderr)
	require.Equal(t, "result", record.Type)
	require.Equal(t, "decrypt", record.Command)
	require.Equal(t, output, resultData(t, record)["output"])
	plaintext, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, "payload", string(plaintext))
}

func TestJSONEncryptDryRunDoesNotMutate(t *testing.T) {
	input := filepath.Join(t.TempDir(), "plain.txt")
	require.NoError(t, os.WriteFile(input, []byte("payload"), 0o600))

	exitCode, record, _, stderr := runJSONCLI(t, "encrypt", input, "--dry-run", "--json")

	require.Zero(t, exitCode)
	require.Empty(t, stderr)
	require.Equal(t, true, resultData(t, record)["dry_run"])
	_, err := os.Stat(input + ".nokv")
	require.True(t, os.IsNotExist(err))
}

func TestJSONDecryptDryRunDoesNotRequireCredentialsOrMutate(t *testing.T) {
	input := filepath.Join(t.TempDir(), "sample.nokv")
	require.NoError(t, os.WriteFile(input, []byte("not-read-in-dry-run"), 0o600))

	exitCode, record, _, stderr := runJSONCLI(t, "decrypt", input, "--dry-run", "--json")

	require.Zero(t, exitCode)
	require.Empty(t, stderr)
	require.Equal(t, true, resultData(t, record)["dry_run"])
	_, err := os.Stat(strings.TrimSuffix(input, ".nokv"))
	require.True(t, os.IsNotExist(err))
}

func TestJSONDecryptPartialAndStrictResults(t *testing.T) {
	dir := t.TempDir()
	vaultDir := filepath.Join(dir, "vault")
	require.NoError(t, os.MkdirAll(vaultDir, 0o700))
	keyfile := writeTempKeyfile(t, "json-directory-password")
	plain := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(plain, []byte("ok"), 0o600))

	exitCode, _, _, _ := runJSONCLI(
		t, "encrypt", plain, "--output", filepath.Join(vaultDir, "z_good.txt.nokv"),
		"--keyfile", keyfile, "--no-prompt", "--json",
	)
	require.Zero(t, exitCode)
	require.NoError(t, os.WriteFile(filepath.Join(vaultDir, "a_bad.nokv"), []byte("bad"), 0o600))

	exitCode, record, _, stderr := runJSONCLI(
		t, "decrypt", vaultDir, "--output", filepath.Join(dir, "continue"),
		"--keyfile", keyfile, "--no-prompt", "--json",
	)
	require.NotZero(t, exitCode)
	require.Empty(t, stderr)
	require.Equal(t, "error", record.Type)
	require.Equal(t, "PARTIAL_FAILURE", record.Error.Code)
	data := resultData(t, record)
	require.Equal(t, float64(1), data["succeeded"])
	require.Equal(t, float64(1), data["failed"])

	exitCode, record, _, stderr = runJSONCLI(
		t, "decrypt", vaultDir, "--output", filepath.Join(dir, "strict"),
		"--keyfile", keyfile, "--no-prompt", "--strict", "--json",
	)
	require.NotZero(t, exitCode)
	require.Empty(t, stderr)
	require.Equal(t, "PARTIAL_FAILURE", record.Error.Code)
	data = resultData(t, record)
	require.Equal(t, float64(0), data["succeeded"])
	require.Equal(t, float64(1), data["failed"])
	require.Equal(t, "a_bad.nokv", data["aborted_at"])
}

func TestJSONSecureDeleteDryRunAndDelete(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.txt")
	second := filepath.Join(dir, "nested", "second.txt")
	require.NoError(t, os.MkdirAll(filepath.Dir(second), 0o700))
	require.NoError(t, os.WriteFile(first, []byte("first"), 0o600))
	require.NoError(t, os.WriteFile(second, []byte("second"), 0o600))

	exitCode, record, _, stderr := runJSONCLI(t, "secure-delete", dir, "--dry-run", "--json")
	require.Zero(t, exitCode)
	require.Empty(t, stderr)
	data := resultData(t, record)
	require.Equal(t, true, data["dry_run"])
	require.Equal(t, float64(2), data["processed"])
	require.Len(t, data["paths"], 2)
	_, err := os.Stat(first)
	require.NoError(t, err)

	exitCode, record, _, stderr = runJSONCLI(t, "secure-delete", dir, "--yes", "--json")
	require.Zero(t, exitCode)
	require.Empty(t, stderr)
	data = resultData(t, record)
	require.Equal(t, float64(2), data["succeeded"])
	_, err = os.Stat(first)
	require.True(t, os.IsNotExist(err))
	_, err = os.Stat(second)
	require.True(t, os.IsNotExist(err))
}

func TestJSONSecureDeleteRequiresYes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(path, []byte("secret"), 0o600))

	exitCode, record, _, stderr := runJSONCLI(t, "secure-delete", path, "--json")

	require.NotZero(t, exitCode)
	require.Empty(t, stderr)
	require.Equal(t, "error", record.Type)
	require.Equal(t, "CONFIRMATION_REQUIRED", record.Error.Code)
	_, err := os.Stat(path)
	require.NoError(t, err)
}

func TestJSONRotateKey(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(input, []byte("payload"), 0o600))
	oldKeyfile := writeTempKeyfile(t, "old-json-password")
	newKeyfile := writeTempKeyfile(t, "new-json-password")

	exitCode, _, _, _ := runJSONCLI(
		t, "encrypt", input, "--keyfile", oldKeyfile, "--no-prompt", "--json",
	)
	require.Zero(t, exitCode)
	encrypted := input + ".nokv"

	exitCode, record, _, stderr := runJSONCLI(
		t, "rotate-key", encrypted,
		"--old-keyfile", oldKeyfile, "--new-keyfile", newKeyfile,
		"--no-prompt", "--json",
	)
	require.Zero(t, exitCode)
	require.Empty(t, stderr)
	require.Equal(t, "result", record.Type)
	require.Equal(t, "rotate-key", record.Command)
	data := resultData(t, record)
	require.Equal(t, encrypted, data["path"])
	require.Equal(t, "rotated", data["status"])

	output := filepath.Join(dir, "new-key-output.txt")
	exitCode, _, _, stderr = runJSONCLI(
		t, "decrypt", encrypted, "--keyfile", newKeyfile,
		"--no-prompt", "--output", output, "--json",
	)
	require.Zero(t, exitCode)
	require.Empty(t, stderr)
}

func TestJSONCredentialCommandsNeverPrompt(t *testing.T) {
	t.Setenv("NOKVAULT_PASSWORD", "")
	path := filepath.Join(t.TempDir(), "input.txt")
	require.NoError(t, os.WriteFile(path, []byte("payload"), 0o600))

	tests := []struct {
		name string
		args []string
	}{
		{name: "encrypt", args: []string{"encrypt", path, "--json"}},
		{name: "decrypt", args: []string{"decrypt", path, "--json"}},
		{name: "rotate-key", args: []string{"rotate-key", path, "--json"}},
		{name: "watch", args: []string{"watch", path, "--auto-encrypt", "--json"}},
		{name: "schedule", args: []string{"schedule", "encrypt", path, "--json"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exitCode, record, _, stderr := runJSONCLI(t, tt.args...)
			require.NotZero(t, exitCode)
			require.Empty(t, stderr)
			require.Equal(t, "error", record.Type)
			require.Equal(t, "INVALID_PASSWORD", record.Error.Code)
		})
	}
}

func TestJSONRotateKeyVerboseWrongCredentialOmitsDiagnostic(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(input, []byte("payload"), 0o600))
	oldKeyfile := writeTempKeyfile(t, "correct-password")
	wrongKeyfile := writeTempKeyfile(t, "wrong-password")
	newKeyfile := writeTempKeyfile(t, "new-password")

	exitCode, _, _, _ := runJSONCLI(t, "encrypt", input, "--keyfile", oldKeyfile, "--no-prompt", "--json")
	require.Zero(t, exitCode)

	exitCode, record, stdout, stderr := runJSONCLI(
		t, "rotate-key", input+".nokv",
		"--old-keyfile", wrongKeyfile, "--new-keyfile", newKeyfile,
		"--no-prompt", "--verbose", "--json",
	)
	require.NotZero(t, exitCode)
	require.Empty(t, stderr)
	require.Equal(t, "DECRYPTION_FAILED", record.Error.Code)
	require.Empty(t, record.Error.Details)
	require.NotContains(t, stdout, "cipher:")
}

func TestHumanRunRetainsHumanErrorRendering(t *testing.T) {
	cli.ResetCLIStateForTest()
	t.Cleanup(cli.ResetCLIStateForTest)
	var stdout, stderr bytes.Buffer

	exitCode := cli.Run([]string{"encrypt", filepath.Join(t.TempDir(), "missing")}, &stdout, &stderr)

	require.NotZero(t, exitCode)
	require.NotContains(t, stderr.String(), `"schema_version"`)
	require.Contains(t, stderr.String(), "Error:")
	require.Contains(t, stderr.String(), "INVALID_PATH")
}
