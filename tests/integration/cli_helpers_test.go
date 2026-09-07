package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jimididit/nokvault/internal/cli"
	"github.com/spf13/cobra"
)

// freshRootCmd resets CLI flag state so tests do not leak Cobra bindings.
func freshRootCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cli.ResetCLIStateForTest()
	t.Cleanup(cli.ResetCLIStateForTest)
	return cli.GetRootCmd()
}

// writeTempKeyfile writes a 0600 keyfile for CLI tests (argv passwords are refused).
func writeTempKeyfile(t *testing.T, password string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keyfile")
	if err := os.WriteFile(path, []byte(password), 0o600); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}
	return path
}
