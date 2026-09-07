package integration

import (
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
