package integration

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jimididit/nokvault/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetBannerCLI(t *testing.T) {
	t.Helper()
	cli.ResetCLIStateForTest()
	t.Cleanup(cli.ResetCLIStateForTest)
}

func assertNoBanner(t *testing.T, output string) {
	t.Helper()
	assert.NotContains(t, output, "███╗")
	assert.NotContains(t, output, `/_/|_/\____/`)
	assert.NotContains(t, output, "LOCAL ENCRYPTION, DELIBERATELY PRIVATE")
	assert.NotRegexp(t, `(?m)^NOKVAULT$`, output)
}

func TestCLIRedirectedRootHelpIsBannerFree(t *testing.T) {
	resetBannerCLI(t)
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run([]string{"--help"}, &stdout, &stderr)

	require.Zero(t, exitCode)
	assert.Contains(t, stdout.String(), "Usage:")
	assertNoBanner(t, stdout.String())
	assert.NotContains(t, stdout.String(), "\x1b[")
	assert.Empty(t, stderr.String())
}

func TestCLISubcommandHelpIsBannerFree(t *testing.T) {
	resetBannerCLI(t)
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run([]string{"encrypt", "--help"}, &stdout, &stderr)

	require.Zero(t, exitCode)
	assert.Contains(t, stdout.String(), "encrypt")
	assertNoBanner(t, stdout.String())
	assert.Empty(t, stderr.String())
}

func TestCLIVersionRemainsOneBannerFreeLine(t *testing.T) {
	resetBannerCLI(t)
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run([]string{"--version"}, &stdout, &stderr)

	require.Zero(t, exitCode)
	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	assert.Len(t, lines, 1)
	assertNoBanner(t, stdout.String())
	assert.Empty(t, stderr.String())
}

func TestCLIJSONErrorIsBannerFree(t *testing.T) {
	resetBannerCLI(t)
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run(
		[]string{"encrypt", filepath.Join(t.TempDir(), "missing"), "--json", "--no-prompt"},
		&stdout,
		&stderr,
	)

	require.NotZero(t, exitCode)
	assertNoBanner(t, stdout.String())
	assert.NotContains(t, stdout.String(), "\x1b[")
	assert.Empty(t, stderr.String())
	var record cli.Record
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &record))
	assert.Equal(t, "error", record.Type)
}

func TestCLIHumanErrorIsBannerFree(t *testing.T) {
	resetBannerCLI(t)
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run([]string{"not-a-command"}, &stdout, &stderr)

	require.NotZero(t, exitCode)
	assertNoBanner(t, stdout.String())
	assertNoBanner(t, stderr.String())
}

func TestCLIRootHelpCommandIsBannerFree(t *testing.T) {
	resetBannerCLI(t)
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run([]string{"help"}, &stdout, &stderr)

	require.Zero(t, exitCode)
	assert.Contains(t, stdout.String(), "Usage:")
	assertNoBanner(t, stdout.String())
	assertNoBanner(t, stderr.String())
	assert.Empty(t, stderr.String())
	assert.NotContains(t, stdout.String(), "\x1b[")
}

func TestCLICompletionHelpIsBannerFree(t *testing.T) {
	resetBannerCLI(t)
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run([]string{"completion", "--help"}, &stdout, &stderr)

	require.Zero(t, exitCode)
	assert.Contains(t, stdout.String(), "completion")
	assertNoBanner(t, stdout.String())
	assertNoBanner(t, stderr.String())
	assert.Empty(t, stderr.String())
}

func TestCLICompletionScriptsAreBannerFree(t *testing.T) {
	resetBannerCLI(t)
	root := cli.GetRootCmd()

	var bash, zsh, fish, powershell bytes.Buffer
	require.NoError(t, root.GenBashCompletionV2(&bash, true))
	require.NoError(t, root.GenZshCompletion(&zsh))
	require.NoError(t, root.GenFishCompletion(&fish, true))
	require.NoError(t, root.GenPowerShellCompletionWithDesc(&powershell))

	for name, output := range map[string]string{
		"bash":       bash.String(),
		"zsh":        zsh.String(),
		"fish":       fish.String(),
		"powershell": powershell.String(),
	} {
		t.Run(name, func(t *testing.T) {
			require.NotEmpty(t, output)
			assertNoBanner(t, output)
		})
	}
}
