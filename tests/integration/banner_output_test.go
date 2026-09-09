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
	assert.NotContains(t, output, "LOCAL ENCRYPTION, DELIBERATELY PRIVATE")
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
