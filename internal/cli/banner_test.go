package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func bannerGolden(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return strings.TrimSuffix(string(content), "\n")
}

func TestBannerTextSelectsResponsiveTier(t *testing.T) {
	tests := []struct {
		name   string
		caps   bannerCapabilities
		golden string
	}{
		{"wide boundary", bannerCapabilities{interactive: true, width: 72}, "banner_wide.golden"},
		{"compact upper boundary", bannerCapabilities{interactive: true, width: 71}, "banner_compact.golden"},
		{"compact lower boundary", bannerCapabilities{interactive: true, width: 56}, "banner_compact.golden"},
		{"unknown width", bannerCapabilities{interactive: true}, "banner_compact.golden"},
		{"minimal boundary", bannerCapabilities{interactive: true, width: 55}, "banner_minimal.golden"},
		{"dumb terminal", bannerCapabilities{interactive: true, width: 120, minimal: true}, "banner_minimal.golden"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, bannerGolden(t, tt.golden), bannerText(tt.caps))
		})
	}
}

func TestBannerTextNeverExceedsKnownWidth(t *testing.T) {
	for _, width := range []int{40, 55, 56, 71, 72, 80, 120} {
		text := bannerText(bannerCapabilities{interactive: true, width: width})
		for _, line := range strings.Split(text, "\n") {
			assert.LessOrEqual(t, len([]rune(line)), width, "width=%d line=%q", width, line)
		}
	}
}

func TestRenderBannerRequiresInteractiveOutput(t *testing.T) {
	assert.Empty(t, renderBanner(bannerCapabilities{width: 120, color: true}))
}

func TestRenderBannerColorPolicy(t *testing.T) {
	styler := func(text string) string { return "<cyan>" + text + "</cyan>" }
	styled := renderBannerWithStyle(
		bannerCapabilities{interactive: true, width: 72, color: true},
		styler,
	)
	plain := renderBannerWithStyle(
		bannerCapabilities{interactive: true, width: 72, color: false},
		styler,
	)
	dumb := renderBannerWithStyle(
		bannerCapabilities{interactive: true, width: 72, color: true, minimal: true},
		styler,
	)

	wide := bannerGolden(t, "banner_wide.golden")
	assert.Equal(t, "<cyan>"+wide+"</cyan>\n\n", styled)
	assert.NotContains(t, plain, "<cyan>")
	assert.NotContains(t, dumb, "<cyan>")
	assert.Equal(t, wide+"\n\n", plain)
	assert.Equal(t, bannerGolden(t, "banner_minimal.golden")+"\n\n", dumb)
}

func TestSystemBannerCapabilitiesTreatsBufferAsNonInteractive(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	caps := systemBannerCapabilities(&bytes.Buffer{})
	assert.False(t, caps.interactive)
	assert.False(t, caps.color)
}

func TestSystemBannerCapabilitiesHonorsDumbTERMWithoutPTY(t *testing.T) {
	t.Setenv("TERM", "dumb")
	original, hadNOColor := os.LookupEnv("NO_COLOR")
	require.NoError(t, os.Unsetenv("NO_COLOR"))
	t.Cleanup(func() {
		if hadNOColor {
			require.NoError(t, os.Setenv("NO_COLOR", original))
		}
	})

	caps := systemBannerCapabilities(&bytes.Buffer{})
	assert.False(t, caps.interactive)
	assert.Zero(t, caps.width)
	assert.True(t, caps.minimal)
	assert.True(t, caps.color)
}

func TestBannerGoldensUseLF(t *testing.T) {
	for _, name := range []string{"banner_wide.golden", "banner_compact.golden", "banner_minimal.golden"} {
		content, err := os.ReadFile(filepath.Join("testdata", name))
		require.NoError(t, err, name)
		assert.NotContains(t, string(content), "\r", name)
	}
}

func TestWrapRootHelpTargetsOnlyRoot(t *testing.T) {
	root := &cobra.Command{Use: "nokvault"}
	child := &cobra.Command{Use: "encrypt"}
	root.AddCommand(child)
	var output bytes.Buffer
	root.SetOut(&output)
	next := func(cmd *cobra.Command, args []string) error {
		_, err := io.WriteString(cmd.OutOrStdout(), "Usage: delegated\n")
		return err
	}
	detect := func(io.Writer) bannerCapabilities {
		return bannerCapabilities{interactive: true, width: 72}
	}
	help := wrapRootHelp(root, next, detect)

	require.NoError(t, help(root, nil))
	assert.Contains(t, output.String(), "███╗")
	assert.Contains(t, output.String(), "Usage: delegated")

	output.Reset()
	require.NoError(t, help(child, nil))
	assert.NotContains(t, output.String(), "███╗")
	assert.Equal(t, "Usage: delegated\n", output.String())
}

func TestWrapRootHelpSuppressesBannerForJSONFlag(t *testing.T) {
	root := &cobra.Command{Use: "nokvault"}
	var output bytes.Buffer
	root.SetOut(&output)
	next := func(cmd *cobra.Command, args []string) error {
		_, err := io.WriteString(cmd.OutOrStdout(), "Usage: delegated\n")
		return err
	}
	detect := func(io.Writer) bannerCapabilities {
		return bannerCapabilities{interactive: true, width: 72}
	}
	previous := jsonOutput
	t.Cleanup(func() { jsonOutput = previous })
	jsonOutput = true

	require.NoError(t, wrapRootHelp(root, next, detect)(root, nil))
	assert.Equal(t, "Usage: delegated\n", output.String())
}

type rejectedWriter struct{}

func (rejectedWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestWrapRootHelpReturnsBannerWriteError(t *testing.T) {
	root := &cobra.Command{Use: "nokvault"}
	root.SetOut(rejectedWriter{})
	delegated := false
	next := func(*cobra.Command, []string) error {
		delegated = true
		return nil
	}
	detect := func(io.Writer) bannerCapabilities {
		return bannerCapabilities{interactive: true, width: 72}
	}

	err := wrapRootHelp(root, next, detect)(root, nil)
	require.ErrorIs(t, err, io.ErrClosedPipe)
	assert.False(t, delegated)
}

func TestInstallRootHelpBannerWritesHelpFuncErrorsToStderr(t *testing.T) {
	root := &cobra.Command{Use: "nokvault"}
	root.SetOut(rejectedWriter{})
	var stderr bytes.Buffer
	root.SetErr(&stderr)
	delegated := false
	root.SetHelpFunc(func(*cobra.Command, []string) {
		delegated = true
	})
	installRootHelpBannerWith(root, func(io.Writer) bannerCapabilities {
		return bannerCapabilities{interactive: true, width: 72}
	})

	root.HelpFunc()(root, nil)

	assert.False(t, delegated)
	assert.Contains(t, stderr.String(), io.ErrClosedPipe.Error())
	assert.NotContains(t, stderr.String(), "███╗")
}
