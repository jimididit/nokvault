package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	assert.Contains(t, styled, "<cyan>")
	assert.NotContains(t, plain, "<cyan>")
	assert.NotContains(t, dumb, "<cyan>")
	assert.Equal(t, bannerGolden(t, "banner_wide.golden")+"\n\n", plain)
}

func TestSystemBannerCapabilitiesTreatsBufferAsNonInteractive(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	caps := systemBannerCapabilities(&bytes.Buffer{})
	assert.False(t, caps.interactive)
	assert.False(t, caps.color)
}
