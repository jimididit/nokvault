package cli

import (
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const wideBanner = `███╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
████╗  ██║██╔═══██╗██║ ██╔╝██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
██╔██╗ ██║██║   ██║█████╔╝ ██║   ██║███████║██║   ██║██║     ██║
██║╚██╗██║██║   ██║██╔═██╗ ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║
██║ ╚████║╚██████╔╝██║  ██╗ ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║
╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝
      LOCAL ENCRYPTION, DELIBERATELY PRIVATE`

const compactBanner = `   _  ______  __ ___   _____  __  ____ ______
  / |/ / __ \/ //_/ | / / _ |/ / / / //_  __/
 /    / /_/ / ,<  | |/ / __ / /_/ / /__/ /
/_/|_/\____/_/|_| |___/_/ |_\____/____/_/
      LOCAL ENCRYPTION, DELIBERATELY PRIVATE`

const minimalBanner = "NOKVAULT"

type bannerCapabilities struct {
	interactive bool
	width       int
	color       bool
	minimal     bool
}

type fdWriter interface {
	Fd() uintptr
}

func bannerStyle() lipgloss.Style {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7DD3FC")).
		Bold(true)
}

func bannerText(caps bannerCapabilities) string {
	if !caps.interactive {
		return ""
	}
	if caps.minimal || (caps.width > 0 && caps.width < 56) {
		return minimalBanner
	}
	if caps.width >= 72 {
		return wideBanner
	}
	return compactBanner
}

func renderBanner(caps bannerCapabilities) string {
	style := bannerStyle()
	return renderBannerWithStyle(caps, func(s string) string { return style.Render(s) })
}

func renderBannerWithStyle(caps bannerCapabilities, style func(string) string) string {
	text := bannerText(caps)
	if text == "" {
		return ""
	}
	if caps.color && !caps.minimal {
		text = style(text)
	}
	return text + "\n\n"
}

func systemBannerCapabilities(output io.Writer) bannerCapabilities {
	_, noColor := os.LookupEnv("NO_COLOR")
	caps := bannerCapabilities{
		color:   !noColor,
		minimal: strings.EqualFold(os.Getenv("TERM"), "dumb"),
	}
	writer, ok := output.(fdWriter)
	if !ok {
		return caps
	}
	fd := int(writer.Fd())
	caps.interactive = term.IsTerminal(fd)
	if width, _, err := term.GetSize(fd); err == nil {
		caps.width = width
	}
	return caps
}

type bannerCapabilityDetector func(io.Writer) bannerCapabilities

func wrapRootHelp(
	root *cobra.Command,
	next func(*cobra.Command, []string) error,
	detect bannerCapabilityDetector,
) func(*cobra.Command, []string) error {
	return func(target *cobra.Command, args []string) error {
		if target == root && !jsonOutput {
			banner := renderBanner(detect(target.OutOrStdout()))
			if banner != "" {
				if _, err := io.WriteString(target.OutOrStdout(), banner); err != nil {
					return err
				}
			}
		}
		return next(target, args)
	}
}

func installRootHelpBanner(root *cobra.Command) {
	installRootHelpBannerWith(root, systemBannerCapabilities)
}

func installRootHelpBannerWith(root *cobra.Command, detect bannerCapabilityDetector) {
	next := root.HelpFunc()
	wrapped := wrapRootHelp(root, func(cmd *cobra.Command, args []string) error {
		next(cmd, args)
		return nil
	}, detect)
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if err := wrapped(cmd, args); err != nil {
			cmd.PrintErrln(err)
		}
	})
}
