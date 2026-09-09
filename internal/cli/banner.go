package cli

import (
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
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

var bannerStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#7DD3FC")).
	Bold(true)

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
	return renderBannerWithStyle(caps, func(s string) string { return bannerStyle.Render(s) })
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
