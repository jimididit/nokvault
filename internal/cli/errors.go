package cli

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/jimididit/nokvault/internal/utils"
)

// PrintErrorWithHint prints an error message with a helpful hint
func PrintErrorWithHint(err error) {
	errorStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("1")).
		Bold(true)

	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("3")).
		Italic(true)

	if nokvaultErr, ok := err.(*utils.NokvaultError); ok {
		fmt.Fprintf(os.Stderr, "%s\n", errorStyle.Render("Error: "+nokvaultErr.Error()))
		if hint := nokvaultErr.GetHint(); hint != "" {
			fmt.Fprintf(os.Stderr, "%s\n", hintStyle.Render("💡 Hint: "+hint))
		}
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", errorStyle.Render("Error: "+err.Error()))
	}
}

// PrintError prints an error message with styling
func PrintError(message string) {
	errorStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("1")).
		Bold(true)
	fmt.Fprintf(os.Stderr, "%s\n", errorStyle.Render("Error: "+message))
}

// PrintSuccess prints a success message with styling
func PrintSuccess(message string) {
	successStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("2")).
		Bold(true)
	fmt.Fprintf(os.Stdout, "%s\n", successStyle.Render("✓ "+message))
}

// PrintInfo prints an info message with styling
func PrintInfo(message string) {
	infoStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("4"))
	fmt.Fprintf(os.Stdout, "%s\n", infoStyle.Render("ℹ "+message))
}

// PrintWarning prints a warning message with styling
func PrintWarning(message string) {
	warningStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("3")).
		Bold(true)
	fmt.Fprintf(os.Stderr, "%s\n", warningStyle.Render("⚠ Warning: "+message))
}
