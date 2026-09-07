package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jimididit/nokvault/internal/utils"
	"golang.org/x/term"
)

func isInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// confirmDestructive prints prompt and requires the user to type "yes".
func confirmDestructive(r io.Reader, w io.Writer, prompt string) error {
	if _, err := fmt.Fprintf(w, "%s\nType 'yes' to confirm: ", prompt); err != nil {
		return err
	}
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return err
		}
		return utils.NewErrorWithHint(
			utils.ErrConfirmationRequired.Code,
			"Confirmation required",
			nil,
			"Type yes to confirm, or pass --yes.",
		)
	}
	answer := strings.TrimSpace(scanner.Text())
	if !strings.EqualFold(answer, "yes") {
		return utils.NewErrorWithHint(
			utils.ErrConfirmationRequired.Code,
			"Confirmation declined",
			nil,
			"Type yes to confirm, or pass --yes.",
		)
	}
	return nil
}

// requireConfirmation allows the operation when yesFlag is set, or when
// interactive stdin confirms with "yes". Non-interactive sessions without
// --yes fail closed.
func requireConfirmation(yesFlag, interactive bool, r io.Reader, w io.Writer) error {
	if yesFlag {
		return nil
	}
	if interactive {
		return confirmDestructive(r, w, "WARNING: This operation is irreversible!")
	}
	return utils.NewErrorWithHint(
		utils.ErrConfirmationRequired.Code,
		"Refusing non-interactive secure-delete without --yes",
		nil,
		"Pass --yes to confirm, or run in a terminal and type yes when prompted.",
	)
}

// refuseIfExists returns OUTPUT_EXISTS when path exists and force is false.
func refuseIfExists(path string, force bool) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if force && info.Mode().IsRegular() {
		return nil
	}
	if force {
		return utils.NewErrorWithHint(
			utils.ErrOutputExists.Code,
			fmt.Sprintf("Refusing to overwrite non-regular output path: %s", path),
			nil,
			"Choose a regular file path; --force never replaces directories, symlinks, or devices.",
		)
	}
	return utils.NewErrorWithHint(
		utils.ErrOutputExists.Code,
		fmt.Sprintf("Output already exists: %s", path),
		nil,
		"Pass --force to overwrite the existing output path.",
	)
}
