package cli

import (
	"fmt"
	"os"

	"github.com/jimididit/nokvault/internal/core"
	"github.com/jimididit/nokvault/internal/utils"
	"github.com/spf13/cobra"
)

var secureDeleteCmd = &cobra.Command{
	Use:   "secure-delete <path>",
	Short: "Securely delete a file or directory by overwriting multiple times",
	Long: `Securely delete a file (or all files under a directory) by overwriting
with random/pattern data multiple times before deletion. This makes recovery
much harder on traditional spinning disks.

WARNING: This operation is irreversible! On SSDs and copy-on-write filesystems,
multi-pass overwrite may not fully erase prior data.

Non-interactive use requires --yes. Use --dry-run to list paths without deleting.`,
	Args: cobra.ExactArgs(1),
	RunE: runSecureDelete,
}

var (
	secureDeletePasses  int
	secureDeleteVerbose bool
	secureDeleteYes     bool
	secureDeleteDryRun  bool
)

func init() {
	secureDeleteCmd.Flags().IntVarP(&secureDeletePasses, "passes", "p", 3, "Number of overwrite passes (default: 3)")
	secureDeleteCmd.Flags().BoolVarP(&secureDeleteVerbose, "verbose", "v", false, "Verbose output")
	secureDeleteCmd.Flags().BoolVarP(&secureDeleteYes, "yes", "y", false, "Confirm deletion without prompting")
	secureDeleteCmd.Flags().BoolVar(&secureDeleteDryRun, "dry-run", false, "List paths that would be deleted without deleting")

	rootCmd.AddCommand(secureDeleteCmd)
}

func runSecureDelete(cmd *cobra.Command, args []string) error {
	path := args[0]

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		PrintError(fmt.Sprintf("Path does not exist: %s", path))
		return utils.NewError(utils.ErrFileNotFound.Code, fmt.Sprintf("Path does not exist: %s", path), err)
	}

	if secureDeleteDryRun {
		if info.IsDir() {
			return dryRunSecureDeleteDirectory(path)
		}
		PrintInfo(fmt.Sprintf("Would securely delete: %s", path))
		return nil
	}

	if err := requireConfirmation(secureDeleteYes, isInteractive(), os.Stdin, os.Stderr); err != nil {
		PrintError(err.Error())
		return err
	}

	if info.IsDir() {
		PrintInfo(fmt.Sprintf("This will securely delete all files under: %s", path))
		PrintInfo("WARNING: This operation is irreversible!")
		if secureDeleteVerbose {
			PrintInfo(fmt.Sprintf("Performing %d overwrite passes per file...", secureDeletePasses))
		}
		if err := secureDeleteDirectory(path, secureDeletePasses, secureDeleteVerbose); err != nil {
			PrintError(fmt.Sprintf("Secure deletion failed: %v", err))
			return err
		}
		PrintSuccess(fmt.Sprintf("Securely deleted directory contents: %s", path))
		return nil
	}

	PrintInfo(fmt.Sprintf("This will securely delete: %s", path))
	PrintInfo("WARNING: This operation is irreversible!")

	service := core.NewSecureDeleteService(secureDeletePasses)

	if secureDeleteVerbose {
		PrintInfo(fmt.Sprintf("Performing %d overwrite passes...", secureDeletePasses))
	}

	if err := service.Delete(path); err != nil {
		PrintError(fmt.Sprintf("Secure deletion failed: %v", err))
		return err
	}

	PrintSuccess(fmt.Sprintf("Securely deleted: %s", path))
	return nil
}

func dryRunSecureDeleteDirectory(dirPath string) error {
	fileHandler := core.NewFileHandler()
	return fileHandler.WalkDirectory(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		PrintInfo(fmt.Sprintf("Would securely delete: %s", path))
		return nil
	})
}

// secureDeleteDirectory securely deletes all files in a directory
func secureDeleteDirectory(dirPath string, passes int, verbose bool) error {
	fileHandler := core.NewFileHandler()
	service := core.NewSecureDeleteService(passes)

	var errors []error

	err := fileHandler.WalkDirectory(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if verbose {
			PrintInfo(fmt.Sprintf("Securely deleting: %s", path))
		}

		if err := service.Delete(path); err != nil {
			errors = append(errors, fmt.Errorf("failed to delete %s: %w", path, err))
		}

		return nil
	})

	if err != nil {
		return err
	}

	if len(errors) > 0 {
		return fmt.Errorf("some files failed to delete: %d errors", len(errors))
	}

	return nil
}
