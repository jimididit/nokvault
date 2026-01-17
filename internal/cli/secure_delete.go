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
	Short: "Securely delete a file by overwriting it multiple times",
	Long: `Securely delete a file by overwriting it with random data multiple times
before deletion. This makes it much harder to recover the file contents.

WARNING: This operation is irreversible!`,
	Args: cobra.ExactArgs(1),
	RunE: runSecureDelete,
}

var (
	secureDeletePasses  int
	secureDeleteVerbose bool
)

func init() {
	secureDeleteCmd.Flags().IntVarP(&secureDeletePasses, "passes", "p", 3, "Number of overwrite passes (default: 3)")
	secureDeleteCmd.Flags().BoolVarP(&secureDeleteVerbose, "verbose", "v", false, "Verbose output")

	rootCmd.AddCommand(secureDeleteCmd)
}

func runSecureDelete(cmd *cobra.Command, args []string) error {
	path := args[0]

	// Validate path
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		PrintError(fmt.Sprintf("Path does not exist: %s", path))
		return utils.NewError(utils.ErrFileNotFound.Code, fmt.Sprintf("Path does not exist: %s", path), err)
	}

	if info.IsDir() {
		PrintError("secure-delete only works with files, not directories")
		return fmt.Errorf("secure-delete requires a file")
	}

	// Confirm deletion
	PrintInfo(fmt.Sprintf("This will securely delete: %s", path))
	PrintInfo("WARNING: This operation is irreversible!")

	// Create secure delete service
	service := core.NewSecureDeleteService(secureDeletePasses)

	if secureDeleteVerbose {
		PrintInfo(fmt.Sprintf("Performing %d overwrite passes...", secureDeletePasses))
	}

	// Delete file
	if err := service.Delete(path); err != nil {
		PrintError(fmt.Sprintf("Secure deletion failed: %v", err))
		return err
	}

	PrintSuccess(fmt.Sprintf("Securely deleted: %s", path))
	return nil
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
