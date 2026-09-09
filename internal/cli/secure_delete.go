package cli

import (
	"fmt"
	"os"
	"sort"

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

	if err := utils.ValidateNoSymlinkComponents(path); err != nil {
		return err
	}

	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		PrintError(fmt.Sprintf("Path does not exist: %s", path))
		return utils.NewError(utils.ErrFileNotFound.Code, fmt.Sprintf("Path does not exist: %s", path), err)
	}
	if err != nil {
		return err
	}

	if secureDeleteDryRun {
		if info.IsDir() {
			paths, err := collectSecureDeletePaths(path)
			if err != nil {
				return err
			}
			if JSONEnabled() {
				return EmitResult("secure-delete", SecureDeleteResult{
					Path: path, TargetKind: "directory", DryRun: true,
					Passes: secureDeletePasses, Processed: len(paths),
					Succeeded: len(paths), Paths: paths,
				})
			}
			for _, filePath := range paths {
				PrintInfo(fmt.Sprintf("Would securely delete: %s", filePath))
			}
			return nil
		}
		if JSONEnabled() {
			return EmitResult("secure-delete", SecureDeleteResult{
				Path: path, TargetKind: "file", DryRun: true,
				Passes: secureDeletePasses, Processed: 1, Succeeded: 1,
				Paths: []string{path},
			})
		}
		PrintInfo(fmt.Sprintf("Would securely delete: %s", path))
		return nil
	}

	if err := requireConfirmation(secureDeleteYes, !JSONEnabled() && isInteractive(), os.Stdin, os.Stderr); err != nil {
		PrintError(err.Error())
		return err
	}

	if info.IsDir() {
		PrintInfo(fmt.Sprintf("This will securely delete all files under: %s", path))
		PrintInfo("WARNING: This operation is irreversible!")
		if secureDeleteVerbose {
			PrintInfo(fmt.Sprintf("Performing %d overwrite passes per file...", secureDeletePasses))
		}
		result, err := secureDeleteDirectory(path, secureDeletePasses, secureDeleteVerbose)
		if err != nil {
			PrintError(fmt.Sprintf("Secure deletion failed: %v", err))
			return WithErrorData(err, result)
		}
		if JSONEnabled() {
			return EmitResult("secure-delete", result)
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

	result, err := secureDeleteFileResult(path, secureDeletePasses, service.Delete)
	if err != nil {
		PrintError(fmt.Sprintf("Secure deletion failed: %v", err))
		return WithErrorData(err, result)
	}

	if JSONEnabled() {
		return EmitResult("secure-delete", result)
	}
	PrintSuccess(fmt.Sprintf("Securely deleted: %s", path))
	return nil
}

func secureDeleteFileResult(path string, passes int, deleteFile func(string) error) (SecureDeleteResult, error) {
	result := SecureDeleteResult{
		Path: path, TargetKind: "file", Passes: passes, Processed: 1,
	}
	if err := deleteFile(path); err != nil {
		result.Failed = 1
		result.Failures = []FileFailure{fileFailure(path, err)}
		return result, err
	}
	result.Succeeded = 1
	result.Paths = []string{path}
	return result, nil
}

func collectSecureDeletePaths(dirPath string) ([]string, error) {
	fileHandler := core.NewFileHandler()
	var paths []string
	err := fileHandler.WalkDirectory(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	sort.Strings(paths)
	return paths, err
}

// secureDeleteDirectory securely deletes all files in a directory
func secureDeleteDirectory(dirPath string, passes int, verbose bool) (SecureDeleteResult, error) {
	fileHandler := core.NewFileHandler()
	service := core.NewSecureDeleteService(passes)
	result := SecureDeleteResult{
		Path: dirPath, TargetKind: "directory", Passes: passes,
	}

	err := fileHandler.WalkDirectory(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}
		result.Processed++

		if verbose {
			PrintInfo(fmt.Sprintf("Securely deleting: %s", path))
		}

		if err := service.Delete(path); err != nil {
			result.Failed++
			result.Failures = append(result.Failures, fileFailure(path, err))
		} else {
			result.Succeeded++
			result.Paths = append(result.Paths, path)
		}

		return nil
	})

	if err != nil {
		return result, err
	}

	if result.Failed > 0 {
		return result, utils.NewError(
			utils.ErrPartialFailure.Code,
			fmt.Sprintf("Secure deletion completed with %d file error(s)", result.Failed),
			nil,
		)
	}

	sort.Strings(result.Paths)
	return result, nil
}
