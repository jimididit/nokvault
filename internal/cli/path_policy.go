package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jimididit/nokvault/internal/core"
	"github.com/jimididit/nokvault/internal/utils"
)

func isPathPolicyError(err error) bool {
	var nv *utils.NokvaultError
	if !errors.As(err, &nv) {
		return false
	}
	return nv.Code == utils.ErrSymlinkDisallowed.Code || nv.Code == utils.ErrPathEscape.Code
}

// reportWatchValidationError always prints typed path-policy errors.
// Ordinary permission/I/O validation errors print only when verbose.
func reportWatchValidationError(err error, verbose bool) {
	if err == nil {
		return
	}
	if isPathPolicyError(err) || verbose {
		PrintError(err.Error())
	}
}

func logScheduleEncryptError(err error) {
	if err == nil {
		return
	}
	if isPathPolicyError(err) || scheduleVerbose {
		PrintError(fmt.Sprintf("Scheduled encryption failed: %v", err))
	}
}

func preflightContainedOutputs(inputPath, outputRoot string, outputRel func(relPath string) (string, bool)) error {
	fileHandler := core.NewFileHandler()
	return fileHandler.WalkDirectory(inputPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relPath, relErr := fileHandler.GetRelativePath(inputPath, path)
		if relErr != nil {
			return relErr
		}
		relOut, ok := outputRel(relPath)
		if !ok {
			return nil
		}
		_, joinErr := utils.SafeJoin(outputRoot, relOut)
		return joinErr
	})
}

func preflightDirectoryEncryptOutputs(inputPath, outputRoot string) error {
	return preflightContainedOutputs(inputPath, outputRoot, func(relPath string) (string, bool) {
		return relPath + ".nokvault", true
	})
}

func preflightDirectoryDecryptOutputs(inputPath, outputRoot string) error {
	return preflightContainedOutputs(inputPath, outputRoot, func(relPath string) (string, bool) {
		if !strings.HasSuffix(relPath, ".nokvault") {
			return "", false
		}
		return relPath[:len(relPath)-len(".nokvault")], true
	})
}
