package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateNoSymlinkComponents walks from path to the volume root and rejects
// any existing symlink component. Missing components are allowed so prospective
// output paths can be validated before they are created.
func ValidateNoSymlinkComponents(path string) error {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return err
	}
	for current := absolute; ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		if statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return NewErrorWithHint(
				ErrSymlinkDisallowed.Code,
				fmt.Sprintf("Symlink paths are not allowed: %s", current),
				nil,
				"Use a regular file or directory path.",
			)
		}
		if statErr != nil && !os.IsNotExist(statErr) {
			return statErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

// SafeJoin joins relative onto root after lexical containment checks and
// symlink-component validation. The returned path is cleaned and absolute.
func SafeJoin(root, relative string) (string, error) {
	if filepath.IsAbs(relative) {
		return "", pathEscapeError(relative)
	}
	cleaned := filepath.Clean(relative)
	if isParentEscape(cleaned) {
		return "", pathEscapeError(relative)
	}

	absRoot, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", err
	}
	joined := filepath.Join(absRoot, cleaned)
	rel, err := filepath.Rel(absRoot, joined)
	if err != nil {
		return "", err
	}
	if isParentEscape(rel) {
		return "", pathEscapeError(relative)
	}

	if err := ValidateNoSymlinkComponents(absRoot); err != nil {
		return "", err
	}
	if err := ValidateNoSymlinkComponents(joined); err != nil {
		return "", err
	}
	return joined, nil
}

func isParentEscape(path string) bool {
	return path == ".." || strings.HasPrefix(path, ".."+string(os.PathSeparator))
}

func pathEscapeError(relative string) error {
	return NewErrorWithHint(
		ErrPathEscape.Code,
		fmt.Sprintf("Path escapes the output root: %s", relative),
		nil,
		"Use a relative path that stays inside the selected output directory.",
	)
}
