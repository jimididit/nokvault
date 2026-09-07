package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

const symlinkHint = "Use a regular file or directory path. Symlinks are not followed."

// ValidateNoSymlinkComponents walks from path to the volume root and rejects
// any existing symlink or Windows reparse/junction component. Missing
// components are allowed so prospective output paths can be validated before
// they are created.
func ValidateNoSymlinkComponents(path string) error {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return err
	}
	for current := absolute; ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		if statErr == nil && isDisallowedRedirect(current, info) {
			return NewErrorWithHint(
				ErrSymlinkDisallowed.Code,
				fmt.Sprintf("Symlink paths are not allowed: %s", current),
				nil,
				symlinkHint,
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
	if isUnsafeRelative(relative) {
		return "", pathEscapeError(relative)
	}
	cleaned := filepath.Clean(relative)

	absRoot, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", err
	}
	joined := filepath.Join(absRoot, cleaned)
	rel, err := filepath.Rel(absRoot, joined)
	if err != nil {
		return "", pathEscapeError(relative)
	}
	if isParentEscape(rel) || !filepath.IsLocal(rel) {
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

func isUnsafeRelative(relative string) bool {
	if filepath.IsAbs(relative) || isRootedBackslash(relative) || filepath.VolumeName(relative) != "" {
		return true
	}
	cleaned := filepath.Clean(relative)
	if filepath.IsAbs(cleaned) || isRootedBackslash(cleaned) || filepath.VolumeName(cleaned) != "" {
		return true
	}
	if !filepath.IsLocal(cleaned) || isParentEscape(cleaned) || hasReservedDeviceName(cleaned) {
		return true
	}
	return false
}

func isRootedBackslash(path string) bool {
	return strings.HasPrefix(path, `\`)
}

func isParentEscape(path string) bool {
	return path == ".." || strings.HasPrefix(path, ".."+string(os.PathSeparator))
}

func hasReservedDeviceName(path string) bool {
	for _, elem := range strings.FieldsFunc(path, isPathSeparator) {
		if isReservedDeviceElem(elem) {
			return true
		}
	}
	return false
}

func isPathSeparator(r rune) bool {
	return r == '\\' || r == '/' || r == filepath.Separator
}

func isReservedDeviceElem(elem string) bool {
	name := strings.TrimRightFunc(elem, func(r rune) bool {
		return r == '.' || r == ' ' || unicode.IsSpace(r)
	})
	if i := strings.IndexByte(name, '.'); i >= 0 {
		name = name[:i]
	}
	name = strings.ToUpper(name)
	switch name {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if len(name) == 4 {
		prefix := name[:3]
		if (prefix == "COM" || prefix == "LPT") && name[3] >= '1' && name[3] <= '9' {
			return true
		}
	}
	return false
}

func pathEscapeError(relative string) error {
	return NewErrorWithHint(
		ErrPathEscape.Code,
		fmt.Sprintf("Path escapes the output root: %s", relative),
		nil,
		"Use a relative path that stays inside the selected output directory.",
	)
}
