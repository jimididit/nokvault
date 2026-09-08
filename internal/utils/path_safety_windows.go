//go:build windows

package utils

import (
	"os"
	"syscall"
)

func isDisallowedRedirect(path string, info os.FileInfo) bool {
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return info.Mode()&os.ModeIrregular != 0
	}
	attrs, err := syscall.GetFileAttributes(ptr)
	if err != nil {
		return info.Mode()&os.ModeIrregular != 0
	}
	return attrs&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
