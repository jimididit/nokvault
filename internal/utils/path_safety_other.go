//go:build !windows

package utils

import "os"

func isDisallowedRedirect(_ string, info os.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}
