package utils

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"

	"github.com/manifoldco/promptui"
	"golang.org/x/term"
)

// ErrPasswordFlagRefused is returned when a password was passed on the command line.
var ErrPasswordFlagRefused = fmt.Errorf(
	"passing passwords on the command line is not allowed (visible in process lists and shell history); use --keyfile, the NOKVAULT_PASSWORD environment variable, or an interactive prompt",
)

// GetPassword retrieves password from keyfile, environment, or interactive prompt.
// passwordFlag must be empty; non-empty values are refused (NV-004).
func GetPassword(passwordFlag, keyfileFlag string, noPrompt, confirm bool) ([]byte, error) {
	// Refuse argv secrets even if a keyfile is also provided — the flag still
	// appears in process lists / shell history (NV-004).
	if passwordFlag != "" {
		return nil, ErrPasswordFlagRefused
	}

	if keyfileFlag != "" {
		return readKeyfile(keyfileFlag)
	}

	if envPassword := os.Getenv("NOKVAULT_PASSWORD"); envPassword != "" {
		return []byte(envPassword), nil
	}

	if noPrompt {
		return nil, fmt.Errorf("no password provided and --no-prompt is set")
	}

	password, err := PromptPassword("Enter password: ", false)
	if err != nil {
		return nil, err
	}

	if confirm {
		confirmPassword, err := PromptPassword("Confirm password: ", false)
		if err != nil {
			return nil, err
		}

		if string(password) != string(confirmPassword) {
			ZeroizePassword(confirmPassword)
			return nil, fmt.Errorf("passwords do not match")
		}
		ZeroizePassword(confirmPassword)
	}

	return password, nil
}

func readKeyfile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat keyfile: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("keyfile must not be a symlink: %s", path)
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("keyfile permissions are too open (got %04o, want 0600 or tighter): %s", info.Mode().Perm(), path)
		}
	}

	keyfileData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyfile: %w", err)
	}
	keyfileData = []byte(strings.TrimRight(string(keyfileData), "\r\n"))
	return keyfileData, nil
}

// PromptPassword prompts for a password
func PromptPassword(label string, mask bool) ([]byte, error) {
	if mask {
		fmt.Print(label)
		password, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		return password, err
	}

	prompt := promptui.Prompt{
		Label: label,
		Mask:  '*',
	}

	result, err := prompt.Run()
	if err != nil {
		return nil, err
	}

	return []byte(result), nil
}

// ZeroizePassword zeroizes a password from memory securely
func ZeroizePassword(password []byte) {
	SecureZeroize(password)
}

// ZeroizeKey zeroizes a key from memory securely
func ZeroizeKey(key []byte) {
	SecureZeroize(key)
}
