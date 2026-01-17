package utils

import (
	"fmt"
	"os"
	"syscall"

	"github.com/manifoldco/promptui"
	"golang.org/x/term"
)

// GetPassword retrieves password from various sources
func GetPassword(passwordFlag, keyfileFlag string, noPrompt, confirm bool) ([]byte, error) {
	// Try keyfile first
	if keyfileFlag != "" {
		keyfileData, err := os.ReadFile(keyfileFlag)
		if err != nil {
			return nil, fmt.Errorf("failed to read keyfile: %w", err)
		}
		// Remove trailing newline if present
		if len(keyfileData) > 0 && keyfileData[len(keyfileData)-1] == '\n' {
			keyfileData = keyfileData[:len(keyfileData)-1]
		}
		return keyfileData, nil
	}

	// Try password flag
	if passwordFlag != "" {
		return []byte(passwordFlag), nil
	}

	// Try environment variable
	if envPassword := os.Getenv("NOKVAULT_PASSWORD"); envPassword != "" {
		return []byte(envPassword), nil
	}

	// Prompt for password
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
