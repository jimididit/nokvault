package utils

import "fmt"

// Error types for nokvault
type NokvaultError struct {
	Code    string
	Message string
	Err     error
	Hint    string // Helpful hint for the user
}

func (e *NokvaultError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *NokvaultError) Unwrap() error {
	return e.Err
}

// GetHint returns a helpful hint for the user
func (e *NokvaultError) GetHint() string {
	if e.Hint != "" {
		return e.Hint
	}
	return getDefaultHint(e.Code)
}

// getDefaultHint returns default hints for common error codes
func getDefaultHint(code string) string {
	switch code {
	case "INVALID_PATH":
		return "Check that the file or directory exists and you have permission to access it."
	case "ENCRYPTION_FAILED":
		return "Ensure you have enough disk space and write permissions. Try again with --verbose for more details."
	case "DECRYPTION_FAILED":
		return "The password may be incorrect, or the file may be corrupted. Verify your password and try again."
	case "INVALID_PASSWORD":
		return "Check your password or keyfile. Use --keyfile to specify a keyfile, or set NOKVAULT_PASSWORD environment variable."
	case "FILE_NOT_FOUND":
		return "Verify the file path is correct. Use absolute paths if relative paths don't work."
	case "KEY_DERIVATION_FAILED":
		return "This may indicate insufficient system resources. Try again or reduce key derivation parameters."
	case "INVALID_FORMAT":
		return "The file may not be a valid nokvault encrypted file. Ensure it was encrypted with nokvault."
	default:
		return "Check the documentation or use --verbose for more details."
	}
}

// Common error codes
var (
	ErrInvalidPath      = &NokvaultError{Code: "INVALID_PATH", Message: "Invalid file or directory path"}
	ErrEncryptionFailed = &NokvaultError{Code: "ENCRYPTION_FAILED", Message: "Encryption operation failed"}
	ErrDecryptionFailed = &NokvaultError{Code: "DECRYPTION_FAILED", Message: "Decryption operation failed"}
	ErrInvalidPassword  = &NokvaultError{Code: "INVALID_PASSWORD", Message: "Invalid password or key"}
	ErrFileNotFound     = &NokvaultError{Code: "FILE_NOT_FOUND", Message: "File not found"}
	ErrKeyDerivation    = &NokvaultError{Code: "KEY_DERIVATION_FAILED", Message: "Key derivation failed"}
	ErrInvalidFormat    = &NokvaultError{Code: "INVALID_FORMAT", Message: "Invalid file format"}
)

// NewError creates a new error with context
func NewError(code, message string, err error) *NokvaultError {
	return &NokvaultError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// NewErrorWithHint creates a new error with a helpful hint
func NewErrorWithHint(code, message string, err error, hint string) *NokvaultError {
	return &NokvaultError{
		Code:    code,
		Message: message,
		Err:     err,
		Hint:    hint,
	}
}
