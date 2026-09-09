package cli

// PrintErrorWithHint prints an error message with a helpful hint
func PrintErrorWithHint(err error) {
	currentReporter().printErrorWithHint(err)
}

// PrintError prints an error message with styling
func PrintError(message string) {
	currentReporter().printError(message)
}

// PrintSuccess prints a success message with styling
func PrintSuccess(message string) {
	currentReporter().printSuccess(message)
}

// PrintInfo prints an info message with styling
func PrintInfo(message string) {
	currentReporter().printInfo(message)
}

// PrintWarning prints a warning message with styling
func PrintWarning(message string) {
	currentReporter().printWarning(message)
}
