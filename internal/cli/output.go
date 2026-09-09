package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/jimididit/nokvault/internal/utils"
)

// JSONSchemaVersion identifies the stable operational JSON contract.
const JSONSchemaVersion = 1

// Record is the common JSON result, error, and event envelope.
type Record struct {
	SchemaVersion int        `json:"schema_version"`
	Type          string     `json:"type"`
	Command       string     `json:"command"`
	Timestamp     time.Time  `json:"timestamp"`
	Status        string     `json:"status,omitempty"`
	Event         string     `json:"event,omitempty"`
	Data          any        `json:"data,omitempty"`
	Error         *ErrorBody `json:"error,omitempty"`
}

// ErrorBody is a safe, structured CLI error.
type ErrorBody struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Hint    string         `json:"hint,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

type outputReporter struct {
	stdout io.Writer
	stderr io.Writer
	json   bool
	now    func() time.Time
	mu     sync.Mutex
}

var (
	reporterMu     sync.RWMutex
	activeReporter = newReporter(dynamicStdout{}, dynamicStderr{}, false, time.Now)
)

type dynamicStdout struct{}

func (dynamicStdout) Write(p []byte) (int, error) {
	return os.Stdout.Write(p)
}

type dynamicStderr struct{}

func (dynamicStderr) Write(p []byte) (int, error) {
	return os.Stderr.Write(p)
}

func newReporter(stdout, stderr io.Writer, jsonMode bool, now func() time.Time) *outputReporter {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if now == nil {
		now = time.Now
	}
	return &outputReporter{stdout: stdout, stderr: stderr, json: jsonMode, now: now}
}

// ConfigureOutput selects human or JSON rendering for the current execution.
func ConfigureOutput(stdout, stderr io.Writer, jsonMode bool) {
	reporterMu.Lock()
	activeReporter = newReporter(stdout, stderr, jsonMode, time.Now)
	reporterMu.Unlock()
}

func currentReporter() *outputReporter {
	reporterMu.RLock()
	reporter := activeReporter
	reporterMu.RUnlock()
	return reporter
}

func setReporterForTest(reporter *outputReporter) {
	reporterMu.Lock()
	activeReporter = reporter
	reporterMu.Unlock()
}

func resetReporter() {
	ConfigureOutput(dynamicStdout{}, dynamicStderr{}, false)
}

// JSONEnabled reports whether an operational command is using JSON output.
func JSONEnabled() bool {
	return currentReporter().json
}

func newOperationProgressBar(total int64, description string) *utils.ProgressBar {
	if JSONEnabled() {
		return utils.NewSilentProgressBar()
	}
	return utils.NewProgressBar(total, description)
}

// EmitResult writes one bounded-command result record in JSON mode.
func EmitResult(command string, data any) error {
	return emitResult(command, "success", data)
}

// EmitPartialResult writes a successful result that completed only part of its requested work.
func EmitPartialResult(command string, data any) error {
	return emitResult(command, "partial", data)
}

func emitResult(command, status string, data any) error {
	reporter := currentReporter()
	if !reporter.json {
		return nil
	}
	return reporter.writeRecord(Record{
		SchemaVersion: JSONSchemaVersion,
		Type:          "result",
		Command:       command,
		Timestamp:     reporter.now().UTC(),
		Status:        status,
		Data:          data,
	})
}

// EmitEvent writes one complete NDJSON event in JSON mode.
func EmitEvent(command, event string, data any) error {
	reporter := currentReporter()
	if !reporter.json {
		return nil
	}
	return reporter.writeRecord(Record{
		SchemaVersion: JSONSchemaVersion,
		Type:          "event",
		Command:       command,
		Timestamp:     reporter.now().UTC(),
		Event:         event,
		Data:          data,
	})
}

// EmitTerminalError writes the terminal error record for an operational command.
func EmitTerminalError(command string, err error, verbose bool) error {
	reporter := currentReporter()
	if !reporter.json {
		return nil
	}
	return reporter.writeRecord(Record{
		SchemaVersion: JSONSchemaVersion,
		Type:          "error",
		Command:       command,
		Timestamp:     reporter.now().UTC(),
		Status:        "error",
		Data:          errorData(err),
		Error:         errorBody(err, verbose),
	})
}

func (r *outputReporter) writeRecord(record Record) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return &outputError{err: fmt.Errorf("encode JSON output: %w", err)}
	}
	encoded = append(encoded, '\n')

	r.mu.Lock()
	defer r.mu.Unlock()
	n, err := r.stdout.Write(encoded)
	if err != nil {
		return &outputError{err: err}
	}
	if n != len(encoded) {
		return &outputError{err: io.ErrShortWrite}
	}
	return nil
}

type outputError struct {
	err error
}

func (e *outputError) Error() string {
	return e.err.Error()
}

func (e *outputError) Unwrap() error {
	return e.err
}

func isOutputError(err error) bool {
	var writeErr *outputError
	return errors.As(err, &writeErr)
}

func errorBody(err error, verbose bool) *ErrorBody {
	body := &ErrorBody{
		Code:    "INTERNAL_ERROR",
		Message: "Operation failed",
	}
	var nokvaultErr *utils.NokvaultError
	if errors.As(err, &nokvaultErr) {
		body.Code = nokvaultErr.Code
		body.Message = nokvaultErr.Message
		body.Hint = nokvaultErr.GetHint()
	}
	if verbose && err != nil && diagnosticAllowed(body.Code) && !containsSensitiveError(err) {
		body.Details = map[string]any{"diagnostic": err.Error()}
	}
	return body
}

func diagnosticAllowed(code string) bool {
	switch code {
	case utils.ErrInvalidPath.Code,
		utils.ErrFileNotFound.Code,
		utils.ErrInvalidFormat.Code,
		utils.ErrConfirmationRequired.Code,
		utils.ErrOutputExists.Code,
		utils.ErrSymlinkDisallowed.Code,
		utils.ErrPathEscape.Code,
		utils.ErrPartialFailure.Code:
		return true
	default:
		return false
	}
}

func containsSensitiveError(err error) bool {
	if err == nil {
		return false
	}
	if nokvaultErr, ok := err.(*utils.NokvaultError); ok {
		switch nokvaultErr.Code {
		case utils.ErrInvalidPassword.Code,
			utils.ErrKeyDerivation.Code,
			utils.ErrEncryptionFailed.Code,
			utils.ErrDecryptionFailed.Code:
			return true
		}
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if containsSensitiveError(child) {
				return true
			}
		}
		return false
	}
	return containsSensitiveError(errors.Unwrap(err))
}

type operationError struct {
	err  error
	data any
}

func (e *operationError) Error() string {
	return e.err.Error()
}

func (e *operationError) Unwrap() error {
	return e.err
}

// WithErrorData attaches partial operation results to a terminal error.
func WithErrorData(err error, data any) error {
	if err == nil {
		return nil
	}
	return &operationError{err: err, data: data}
}

func errorData(err error) any {
	var operationErr *operationError
	if errors.As(err, &operationErr) {
		return operationErr.data
	}
	return nil
}

func fileFailure(path string, err error) FileFailure {
	body := errorBody(err, false)
	return FileFailure{Path: path, Code: body.Code, Message: body.Message}
}

func (r *outputReporter) printErrorWithHint(err error) {
	if r.json {
		return
	}
	errorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true)
	hintStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Italic(true)

	fmt.Fprintf(r.stderr, "%s\n", errorStyle.Render("Error: "+err.Error()))
	var nokvaultErr *utils.NokvaultError
	if errors.As(err, &nokvaultErr) {
		if hint := nokvaultErr.GetHint(); hint != "" {
			fmt.Fprintf(r.stderr, "%s\n", hintStyle.Render("💡 Hint: "+hint))
		}
	}
}

func (r *outputReporter) printError(message string) {
	if r.json {
		return
	}
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true)
	fmt.Fprintf(r.stderr, "%s\n", style.Render("Error: "+message))
}

func (r *outputReporter) printSuccess(message string) {
	if r.json {
		return
	}
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true)
	fmt.Fprintf(r.stdout, "%s\n", style.Render("✓ "+message))
}

func (r *outputReporter) printInfo(message string) {
	if r.json {
		return
	}
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("4"))
	fmt.Fprintf(r.stdout, "%s\n", style.Render("ℹ "+message))
}

func (r *outputReporter) printWarning(message string) {
	if r.json {
		return
	}
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Bold(true)
	fmt.Fprintf(r.stderr, "%s\n", style.Render("⚠ Warning: "+message))
}
