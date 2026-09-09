package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jimididit/nokvault/internal/utils"
	"github.com/stretchr/testify/require"
)

func fixedOutputTime() time.Time {
	return time.Date(2026, 9, 9, 3, 0, 0, 0, time.UTC)
}

func TestJSONReporterResultEnvelope(t *testing.T) {
	var stdout, stderr bytes.Buffer
	setReporterForTest(newReporter(&stdout, &stderr, true, fixedOutputTime))
	t.Cleanup(resetReporter)

	require.NoError(t, EmitResult("encrypt", EncryptResult{
		Input: "plain.txt", Output: "plain.txt.nokvault",
		TargetKind: "file", Processed: 1, Succeeded: 1,
	}))

	var record Record
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &record))
	require.Equal(t, JSONSchemaVersion, record.SchemaVersion)
	require.Equal(t, "result", record.Type)
	require.Equal(t, "encrypt", record.Command)
	require.Equal(t, "success", record.Status)
	require.Equal(t, fixedOutputTime(), record.Timestamp)
	require.Empty(t, stderr.String())
}

func TestJSONReporterPartialResultStatus(t *testing.T) {
	var stdout bytes.Buffer
	setReporterForTest(newReporter(&stdout, io.Discard, true, fixedOutputTime))
	t.Cleanup(resetReporter)

	require.NoError(t, EmitPartialResult("secure-delete", SecureDeleteResult{Processed: 2, Succeeded: 1, Failed: 1}))

	var record Record
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &record))
	require.Equal(t, "partial", record.Status)
}

func TestJSONReporterConcurrentEventsRemainWholeLines(t *testing.T) {
	var stdout bytes.Buffer
	setReporterForTest(newReporter(&stdout, io.Discard, true, fixedOutputTime))
	t.Cleanup(resetReporter)

	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- EmitEvent("watch", "file.detected", EventData{
				Path: fmt.Sprintf("file-%d", i),
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	lines := bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte("\n"))
	require.Len(t, lines, 50)
	for _, line := range lines {
		var record Record
		require.NoError(t, json.Unmarshal(line, &record))
		require.Equal(t, "event", record.Type)
		require.Equal(t, "file.detected", record.Event)
	}
}

func TestJSONReporterTypedErrorIsSafeByDefault(t *testing.T) {
	var stdout bytes.Buffer
	setReporterForTest(newReporter(&stdout, io.Discard, true, fixedOutputTime))
	t.Cleanup(resetReporter)

	err := utils.NewErrorWithHint("TEST_CODE", "safe message", errors.New("secret detail"), "safe hint")
	require.NoError(t, EmitTerminalError("decrypt", err, false))

	var record Record
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &record))
	require.Equal(t, "TEST_CODE", record.Error.Code)
	require.Equal(t, "safe message", record.Error.Message)
	require.Equal(t, "safe hint", record.Error.Hint)
	require.Empty(t, record.Error.Details)
	require.NotContains(t, stdout.String(), "secret detail")
}

func TestJSONReporterUntypedErrorUsesFallback(t *testing.T) {
	var stdout bytes.Buffer
	setReporterForTest(newReporter(&stdout, io.Discard, true, fixedOutputTime))
	t.Cleanup(resetReporter)

	require.NoError(t, EmitTerminalError("encrypt", errors.New("private path detail"), false))

	var record Record
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &record))
	require.Equal(t, "INTERNAL_ERROR", record.Error.Code)
	require.Equal(t, "Operation failed", record.Error.Message)
	require.NotContains(t, stdout.String(), "private path detail")
}

func TestJSONReporterVerboseErrorIncludesDiagnostic(t *testing.T) {
	var stdout bytes.Buffer
	setReporterForTest(newReporter(&stdout, io.Discard, true, fixedOutputTime))
	t.Cleanup(resetReporter)

	err := utils.NewError(utils.ErrInvalidFormat.Code, "safe message", errors.New("diagnostic"))
	require.NoError(t, EmitTerminalError("decrypt", err, true))

	var record Record
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &record))
	require.Equal(t, "INVALID_FORMAT: safe message (diagnostic)", record.Error.Details["diagnostic"])
}

func TestJSONReporterVerboseSensitiveErrorOmitsDiagnostic(t *testing.T) {
	var stdout bytes.Buffer
	setReporterForTest(newReporter(&stdout, io.Discard, true, fixedOutputTime))
	t.Cleanup(resetReporter)

	err := utils.NewError(utils.ErrInvalidPassword.Code, "credential failed", errors.New("secret path"))
	require.NoError(t, EmitTerminalError("decrypt", err, true))

	var record Record
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &record))
	require.Empty(t, record.Error.Details)
	require.NotContains(t, stdout.String(), "secret path")
}

func TestJSONReporterVerbosePartialFailureCannotExposeSensitiveCause(t *testing.T) {
	var stdout bytes.Buffer
	setReporterForTest(newReporter(&stdout, io.Discard, true, fixedOutputTime))
	t.Cleanup(resetReporter)

	sensitive := utils.NewError(utils.ErrDecryptionFailed.Code, "decrypt failed", errors.New("cipher detail"))
	partial := utils.NewError(utils.ErrPartialFailure.Code, "batch failed", sensitive)
	require.NoError(t, EmitTerminalError("decrypt", WithErrorData(partial, DecryptResult{Failed: 1}), true))

	var record Record
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &record))
	require.Empty(t, record.Error.Details)
	require.NotContains(t, stdout.String(), "cipher detail")
}

func TestErrorDataPreservesCauseAndPayload(t *testing.T) {
	cause := utils.NewError("TEST_CODE", "failed", nil)
	payload := DecryptResult{Input: "vault", Failed: 1}
	err := WithErrorData(cause, payload)

	var nv *utils.NokvaultError
	require.ErrorAs(t, err, &nv)
	require.Equal(t, payload, errorData(err))
}

func TestSecureDeleteFileFailurePreservesOperationData(t *testing.T) {
	result, err := secureDeleteFileResult("secret.txt", 3, func(string) error {
		return errors.New("delete failed")
	})

	require.Error(t, err)
	require.Equal(t, 1, result.Processed)
	require.Equal(t, 1, result.Failed)
	require.Zero(t, result.Succeeded)
	require.Len(t, result.Failures, 1)
	require.Equal(t, "secret.txt", result.Failures[0].Path)
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	return len(p) - 1, nil
}

func TestJSONReporterShortWriteReturnsError(t *testing.T) {
	setReporterForTest(newReporter(shortWriter{}, io.Discard, true, fixedOutputTime))
	t.Cleanup(resetReporter)

	require.ErrorIs(t, EmitResult("encrypt", EncryptResult{}), io.ErrShortWrite)
}

func TestRunJSONEmitsOneStructuredError(t *testing.T) {
	ResetCLIStateForTest()
	t.Cleanup(ResetCLIStateForTest)
	var stdout, stderr bytes.Buffer

	exitCode := Run(
		[]string{"encrypt", filepath.Join(t.TempDir(), "missing"), "--json"},
		&stdout,
		&stderr,
	)

	require.NotZero(t, exitCode)
	require.Empty(t, stderr.String())
	lines := bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte("\n"))
	require.Len(t, lines, 1)

	var record Record
	require.NoError(t, json.Unmarshal(lines[0], &record))
	require.Equal(t, "error", record.Type)
	require.Equal(t, "encrypt", record.Command)
	require.Equal(t, "INVALID_PATH", record.Error.Code)
}

func TestRunJSONSecureDeleteDoesNotPrompt(t *testing.T) {
	ResetCLIStateForTest()
	t.Cleanup(ResetCLIStateForTest)
	path := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(path, []byte("secret"), 0o600))
	var stdout, stderr bytes.Buffer

	exitCode := Run([]string{"secure-delete", path, "--json"}, &stdout, &stderr)

	require.NotZero(t, exitCode)
	require.Empty(t, stderr.String())
	var record Record
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &record))
	require.Equal(t, "CONFIRMATION_REQUIRED", record.Error.Code)
	_, err := os.Stat(path)
	require.NoError(t, err)
}

func TestRunRepeatedJSONFlagsUseLastValue(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")

	t.Run("final true remains JSON-only", func(t *testing.T) {
		ResetCLIStateForTest()
		t.Cleanup(ResetCLIStateForTest)
		var stdout, stderr bytes.Buffer
		exitCode := Run([]string{"encrypt", missing, "--json=false", "--json=TRUE"}, &stdout, &stderr)

		require.NotZero(t, exitCode)
		require.Empty(t, stderr.String())
		var record Record
		require.NoError(t, json.Unmarshal(stdout.Bytes(), &record))
		require.Equal(t, "error", record.Type)
	})

	t.Run("final false remains human", func(t *testing.T) {
		ResetCLIStateForTest()
		t.Cleanup(ResetCLIStateForTest)
		var stdout, stderr bytes.Buffer
		exitCode := Run([]string{"encrypt", missing, "--json", "--json=FALSE"}, &stdout, &stderr)

		require.NotZero(t, exitCode)
		require.NotContains(t, stdout.String(), `"schema_version"`)
		require.Contains(t, stderr.String(), "Error:")
	})
}
