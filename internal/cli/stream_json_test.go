package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/jimididit/nokvault/internal/core"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

type synchronizedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *synchronizedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

func decodeNDJSON(t *testing.T, raw []byte) []Record {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	records := make([]Record, 0, len(lines))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var record Record
		require.NoError(t, json.Unmarshal(line, &record))
		require.Equal(t, JSONSchemaVersion, record.SchemaVersion)
		records = append(records, record)
	}
	return records
}

func TestJSONScheduleLoopEmitsOrderedLifecycle(t *testing.T) {
	var stdout synchronizedBuffer
	setReporterForTest(newReporter(&stdout, &bytes.Buffer{}, true, fixedOutputTime))
	t.Cleanup(resetReporter)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ticks := make(chan time.Time)
	err := runScheduleLoop(ctx, "evidence", ticks, func() (EncryptResult, error) {
		return EncryptResult{
			Input: "evidence", Output: "evidence.nokv",
			TargetKind: "file", Processed: 1, Succeeded: 1,
		}, nil
	})
	require.NoError(t, err)

	records := decodeNDJSON(t, stdout.Bytes())
	require.Len(t, records, 3)
	require.Equal(t, "schedule.tick.started", records[0].Event)
	require.Equal(t, "schedule.tick.completed", records[1].Event)
	require.Equal(t, "schedule.stopped", records[2].Event)
}

func TestJSONScheduleLoopEmitsFailureAndContinues(t *testing.T) {
	var stdout synchronizedBuffer
	setReporterForTest(newReporter(&stdout, &bytes.Buffer{}, true, fixedOutputTime))
	t.Cleanup(resetReporter)

	ticks := make(chan time.Time)
	close(ticks)
	err := runScheduleLoop(context.Background(), "evidence", ticks, func() (EncryptResult, error) {
		return EncryptResult{Input: "evidence", Failed: 1}, errors.New("disk failed")
	})
	require.NoError(t, err)

	records := decodeNDJSON(t, stdout.Bytes())
	require.Len(t, records, 2)
	require.Equal(t, "schedule.tick.started", records[0].Event)
	require.Equal(t, "operation.failed", records[1].Event)
	require.Equal(t, "INTERNAL_ERROR", records[1].Data.(map[string]any)["error"].(map[string]any)["code"])
}

func TestScheduledFileFailureReportsAttemptCounts(t *testing.T) {
	ResetCLIStateForTest()
	t.Cleanup(ResetCLIStateForTest)
	path := filepath.Join(t.TempDir(), "scheduled.txt")
	require.NoError(t, os.WriteFile(path, []byte("payload"), 0o600))
	require.NoError(t, os.WriteFile(path+".nokv", []byte("existing"), 0o600))

	result, err := performScheduledEncryptResult(
		path,
		core.NewEncryptionService(),
		bytes.Repeat([]byte{0x42}, 32),
		bytes.Repeat([]byte{0x24}, 16),
	)

	require.Error(t, err)
	require.Equal(t, 1, result.Processed)
	require.Equal(t, 0, result.Succeeded)
	require.Equal(t, 1, result.Failed)
}

func TestJSONWatchCallbackEmitsCompleteRecords(t *testing.T) {
	var stdout synchronizedBuffer
	setReporterForTest(newReporter(&stdout, &bytes.Buffer{}, true, fixedOutputTime))
	t.Cleanup(resetReporter)

	path := filepath.Join(t.TempDir(), "incoming.txt")
	require.NoError(t, os.WriteFile(path, []byte("payload"), 0o600))
	key := bytes.Repeat([]byte{0x42}, 32)
	salt := bytes.Repeat([]byte{0x24}, 16)
	callback := createEncryptCallback(core.NewEncryptionService(), key, salt, 0, nil, false)

	callback(path, fsnotify.Event{Name: path, Op: fsnotify.Create})
	require.Eventually(t, func() bool {
		_, err := os.Stat(path + ".nokv")
		return err == nil
	}, time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		return bytes.Contains(stdout.Bytes(), []byte(`"event":"encryption.completed"`))
	}, time.Second, 10*time.Millisecond)

	records := decodeNDJSON(t, stdout.Bytes())
	require.Len(t, records, 3)
	require.Equal(t, "file.detected", records[0].Event)
	require.Equal(t, "encryption.scheduled", records[1].Event)
	require.Equal(t, "encryption.completed", records[2].Event)
}

func TestJSONWatchShutdownCancelsPendingEncryption(t *testing.T) {
	var stdout synchronizedBuffer
	setReporterForTest(newReporter(&stdout, &bytes.Buffer{}, true, fixedOutputTime))
	t.Cleanup(resetReporter)

	ctx, cancel := context.WithCancel(context.Background())
	path := filepath.Join(t.TempDir(), "pending.txt")
	require.NoError(t, os.WriteFile(path, []byte("payload"), 0o600))
	manager := newWatchCallbackManager(
		ctx, cancel, core.NewEncryptionService(),
		bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x24}, 16),
		200*time.Millisecond, nil, false,
	)
	manager.Callback(path, fsnotify.Event{Name: path, Op: fsnotify.Create})

	cancel()
	manager.Stop()
	require.NoError(t, EmitEvent("watch", "watch.stopped", EventData{Path: filepath.Dir(path)}))
	time.Sleep(250 * time.Millisecond)

	_, err := os.Stat(path + ".nokv")
	require.True(t, os.IsNotExist(err))
	records := decodeNDJSON(t, stdout.Bytes())
	require.Equal(t, "watch.stopped", records[len(records)-1].Event)
}

func TestJSONWatchWriteFailureCancelsManager(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	setReporterForTest(newReporter(shortWriter{}, &bytes.Buffer{}, true, fixedOutputTime))
	t.Cleanup(resetReporter)

	path := filepath.Join(t.TempDir(), "incoming.txt")
	require.NoError(t, os.WriteFile(path, []byte("payload"), 0o600))
	manager := newWatchCallbackManager(
		ctx, cancel, core.NewEncryptionService(),
		bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x24}, 16),
		time.Second, nil, false,
	)
	manager.Callback(path, fsnotify.Event{Name: path, Op: fsnotify.Create})

	require.ErrorIs(t, manager.FatalError(), io.ErrShortWrite)
	require.Error(t, ctx.Err())
	manager.Stop()
}

func TestJSONWatchCommandLifecycle(t *testing.T) {
	ResetCLIStateForTest()
	t.Cleanup(ResetCLIStateForTest)
	var stdout synchronizedBuffer
	var stderr bytes.Buffer
	setReporterForTest(newReporter(&stdout, &stderr, true, fixedOutputTime))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	watchPath := t.TempDir()

	require.NoError(t, runWatch(cmd, []string{watchPath}))

	records := decodeNDJSON(t, stdout.Bytes())
	require.Len(t, records, 2)
	require.Equal(t, "watch.started", records[0].Event)
	require.Equal(t, "watch.stopped", records[1].Event)
	require.Empty(t, stderr.String())
}

func TestJSONWatchConcurrentCallbacksRemainValidNDJSON(t *testing.T) {
	var stdout synchronizedBuffer
	setReporterForTest(newReporter(&stdout, &bytes.Buffer{}, true, fixedOutputTime))
	t.Cleanup(resetReporter)

	ctx, cancel := context.WithCancel(context.Background())
	manager := newWatchCallbackManager(
		ctx, cancel, core.NewEncryptionService(),
		bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x24}, 16),
		0, nil, false,
	)
	dir := t.TempDir()
	const fileCount = 12
	var callbacks sync.WaitGroup
	for i := 0; i < fileCount; i++ {
		path := filepath.Join(dir, fmt.Sprintf("incoming-%02d.txt", i))
		require.NoError(t, os.WriteFile(path, []byte("payload"), 0o600))
		callbacks.Add(1)
		go func() {
			defer callbacks.Done()
			manager.Callback(path, fsnotify.Event{Name: path, Op: fsnotify.Create})
		}()
	}
	callbacks.Wait()
	require.Eventually(t, func() bool {
		for i := 0; i < fileCount; i++ {
			path := filepath.Join(dir, fmt.Sprintf("incoming-%02d.txt.nokv", i))
			if _, err := os.Stat(path); err != nil {
				return false
			}
		}
		return true
	}, 2*time.Second, 10*time.Millisecond)
	manager.Stop()

	records := decodeNDJSON(t, stdout.Bytes())
	require.Len(t, records, fileCount*3)
}

func TestJSONScheduleCommandLifecycle(t *testing.T) {
	ResetCLIStateForTest()
	t.Cleanup(ResetCLIStateForTest)
	var stdout synchronizedBuffer
	var stderr bytes.Buffer
	setReporterForTest(newReporter(&stdout, &stderr, true, fixedOutputTime))

	dir := t.TempDir()
	path := filepath.Join(dir, "scheduled.txt")
	keyfile := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(path, []byte("payload"), 0o600))
	require.NoError(t, os.WriteFile(keyfile, []byte("schedule-password"), 0o600))
	scheduleKeyfile = keyfile
	scheduleNoPrompt = true

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)

	require.NoError(t, runScheduleEncrypt(cmd, []string{path}))

	records := decodeNDJSON(t, stdout.Bytes())
	require.Len(t, records, 4)
	require.Equal(t, "schedule.started", records[0].Event)
	require.Equal(t, "schedule.tick.started", records[1].Event)
	require.Equal(t, "schedule.tick.completed", records[2].Event)
	require.Equal(t, "schedule.stopped", records[3].Event)
	require.Empty(t, stderr.String())
}
