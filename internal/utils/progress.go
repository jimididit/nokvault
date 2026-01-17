package utils

import (
	"io"
	"os"

	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

// ProgressBar wraps mpb progress bar functionality
type ProgressBar struct {
	bar *mpb.Bar
	p   *mpb.Progress
}

// NewProgressBar creates a new progress bar with its own container
// Each progress bar gets its own container to avoid rendering conflicts
func NewProgressBar(total int64, description string) *ProgressBar {
	// Create a new progress container for this bar
	// Using WithOutput to stderr and suppressing refresh rate to avoid duplicates
	p := mpb.New(
		mpb.WithWidth(64),
		mpb.WithOutput(os.Stderr),
		mpb.WithRefreshRate(100), // Refresh every 100ms to reduce flicker
	)

	bar := p.AddBar(total,
		mpb.PrependDecorators(
			decor.Name(description),
			decor.Percentage(decor.WC{W: 5}),
		),
		mpb.AppendDecorators(
			decor.EwmaETA(decor.ET_STYLE_GO, 60),
			decor.Name(" ] "),
			decor.EwmaSpeed(decor.SizeB1024(0), "% .2f", 60),
		),
	)

	return &ProgressBar{
		bar: bar,
		p:   p,
	}
}

// Increment increments the progress bar
func (pb *ProgressBar) Increment(n int64) {
	pb.bar.IncrBy(int(n))
}

// SetTotal sets the total value
func (pb *ProgressBar) SetTotal(total int64) {
	pb.bar.SetTotal(total, false)
}

// Wait waits for the progress bar to complete and cleans up
func (pb *ProgressBar) Wait() {
	if pb.bar == nil || pb.p == nil {
		return
	}

	// Get current progress and mark as complete
	current := pb.bar.Current()
	// Set total to current to mark as 100% complete
	// The second parameter 'true' marks it as complete
	pb.bar.SetTotal(current, true)

	// Wait for the progress container to finish rendering
	// This ensures the final state is displayed before cleanup
	pb.p.Wait()
}

// Writer returns a writer that updates the progress bar
func (pb *ProgressBar) Writer() io.Writer {
	return pb.bar.ProxyWriter(io.Discard)
}
