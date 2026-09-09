package cli

// FileFailure describes one failed item in a batch operation.
type FileFailure struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// EncryptResult is the stable JSON payload for encrypt.
type EncryptResult struct {
	Input       string        `json:"input"`
	Output      string        `json:"output"`
	TargetKind  string        `json:"target_kind"`
	DryRun      bool          `json:"dry_run"`
	Processed   int           `json:"processed"`
	Succeeded   int           `json:"succeeded"`
	Failed      int           `json:"failed"`
	Compression bool          `json:"compression"`
	Force       bool          `json:"force"`
	Failures    []FileFailure `json:"failures,omitempty"`
}

// DecryptResult is the stable JSON payload for decrypt.
type DecryptResult struct {
	Input      string        `json:"input"`
	Output     string        `json:"output"`
	TargetKind string        `json:"target_kind"`
	DryRun     bool          `json:"dry_run"`
	Processed  int           `json:"processed"`
	Succeeded  int           `json:"succeeded"`
	Failed     int           `json:"failed"`
	Force      bool          `json:"force"`
	Strict     bool          `json:"strict"`
	AbortedAt  string        `json:"aborted_at,omitempty"`
	Failures   []FileFailure `json:"failures,omitempty"`
}

// SecureDeleteResult is the stable JSON payload for secure-delete.
type SecureDeleteResult struct {
	Path       string        `json:"path"`
	TargetKind string        `json:"target_kind"`
	DryRun     bool          `json:"dry_run"`
	Passes     int           `json:"passes"`
	Processed  int           `json:"processed"`
	Succeeded  int           `json:"succeeded"`
	Failed     int           `json:"failed"`
	Paths      []string      `json:"paths,omitempty"`
	Failures   []FileFailure `json:"failures,omitempty"`
}

// RotateKeyResult is the stable JSON payload for rotate-key.
type RotateKeyResult struct {
	Path   string `json:"path"`
	Status string `json:"status"`
}

// EventData is the stable payload shared by watch and schedule events.
type EventData struct {
	Path         string     `json:"path,omitempty"`
	Output       string     `json:"output,omitempty"`
	TargetKind   string     `json:"target_kind,omitempty"`
	FilesystemOp string     `json:"filesystem_op,omitempty"`
	Pattern      string     `json:"pattern,omitempty"`
	Delay        string     `json:"delay,omitempty"`
	Interval     string     `json:"interval,omitempty"`
	Processed    int        `json:"processed,omitempty"`
	Succeeded    int        `json:"succeeded,omitempty"`
	Failed       int        `json:"failed,omitempty"`
	Error        *ErrorBody `json:"error,omitempty"`
}
