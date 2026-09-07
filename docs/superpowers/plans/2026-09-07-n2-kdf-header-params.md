# N2 KDF Header Params Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist Argon2id KDF parameters in `.nokvault` v2 headers, keep v1 decryptable, and apply config `key_derivation` to new encryptions only.

**Architecture:** Versioned binary header (v1 unchanged; v2 appends Memory/Time/Parallelism/pad/KeyLength). A unified in-memory `NokvaultHeader` always exposes KDF fields (defaults filled when reading v1). Encrypt-side applies runtime config via `KeyManager.SetParams`; decrypt-side sets params from the header before derive. Docs site configuration page is corrected in the same PR after code is green.

**Tech Stack:** Go, `encoding/binary`, Argon2id (`golang.org/x/crypto/argon2`), Cobra CLI, testify, Astro docs site.

**Spec:** `docs/superpowers/specs/2026-09-07-n2-kdf-header-params-design.md`

## Global Constraints

- `CurrentVersion` becomes **2**; v1 files remain readable forever with `DefaultArgon2Params()` (65536 / 3 / 4 / 32).
- Decrypt **never** uses live config for KDF; encrypt/rotate/watch/schedule **do**.
- No compress flag / cipher alg IDs in this PR.
- No `key_length` in TOML; always write/read `crypto.DefaultKeyLength` (32) in header for v2.
- Reject parallelism 0, time 0, memory 0, or keyLength ≠ 32 on write/read of v2.
- Docs site updates land in the **same PR**, after behavior is stable.
- Branch: `feat/kdf-header-params` from latest `main`.
- After modifying Go files, run `graphify update .` before finishing the PR.
- Commit only when the user asks, or at task boundaries if the user already approved executing the plan with commits; otherwise stage work and ask before commit/PR.

---

## File map

| File | Responsibility |
|------|----------------|
| `internal/core/file_handler.go` | Versioned header write/read; `HeaderSize`; `ValidateKDFParams`; `Argon2Params()` on header |
| `internal/core/file_handler_test.go` | v1/v2 header tests + v1 fixture bytes |
| `internal/core/key_manager.go` | `SetArgon2Params(*crypto.Argon2Params)`; keep `SetParams` |
| `internal/core/encryption.go` | `NewEncryptionServiceWithParams(*crypto.Argon2Params)` |
| `internal/cli/runtime_config.go` | Store/get/clear loaded `*config.Config` |
| `internal/cli/root.go` | Load config into runtime store |
| `internal/cli/testing.go` | Clear runtime config in `ResetCLIStateForTest` |
| `internal/cli/encrypt.go`, `watch.go`, `schedule.go`, `rotate_key.go` | Apply config on encrypt-side; pass params into `WriteHeader` |
| `internal/cli/decrypt.go`, `rotate_key.go`, `internal/core/directory.go` | Apply header params before derive; pass params into `WriteHeader` on encrypt |
| `tests/integration/kdf_header_test.go` | Custom params round-trip + config-does-not-affect-decrypt |
| `docs/src/pages/docs/configuration.astro`, `security.astro` | Usage docs |
| `CHANGELOG.md`, `ROADMAP.md`, optional `HELP_DOCS/FORMAT.md` | Release notes + format sketch |

---

### Task 1: Branch + failing header tests

**Files:**
- Create branch `feat/kdf-header-params`
- Modify: `internal/core/file_handler_test.go`
- Test: same

**Interfaces:**
- Produces (expected API for Task 2):
  - `CurrentVersion == 2`
  - `WriteHeader(w io.Writer, salt []byte, metadata *FileMetadata, params *crypto.Argon2Params) error`
  - `ReadHeader` / `ReadHeaderWithMetadata` populate `Memory`, `Time`, `Parallelism`, `KeyLength` for both versions
  - `func (h *NokvaultHeader) Argon2Params() *crypto.Argon2Params`
  - `func HeaderWireSize(version uint16) int`

- [ ] **Step 1: Create branch from main**

```bash
cd E:/repos/nokvault
git checkout main
git pull origin main
git checkout -b feat/kdf-header-params
```

- [ ] **Step 2: Add failing tests** to `internal/core/file_handler_test.go`

```go
func TestFileHandler_WriteHeader_V2IncludesKDFParams(t *testing.T) {
	fh := NewFileHandler()
	salt := make([]byte, 16)
	params := &crypto.Argon2Params{Memory: 32768, Time: 2, Parallelism: 2, KeyLength: 32}

	var buf bytes.Buffer
	require.NoError(t, fh.WriteHeader(&buf, salt, nil, params))

	header, meta, err := fh.ReadHeaderWithMetadata(&buf)
	require.NoError(t, err)
	assert.Nil(t, meta)
	assert.Equal(t, uint16(2), header.Version)
	assert.Equal(t, uint32(32768), header.Memory)
	assert.Equal(t, uint32(2), header.Time)
	assert.Equal(t, uint8(2), header.Parallelism)
	assert.Equal(t, uint32(32), header.KeyLength)
	assert.Equal(t, uint64(HeaderWireSize(2)), header.DataOffset)
}

func TestFileHandler_ReadHeader_V1UsesDefaultKDFParams(t *testing.T) {
	// Hand-built v1 header: magic + version=1 + salt + metadataSize=0 + dataOffset=sizeof(v1)
	fh := NewFileHandler()
	var buf bytes.Buffer
	magic := [8]byte{}
	copy(magic[:], NokvaultMagic)
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, magic))
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, uint16(1)))
	salt := make([]byte, 16)
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, salt))
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, uint32(0)))
	v1Size := HeaderWireSize(1)
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, uint64(v1Size)))

	header, err := fh.ReadHeader(&buf)
	require.NoError(t, err)
	assert.Equal(t, uint16(1), header.Version)
	defs := crypto.DefaultArgon2Params()
	assert.Equal(t, defs.Memory, header.Memory)
	assert.Equal(t, defs.Time, header.Time)
	assert.Equal(t, defs.Parallelism, header.Parallelism)
	assert.Equal(t, defs.KeyLength, header.KeyLength)
}

func TestFileHandler_WriteHeader_RejectsInvalidParams(t *testing.T) {
	fh := NewFileHandler()
	salt := make([]byte, 16)
	err := fh.WriteHeader(&bytes.Buffer{}, salt, nil, &crypto.Argon2Params{
		Memory: 0, Time: 3, Parallelism: 4, KeyLength: 32,
	})
	assert.Error(t, err)
}
```

Add import `"encoding/binary"` and `"github.com/jimididit/nokvault/internal/crypto"` if missing.

Update existing `WriteHeader` call sites in this test file to pass `crypto.DefaultArgon2Params()` as the fourth argument (they will not compile until Task 2 — that is expected after Step 3 starts; for Step 2 only add the new tests, then in Task 2 update call sites together with the signature change).

Prefer: in Step 2, temporarily keep old signature and only add tests that won't compile — RED is compile failure OR assertion failure. Cleaner: Task 2 implements signature + updates all call sites; Task 1 only adds the three new test functions assuming the new API (RED = compile fail).

- [ ] **Step 3: Run tests (expect fail/compile error)**

```bash
go test ./internal/core -run "TestFileHandler_WriteHeader_V2|TestFileHandler_ReadHeader_V1|TestFileHandler_WriteHeader_Rejects" -count=1
```

Expected: compile error (missing 4th arg / undefined `HeaderWireSize`) or FAIL.

- [ ] **Step 4: Commit** (if executing with commits)

```bash
git add internal/core/file_handler_test.go
git commit -m "test: add failing v2 KDF header coverage"
```

---

### Task 2: Implement versioned header read/write

**Files:**
- Modify: `internal/core/file_handler.go`
- Modify: all `WriteHeader(` callers (encrypt, watch, directory, rotate_key, tests)
- Modify: `internal/core/file_handler_test.go` existing helpers

**Interfaces:**
- Consumes: `*crypto.Argon2Params`
- Produces: versioned header API as in Task 1

- [ ] **Step 1: Replace header types/constants in `file_handler.go`**

```go
import (
	// existing...
	"github.com/jimididit/nokvault/internal/crypto"
)

// NokvaultHeader is the in-memory header. Wire layout depends on Version.
type NokvaultHeader struct {
	Magic        [8]byte
	Version      uint16
	Salt         [16]byte
	MetadataSize uint32
	DataOffset   uint64
	Memory       uint32
	Time         uint32
	Parallelism  uint8
	KeyLength    uint32
}

const (
	NokvaultMagic  = "NOKVAULT"
	Version1       = uint16(1)
	Version2       = uint16(2)
	CurrentVersion = Version2
)

// HeaderWireSize returns on-disk header size for a format version (excluding JSON metadata).
func HeaderWireSize(version uint16) int {
	switch version {
	case Version1:
		return 8 + 2 + 16 + 4 + 8 // 38
	case Version2:
		return HeaderWireSize(Version1) + 4 + 4 + 1 + 3 + 4 // +16 = 54
	default:
		return -1
	}
}

func ValidateKDFParams(p *crypto.Argon2Params) error {
	if p == nil {
		return fmt.Errorf("kdf params are required")
	}
	if p.Memory == 0 || p.Time == 0 || p.Parallelism == 0 {
		return fmt.Errorf("invalid kdf params: memory, time, and parallelism must be non-zero")
	}
	if p.KeyLength != crypto.DefaultKeyLength {
		return fmt.Errorf("invalid kdf params: key length must be %d", crypto.DefaultKeyLength)
	}
	return nil
}

func (h *NokvaultHeader) Argon2Params() *crypto.Argon2Params {
	return &crypto.Argon2Params{
		Memory:      h.Memory,
		Time:        h.Time,
		Parallelism: h.Parallelism,
		KeyLength:   h.KeyLength,
	}
}
```

- [ ] **Step 2: Rewrite `WriteHeader`**

```go
func (fh *FileHandler) WriteHeader(writer io.Writer, salt []byte, metadata *FileMetadata, params *crypto.Argon2Params) error {
	if err := ValidateKDFParams(params); err != nil {
		return err
	}
	if len(salt) != 16 {
		return fmt.Errorf("salt must be 16 bytes")
	}

	var metadataJSON []byte
	if metadata != nil {
		var err error
		metadataJSON, err = json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("failed to serialize metadata: %w", err)
		}
	}

	headerSize := HeaderWireSize(CurrentVersion)
	dataOffset := uint64(headerSize) + uint64(len(metadataJSON))

	var magic [8]byte
	copy(magic[:], NokvaultMagic)
	var saltArr [16]byte
	copy(saltArr[:], salt)

	if err := binary.Write(writer, binary.LittleEndian, magic); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if err := binary.Write(writer, binary.LittleEndian, CurrentVersion); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if err := binary.Write(writer, binary.LittleEndian, saltArr); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if err := binary.Write(writer, binary.LittleEndian, uint32(len(metadataJSON))); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if err := binary.Write(writer, binary.LittleEndian, dataOffset); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	// v2 KDF fields
	if err := binary.Write(writer, binary.LittleEndian, params.Memory); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if err := binary.Write(writer, binary.LittleEndian, params.Time); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if err := binary.Write(writer, binary.LittleEndian, params.Parallelism); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	pad := [3]byte{}
	if err := binary.Write(writer, binary.LittleEndian, pad); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if err := binary.Write(writer, binary.LittleEndian, params.KeyLength); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	if len(metadataJSON) > 0 {
		if _, err := writer.Write(metadataJSON); err != nil {
			return fmt.Errorf("failed to write metadata: %w", err)
		}
	}
	return nil
}
```

- [ ] **Step 3: Rewrite `ReadHeader`** — read common prefix, branch on version, fill defaults for v1, validate v2 params.

```go
func (fh *FileHandler) ReadHeader(reader io.Reader) (*NokvaultHeader, error) {
	h := &NokvaultHeader{}
	if err := binary.Read(reader, binary.LittleEndian, &h.Magic); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}
	if string(h.Magic[:]) != NokvaultMagic {
		return nil, fmt.Errorf("invalid magic number: not a nokvault file")
	}
	if err := binary.Read(reader, binary.LittleEndian, &h.Version); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &h.Salt); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &h.MetadataSize); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &h.DataOffset); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	switch h.Version {
	case Version1:
		defs := crypto.DefaultArgon2Params()
		h.Memory = defs.Memory
		h.Time = defs.Time
		h.Parallelism = defs.Parallelism
		h.KeyLength = defs.KeyLength
	case Version2:
		if err := binary.Read(reader, binary.LittleEndian, &h.Memory); err != nil {
			return nil, fmt.Errorf("failed to read header: %w", err)
		}
		if err := binary.Read(reader, binary.LittleEndian, &h.Time); err != nil {
			return nil, fmt.Errorf("failed to read header: %w", err)
		}
		if err := binary.Read(reader, binary.LittleEndian, &h.Parallelism); err != nil {
			return nil, fmt.Errorf("failed to read header: %w", err)
		}
		var pad [3]byte
		if err := binary.Read(reader, binary.LittleEndian, &pad); err != nil {
			return nil, fmt.Errorf("failed to read header: %w", err)
		}
		if err := binary.Read(reader, binary.LittleEndian, &h.KeyLength); err != nil {
			return nil, fmt.Errorf("failed to read header: %w", err)
		}
		if err := ValidateKDFParams(h.Argon2Params()); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported version: %d", h.Version)
	}
	return h, nil
}
```

Leave `ReadHeaderWithMetadata` as-is (still uses `ReadHeader` then metadata).

- [ ] **Step 4: Update every `WriteHeader(` call** to pass params:

```bash
rg "WriteHeader\(" -n
```

- Encrypt/watch/directory/rotate: pass `encryptionService.GetKeyManager().Params()` or `crypto.DefaultArgon2Params()` until Task 3 adds `Params()`.
- For Task 2 interim: add `func (km *KeyManager) Params() *crypto.Argon2Params { return km.params }` in `key_manager.go` (tiny helper).
- Tests: pass `crypto.DefaultArgon2Params()`.

- [ ] **Step 5: Run unit tests**

```bash
go test ./internal/core -count=1
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/core/file_handler.go internal/core/file_handler_test.go internal/core/key_manager.go internal/cli internal/core/directory.go
git commit -m "feat: version-2 header stores Argon2 KDF parameters"
```

---

### Task 3: Decrypt uses header params; encrypt service accepts params

**Files:**
- Modify: `internal/core/key_manager.go`, `internal/core/encryption.go`
- Modify: `internal/cli/decrypt.go`, `internal/cli/rotate_key.go`, `internal/core/directory.go`

**Interfaces:**
- Produces:
  - `func (km *KeyManager) SetArgon2Params(p *crypto.Argon2Params)`
  - `func (km *KeyManager) Params() *crypto.Argon2Params`
  - `func NewEncryptionServiceWithParams(p *crypto.Argon2Params) *EncryptionService`

- [ ] **Step 1: Extend KeyManager / EncryptionService**

```go
func (km *KeyManager) Params() *crypto.Argon2Params {
	return km.params
}

func (km *KeyManager) SetArgon2Params(p *crypto.Argon2Params) {
	if p == nil {
		km.params = crypto.DefaultArgon2Params()
		return
	}
	km.params = &crypto.Argon2Params{
		Memory: p.Memory, Time: p.Time, Parallelism: p.Parallelism, KeyLength: p.KeyLength,
	}
}

func NewEncryptionServiceWithParams(p *crypto.Argon2Params) *EncryptionService {
	es := NewEncryptionService()
	es.keyManager.SetArgon2Params(p)
	return es
}
```

- [ ] **Step 2: Before every decrypt-side `DeriveKeyFromPasswordAndSalt`, set params from header**

Pattern (decrypt.go, directory decrypt, rotate_key old-key path):

```go
keyManager := encryptionService.GetKeyManager()
keyManager.SetArgon2Params(header.Argon2Params())
key, err := keyManager.DeriveKeyFromPasswordAndSalt(password, header.Salt[:])
```

For rotate-key **new** key derivation: keep manager params as encrypt-side config params (Task 4); after decrypt, re-apply config params before generating new salt/key (or use two managers). Preferred:

```go
// decrypt with header params
keyManager.SetArgon2Params(header.Argon2Params())
oldKey, err := keyManager.DeriveKeyFromPasswordAndSalt(oldPassword, header.Salt[:])
// ... decrypt ...
// re-key with runtime/config params (defaults until Task 4 wires config)
keyManager.SetArgon2Params(crypto.DefaultArgon2Params()) // Task 4: from runtime config
newKey, newSalt, err := keyManager.DeriveKeyFromPassword(newPassword)
// WriteHeader(..., keyManager.Params())
```

- [ ] **Step 3: Run core + integration smoke**

```bash
go test ./internal/core ./tests/integration -count=1
```

Expected: PASS (existing round-trips still use matching defaults on encrypt+decrypt).

- [ ] **Step 4: Commit**

```bash
git commit -am "fix: derive decrypt keys from header KDF parameters"
```

---

### Task 4: Wire runtime config into encrypt-side KeyManager

**Files:**
- Create: `internal/cli/runtime_config.go`
- Modify: `internal/cli/root.go`, `internal/cli/testing.go`
- Modify: `internal/cli/encrypt.go`, `watch.go`, `schedule.go`, `rotate_key.go`
- Create: `tests/integration/kdf_header_test.go`

**Interfaces:**
- Produces:
  - `func SetRuntimeConfig(c *config.Config)`
  - `func GetRuntimeConfig() *config.Config`
  - `func ClearRuntimeConfig()`
  - `func applyKDFConfig(km *core.KeyManager)`

- [ ] **Step 1: Add runtime config store**

```go
// internal/cli/runtime_config.go
package cli

import (
	"github.com/jimididit/nokvault/internal/config"
	"github.com/jimididit/nokvault/internal/core"
	"github.com/jimididit/nokvault/internal/crypto"
)

var runtimeConfig *config.Config

func SetRuntimeConfig(c *config.Config) { runtimeConfig = c }
func GetRuntimeConfig() *config.Config  { return runtimeConfig }
func ClearRuntimeConfig()               { runtimeConfig = nil }

func applyKDFConfig(km *core.KeyManager) {
	cfg := GetRuntimeConfig()
	if cfg == nil {
		km.SetArgon2Params(crypto.DefaultArgon2Params())
		return
	}
	km.SetParams(cfg.KeyDerivation.MemoryCost, cfg.KeyDerivation.TimeCost, cfg.KeyDerivation.Parallelism, crypto.DefaultKeyLength)
}
```

In `Execute`:

```go
cm := config.NewConfigManager()
_ = cm.Load()
SetRuntimeConfig(cm.Get())
```

In `ResetCLIStateForTest`: call `ClearRuntimeConfig()`.

- [ ] **Step 2: Call `applyKDFConfig(keyManager)`** after `NewEncryptionService()` in encrypt, watch, schedule, and on rotate **new-key** path (after decrypt).

- [ ] **Step 3: Write integration test** `tests/integration/kdf_header_test.go`

```go
func TestCLI_EncryptDecrypt_CustomKDFParams(t *testing.T) {
	ResetCLIStateForTest()
	// Build a config with MemoryCost=32768, TimeCost=2, Parallelism=2
	cfg := config.DefaultConfig()
	cfg.KeyDerivation.MemoryCost = 32768
	cfg.KeyDerivation.TimeCost = 2
	cfg.KeyDerivation.Parallelism = 2
	cli.SetRuntimeConfig(cfg)
	defer cli.ClearRuntimeConfig()

	// encrypt with password via CLI helpers used by other integration tests
	// then decrypt with defaults in runtime config changed to something else
	// assert decrypt still succeeds
	// optionally parse header Version==2 and Memory==32768 via core.FileHandler
}
```

Follow existing patterns in `tests/integration/rotate_key_test.go` / `cli_helpers_test.go` for invoking CLI.

Also assert: after encrypt, set runtime config to different params; decrypt still works (proves decrypt ignores config).

- [ ] **Step 4: Run tests**

```bash
go test ./tests/integration -run TestCLI_EncryptDecrypt_CustomKDFParams -count=1
go test ./... -count=1
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cli tests/integration/kdf_header_test.go
git commit -m "feat: apply config key_derivation to new encryptions"
```

---

### Task 5: Docs pass + changelog/roadmap + graphify

**Files:**
- Modify: `docs/src/pages/docs/configuration.astro`
- Modify: `docs/src/pages/docs/security.astro` (short note on persisted params)
- Modify: `CHANGELOG.md`, `ROADMAP.md`
- Create (optional but recommended): `HELP_DOCS/FORMAT.md` sketch from spec layout
- Note: `docs/.../changelog.astro` only links to GitHub — no content change required unless adding a one-liner.

- [ ] **Step 1: Fix configuration.astro** to use real schema and document encrypt-only semantics:

```toml
[encryption]
algorithm = "aes256gcm"
compression = false
preserve_metadata = true

[key_derivation]
algorithm = "argon2id"
memory_cost = 65536  # KiB
time_cost = 3
parallelism = 4
```

State clearly: these settings apply when **creating** encrypted files; decrypt always uses parameters stored in the file (format v2) or built-in defaults (v1).

Replace bogus `nokvault config --set argon2.*` examples with whatever `config` command actually supports — check `internal/cli/config.go` and match reality (if `--set` keys differ, document the working form or the TOML file edit path).

- [ ] **Step 2: Security page** — under Argon2 section, add that parameters are written into the `.nokvault` header for new files.

- [ ] **Step 3: CHANGELOG `[Unreleased]`** — note v2 header + config wiring + v1 compat.

- [ ] **Step 4: ROADMAP** — mark N2 DONE (PR pending).

- [ ] **Step 5: `graphify update .`**

- [ ] **Step 6: Final verification**

```bash
go test ./... -count=1
# optional docs build if node available:
# cd docs && npm ci && npm run build
```

- [ ] **Step 7: Commit + open PR** (when user asks)

```bash
git add docs CHANGELOG.md ROADMAP.md HELP_DOCS/FORMAT.md graphify-out
git commit -m "docs: document v2 KDF header and real key_derivation config"
git push -u origin HEAD
gh pr create --title "feat: persist Argon2 params in v2 header (N2)" --body "..."
```

---

## Spec coverage checklist

| Spec requirement | Task |
|------------------|------|
| v2 header fields + pad | 2 |
| v1 decrypt with defaults | 2, 3 |
| Encrypt writes v2 | 2 |
| Decrypt from header | 3 |
| Config → SetParams for new encrypts | 4 |
| No compress/alg IDs | (non-goal) |
| Docs site same PR | 5 |
| Tests | 1, 4 |
| CHANGELOG / ROADMAP | 5 |

## Placeholder / consistency self-review

- `WriteHeader` fourth arg is always `*crypto.Argon2Params`.
- `HeaderWireSize(1)=38`, `HeaderWireSize(2)=54`.
- Runtime config cleared in tests to avoid leakage.
- Rotate-key: old derive from header; new derive from config params; write v2 header with new params.
