# N4: Atomic encrypt writes + decrypt permission clamp

**Date:** 2026-09-07  
**Status:** Approved  
**Roadmap:** N4 (NV-006, NV-007)  
**Branch:** `feat/n4-atomic-encrypt-mode-clamp`

## Goals

1. Encrypt outputs use temp → sync → close → rename (Windows-safe).
2. Decrypt metadata restore clamps file modes ≤0600 and dirs ≤0700 by default.
3. `--preserve-mode` opts into restoring original mode bits.
4. Remove unused RecoveryHandler; keep/improve atomic write helpers.
5. Docs + tests in same PR; mark N3 merged / N4 pending on ROADMAP.

## Non-goals

- `--force` overwrite prompts (X1).
- Streaming encrypt (L2).
