# RMS24 Client State Cache + Progress Logging Design

Date: 2026-01-31
Owner: Codex + user
Scope: `rms24_client` hint generation caching and progress logging (full DB baseline).

## Problem

Full‑DB benchmarks spend a long time in `Client::generate_hints()` with no progress output.
If the process restarts, we lose hours of work. We need reproducible, restartable runs.

## Goals

- Persist `OnlineClient` state to disk so hint generation can be reused across runs.
- Emit progress logs during hint generation (percent + ETA).
- Keep the bench harness simple; a single flag is preferred.
- Maintain determinism when `--seed` is provided.

## Non‑Goals

- Algorithmic optimization of hint generation.
- GPU acceleration changes.
- Changing protocol semantics.

## Design Overview

Add a new CLI flag to `rms24_client`:

```text
--state <path>
```

If `<path>` exists, the client attempts to deserialize `OnlineClient` from disk, validates
it against the current run, and reuses it. If the file is missing or invalid, it generates
hints, logs progress, and saves the state to `<path>`.

The bench harness will pass a fixed cache path such as:

```text
/data/rms24/cache/hints_${dataset}_entry${entry}_lambda${lambda}_seed${seed}.bin
```

This yields reuse across runs and preserves reproducibility. The cached state contains the
PRF key, so this file should be treated as sensitive.

## Validation Rules

State loaded from disk is accepted only if:

- `params.entry_size`, `params.num_entries`, and `params.lambda` match the current DB/CLI.
- `validate_state()` succeeds (length checks, PRF ID ranges, parity sizes).
- If `--seed != 0`, the PRF key matches the seed‑derived PRF key.

If any check fails, the cache is ignored and regenerated.

## Progress Logging

Add percent‑based logs inside `Client::generate_hints()`:

- Phase 1 (cutoffs/extras): log every 1% of total hints.
- Phase 2 (database blocks): log every 1% of total blocks.

Each log line includes phase, percent, elapsed seconds, and ETA, e.g.:

```text
progress phase=phase1 pct=12.0 elapsed_s=123 eta_s=900
```

Logs go to stdout so they are captured by existing harness logs and do not interfere with
the `elapsed_ms` parsing.

## Error Handling

- Cache load errors are non‑fatal: log warning and regenerate.
- Cache save errors are non‑fatal: log warning and continue.
- Use atomic writes (`.tmp` + rename) for the cache file.

## Testing

- Unit test: `serialize_state` → `deserialize_state` round‑trip preserves PRF key and sizes.
- CLI test: `--state` flag parses.
- Small integration test with a tiny DB: load cached state and verify `available_hints` and
  `hint_prf_ids` lengths are correct.

## Impacted Files

- `src/bin/rms24_client.rs` (new `--state` flag, cache load/save flow).
- `src/client.rs` (progress logging inside `generate_hints()`).
- `scripts/bench_hsiao.sh` (compute fixed cache path, pass `--state`).
- Docs: add cache flag description (FEATURE_FLAGS or benchmarks doc).
