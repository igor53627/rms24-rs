# Feature Flags

This project is a Rust library with optional Cargo features.

## Cargo Features

- `cuda`: Enable CUDA-accelerated hint generation.

## Environment Variables

- `RMS24_DATA_DIR`: Optional. Enables integration tests against a local data slice when set.
- `RMS24_COVERAGE_INDEX`: Optional (0/1). When set to 1, the benchmark harness enables a coverage index for slice runs. Coverage index mode keeps hint state static (no consume/replenish) to preserve index validity.
- `RMS24_STATE_PATH`: Optional. Overrides the benchmark harness RMS24 client state cache path used to persist hint generation results.
- `CACHE_DIR`: Optional. Overrides the base directory for benchmark state cache files.

## CLI Flags

- `rms24_client --timing`: Optional. Emits per-phase timing summaries during runs.
- `rms24_client --timing-every <N>`: Optional. Emit timing summaries every N occurrences per phase (default: 1000).
- `rms24_server --timing`: Optional. Emits per-phase timing summaries during runs.
- `rms24_server --timing-every <N>`: Optional. Emit timing summaries every N occurrences per phase (default: 1000).
