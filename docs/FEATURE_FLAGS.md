# Feature Flags

This project is a Rust library with optional Cargo features.

## Cargo Features

- `cuda`: Enable CUDA-accelerated hint generation.

## Environment Variables

- `RMS24_DATA_DIR`: Optional. Enables integration tests against a local data slice when set.
- `RMS24_COVERAGE_INDEX`: Optional (0/1). When set to 1, the benchmark harness enables a coverage index for slice runs. Coverage index mode keeps hint state static (no consume/replenish) to preserve index validity.
