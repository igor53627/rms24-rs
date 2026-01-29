# Deployment

This repository is a Rust library with optional CUDA support. There is no network service to deploy.

## Build

```bash
cargo build --release
```

## Build with CUDA

```bash
cargo build --release --features cuda
```

## Tests

```bash
cargo test
```

## Optional data-slice tests

Set `RMS24_DATA_DIR` to enable integration tests that use a local data slice.
