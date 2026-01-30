# Deployment

This repository is a Rust library with optional CUDA support. The online protocol core is implemented in-library, but there is not yet a production server binary for deployment.

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

## Online protocol (library)

The online protocol core supports raw TCP framing with length-prefixed `bincode` frames. A server binary can wrap `online_server::ServerCore` and `online_transport::FramedIo` to expose a network service when needed.
