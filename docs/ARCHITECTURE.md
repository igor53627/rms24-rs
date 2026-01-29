# Architecture

## Overview

RMS24-RS is a Rust implementation of the RMS24 single-server PIR protocol with optional CUDA acceleration for hint generation. The core treats the database as a flat array of fixed-size entries (default 40 bytes).

## Core Modules

- `src/params.rs`: Parameter derivation (block size, number of hints).
- `src/prf.rs`: ChaCha12-based PRF for subset selection and offsets.
- `src/hints.rs`: Hint state, subset representation, and utilities.
- `src/client.rs`: Offline hint generation and subset precomputation.

## Binaries

- `src/bin/bench_cpu_hints.rs`: CPU hint benchmarking.
- `src/bin/bench_gpu_hints.rs`: GPU hint benchmarking (with `cuda`).
- `src/bin/run_gpu_kernel.rs`: GPU kernel runner.
- `src/bin/generate_subsets.rs`: Subset precomputation helper.

## Data Model

Entries are fixed-size byte records. The default schema uses 40-byte entries: 32-byte value + 8-byte tag.
