# Architecture

## Overview

RMS24-RS is a Rust implementation of the RMS24 single-server PIR protocol with optional CUDA acceleration for hint generation. The core treats the database as a flat array of fixed-size entries (default 40 bytes).

## Core Modules

- `src/params.rs`: Parameter derivation (block size, number of hints).
- `src/prf.rs`: ChaCha12-based PRF for subset selection and offsets.
- `src/hints.rs`: Hint state, subset representation, and utilities.
- `src/client.rs`: Offline hint generation and online query construction, including an in-memory per-hint subset cache for faster query building.

## Binaries

- `src/bin/bench_cpu_hints.rs`: CPU hint benchmarking.
- `src/bin/bench_gpu_hints.rs`: GPU hint benchmarking (with `cuda`).
- `src/bin/run_gpu_kernel.rs`: GPU kernel runner.
- `src/bin/generate_subsets.rs`: Subset precomputation helper.

## Data Model

Entries are fixed-size byte records. The default schema uses 40-byte entries: 32-byte value + 8-byte tag.

## Runtime Notes

- Online clients maintain a per-hint subset cache to avoid recomputing subset scans on each query. The cache is invalidated on hint replenishment and is not serialized.
- Coverage index mode uses static hints (no consume/replenish) to keep index validity.
