# Architecture

## Overview

RMS24-RS is a Rust implementation of the RMS24 single-server PIR protocol with optional CUDA acceleration for hint generation. The core treats the database as a flat array of fixed-size entries (default 40 bytes).

## Core Modules

- `src/params.rs`: Parameter derivation (block size, number of hints).
- `src/prf.rs`: ChaCha12-based PRF for subset selection and offsets.
- `src/hints.rs`: Hint state, subset representation, and utilities.
- `src/client.rs`: Offline hint generation and online query construction, including an in-memory per-hint subset cache for faster query building.
- `src/online.rs`: Online protocol types (config, queries, replies, errors).
- `src/online_framing.rs`: Length-prefixed framing helpers for byte streams.
- `src/online_transport.rs`: Transport abstraction and framed I/O implementation.
- `src/online_server.rs`: Sync server core for RMS24/KeywordPIR routing.
- `src/online_client.rs`: Sync client helpers for building/parsing online queries.

## Online Protocol

The online protocol exposes a single logical entrypoint with a mode switch (RMS24 or KeywordPIR). Clients send a `RunConfig` frame, then one or more `Query` frames over a raw TCP connection using length-prefixed `bincode` encoding. The server core maps RMS24 requests to `messages::Query` and uses `Server::answer`, while KeywordPIR requests are handled by an injected handler.

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
