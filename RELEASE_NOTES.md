# Release Notes — v0.1.0

Initial release of **rms24-rs**, a Rust implementation of the RMS24 single-server
Private Information Retrieval (PIR) protocol with optional CUDA acceleration.

## Highlights

- **Core RMS24 PIR** — Median-cutoff subset selection, ChaCha12-based PRF,
  and configurable parameters for single-server PIR over 40-byte entries
  (32-byte value + 8-byte TAG fingerprint).

- **CUDA-accelerated hint generation** — Optional `cuda` feature enables GPU
  hint generation with a warp-optimized kernel, multi-GPU support, and
  distributed hint generation with shared Phase 1. Benchmarked at 22,855
  hints/sec across 50 H200 GPUs.

- **Online TCP protocol** — Framed TCP transport with client/server cores,
  client state serialization, point updates, and hint consumption/replenish
  flow for long-lived sessions.

- **KeywordPIR** — Cuckoo-hashing-based keyword PIR module that maps
  arbitrary string keys to database rows. Includes a builder binary,
  collision bucket persistence, and integration with the online protocol.

- **Request batching** — Batch query support across the online protocol and
  benchmark harness, allowing multiple PIR queries per round-trip with
  configurable batch budgets.

- **Client-side subset caching** — Reusable subset cache for client hints,
  reducing repeated work across queries on the same database.

- **Coverage index** — Optional coverage index that tracks which database rows
  are reachable by the client's current hint set, guarding against queries on
  unavailable indices.

- **Benchmark tooling** — TCP-based benchmark harness with protocol framing,
  dedicated client/server binaries, a Modal GPU benchmark script, timing
  flags, and client state caching for repeatable runs.

## Changes by Category

### Features

- Project scaffolding with params, HMAC-SHA256 PRF module (later switched to
  ChaCha12), hint state and utilities
- CPU and GPU hint generation with CUDA kernel and GPU bindings
- Warp-optimized CUDA hint generation kernel
- Multi-GPU and distributed hint generation with shared Phase 1
- PyTorch kernel for Forge optimization
- Production-grade CPU and GPU hint generation optimizations
- Online protocol types, framing helpers, transport abstraction, client/server
  cores, and network query helpers
- Online client state and serialization, query subset flow, hint consumption
  and replenish, point update flow
- Server and DB trait, server module export
- Schema40 v3 entries (account, storage, code store), constants, and helpers
- Online message types and protocol types
- Benchmark protocol types, TCP framing, client/server, harness script and
  steps
- Batch frames in bench protocol, batch handling in server and client, bench
  frame handler for batching
- Client-side subset cache for hints
- Coverage index helpers, flag, and env-var activation
- Static decode helper
- Timing flags for client, server, and benchmarks
- Synthetic database option for quick testing
- KeywordPIR module skeleton, mapping parser, cuckoo hashing core, builder
  binary, client wrapper, bench protocol flow, and benchmark client mode

### Bug Fixes

- Align PRF select/offset with vector stream
- Correct benchmark binary names and derive server block size from params
- Handle extra-entry update overlap and zero subset size in forge_v2
- Make subset generation deterministic
- Add padding to Rms24Params for Pod derive
- Add CUDA 12040 feature to cudarc; run CPU Phase 1 before GPU init
- Set TCP read/write timeouts in client
- Handle server deserialize errors without panic
- Avoid logging timing at count 0
- Avoid selecting unavailable hints from coverage index
- Bound bench framing payload size
- Harden keywordpir subset handling, reject empty subsets, fix bucket rounding
- Scale keywordpir batch budget and builder slack
- Restore batch query cap for keywordpir
- Persist collision buckets in keywordpir metadata
- Allow legacy keywordpir metadata and validate collision capacity
- KeywordPIR coverage guard and collision entry size

### Performance

- Parallelize Phase 1 subset generation with rayon
- Parallelize hint generation
- Speed up online query candidate search

### Refactoring

- Switch PRF from HMAC-SHA256 to ChaCha12

### Tests

- Integration tests for hint generation and stabilized hint_gen tests
- Correctness tests for PyTorch hint kernel
- Schema40 tests
- Optional real-slice online test with covered indices
- Subset cache reuse and cached-vs-uncached query parity
- Coverage query test with covered index selection
- Timing helper smoke test
- Median cutoff tests
- Guard RMS24_COVERAGE_INDEX env var in tests

### Documentation

- Architecture diagrams, online protocol design, and implementation plans
- Coverage index, client state cache, and runtime optimizations designs
- Batching implementation plan and q200 report
- KeywordPIR implementation plan and collision routing docs
- Benchmark results for distributed and multi-GPU runs
- Feature flags, deployment, and API endpoint docs

## Known Limitations

- The `cuda` feature requires CUDA toolkit 12.4+ and a compatible NVIDIA GPU.
- KeywordPIR collision routing is probabilistic; very high collision rates may
  require tuning cuckoo hashing parameters.
- No TLS support on the TCP transport; connections are plaintext.
- Client state serialization format is not yet stabilized and may change in
  future releases.
