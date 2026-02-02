# Feature Flags

This project is a Rust library with optional Cargo features.

## Cargo Features

- `cuda`: Enable CUDA-accelerated hint generation.

## Environment Variables

- `RMS24_DATA_DIR`: Optional. Enables integration tests against a local data slice when set.
- `RMS24_COVERAGE_INDEX`: Optional (0/1/true/yes). When set, the benchmark harness enables a coverage index for slice runs, and `rms24_client` will enable coverage without requiring `--coverage-index`. Coverage index mode keeps hint state static (no consume/replenish) to preserve index validity.
- `RMS24_STATE_PATH`: Optional. Overrides the benchmark harness RMS24 client state cache path used to persist hint generation results.
- `CACHE_DIR`: Optional. Overrides the base directory for benchmark state cache files.

## CLI Flags

- `rms24_client --timing`: Optional. Emits per-phase timing summaries during runs.
- `rms24_client --timing-every <N>`: Optional. Emit timing summaries every N occurrences per phase (default: 1000).
- `rms24_server --timing`: Optional. Emits per-phase timing summaries during runs.
- `rms24_server --timing-every <N>`: Optional. Emit timing summaries every N occurrences per phase (default: 1000).

## KeywordPIR (benchmark client)

KeywordPIR mode expects `rms24_client --db` to point at `keywordpir-db.bin`, plus the mapping and metadata artifacts from `rms24_keywordpir_build`.

- `rms24_client --mode keywordpir`: Enable KeywordPIR benchmarking mode.
- `rms24_client --query-count <N>`: In keywordpir mode, counts keywords (not total RMS24 queries). Each keyword expands into `num_hashes * bucket_size` candidate positions, and each position emits one real + one dummy RMS24 query over the network.
- `rms24_client --keywordpir-metadata <path>`: Required. `keywordpir-metadata.json` from the builder.
- `rms24_client --account-mapping <path>`: Required. Account mapping file (20-byte key + u32 index).
- `rms24_client --storage-mapping <path>`: Required. Storage mapping file (52-byte key + u32 index).
- `rms24_client --collision-tags <path>`: Optional. Collision tag list for keywordpir collisions.
- `rms24_client --collision-server <addr>`: Required when `--collision-tags` is provided and non-empty.
- `rms24_client` expects `keywordpir-collision-db.bin` to live alongside `keywordpir-metadata.json` when collision tags are non-empty, so it can build collision-table hints for the collision server.

## Online batching (benchmark client/server)

- `rms24_client --batch-size <N>`: Optional. Send up to N network queries per frame.
- `rms24_server --max-batch-queries <N>`: Optional. Cap the number of queries in a batch.
