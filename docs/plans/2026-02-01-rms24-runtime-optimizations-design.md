# RMS24 Runtime Optimizations Design (2026-02-01)

## Goal

Reduce end-to-end runtime for RMS24/KeywordPIR by identifying and removing bottlenecks in client query construction, server answer path, and serialization overhead, while preserving protocol correctness.

## Context

Recent full-db benchmarks show no scaling from 1 to many threads and similar timings between RMS24 and KeywordPIR. This suggests a shared bottleneck (likely single-threaded logic, server compute, or IO/serialization). We will add minimal instrumentation, profile, and then optimize the confirmed hot paths.

## Design Overview

We will proceed in two phases:

1) **Measure**: Add optional timing instrumentation on client and server to attribute time to specific phases. Use perf/flamegraphs to confirm hotspots.
2) **Optimize**: Target confirmed hot paths. Initial likely targets are client subset generation and candidate selection; server answer path improvements are deferred until measurement confirms need.

## Instrumentation Plan

### Client (`rms24_client`)

Add optional timing counters (enabled by flag) for:
- `build_query` (hint selection + subset build)
- `serialize` (bincode)
- `write_frame`
- `read_frame`
- `deserialize`
- `decode/replenish`

Log a single summary line every N queries and on exit:
`timing phase=<name> count=<n> total_ms=<ms> avg_us=<us>`

### Server (`rms24_server`)

Add optional timing counters (enabled by flag) for:
- `read_frame`
- `deserialize`
- `answer` (server.compute)
- `serialize`
- `write_frame`

Log a single summary line every N queries and on exit.

### Perf/Flamegraph

Run perf on hsiao for both client and server to corroborate timing logs. Use flamegraphs to pinpoint hot functions before optimization.

## Optimization Targets (Based on Code Inspection)

1) **Client subset generation** (`build_subset_for_hint`)
   - Currently scans all blocks and re-computes PRF select/offset every time a hint is used.
   - Likely O(num_blocks) per query and repeated.

2) **Client candidate search** (`build_network_queries`)
   - Scans all available hints and calls `hint_covers`, which recomputes PRF values.

3) **Server answer path** (`server.answer`)
   - Potentially CPU-heavy; exact impact to be confirmed by profiling.

4) **Serialization overhead**
   - bincode + frame read/write per query may add significant cost.

## Proposed Changes (Concrete)

### Client: subset cache

- Add optional in-memory cache: `subset_cache: Vec<Option<Vec<(u32, u32)>>>` indexed by hint id.
- New helper `get_subset_for_hint(hint_id)`:
  - If cached, return cached subset.
  - Else compute via `build_subset_for_hint`, store, and return.
- This removes repeated PRF scans for the same hint during query building.

**Flags:**
- `--subset-cache` or `RMS24_SUBSET_CACHE=1` to enable.

**Serialization:**
- Do not serialize by default (avoid state bloat). Optional follow-up if memory/time tradeoff is favorable.

### Client: coverage index default

- When enabled, build once and use for candidate selection by default.
- Only fall back to non-coverage path if `coverage[index]` is empty.
- Coverage index is not serialized due to size.

### Server: defer until profiling

- Only optimize `server.answer` once profiling shows it dominates. Potential next steps:
  - SIMD/parallel accumulation
  - Batching queries
  - Reduced allocations

## Data Flow (Client Query)

1) Choose index
2) Candidate selection (coverage index if enabled)
3) Get subset (from cache or compute)
4) Serialize + send
5) Receive + decode
6) Replenish hints

## Error Handling

- If cache build fails, fall back to non-cached subset generation.
- If coverage entry is empty, fall back to non-coverage path.
- Timing logs are best-effort; errors should not fail a run.

## Testing (TDD)

- `subset_cache_matches_uncached`: cached subset equals `build_subset_for_hint` result.
- `subset_cache_reuse`: repeated calls reuse cached data (no recompute).
- `coverage_query_still_valid`: coverage path returns valid hint and decode matches non-coverage path.
- `timing_smoke`: timing flag enables log output (format sanity).

## Success Criteria

- Timing logs identify at least one dominant phase.
- Subset cache reduces client query-build time measurably.
- End-to-end runtime decreases in controlled benchmarks without correctness regressions.

## Risks

- Subset cache memory overhead may be high for large hint counts.
- Coverage index size may be large; must remain optional and not serialized.
- Instrumentation overhead could affect microbenchmarks; keep disabled by default.

