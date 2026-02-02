# Coverage Index for Benchmarking Design

**Goal:** Make slice benchmarks practical by precomputing a coverage index that maps each entry index to a list of hint IDs that cover it, avoiding per-query scans of all hints.

**Scope:** Benchmark-only optimization. When enabled, queries use a precomputed coverage index and **freeze hint state** (no consume/replenish) to keep the index valid. Not intended for full-snapshot runs.

## Architecture

- Add a `coverage index` built from existing hint subsets: `Vec<Vec<u32>>` where `coverage[i]` lists hint IDs covering entry `i`.
- Build index only for **regular hints** (available hints) to avoid backup-hint churn.
- Add `OnlineClient::build_coverage_index()` and `OnlineClient::build_network_queries_with_coverage()` helpers.
- When coverage is enabled, decode replies without updating hint state.

## Feature Flag

- Add `--coverage-index` to `rms24-client` (explicit opt-in).
- Benchmark harness enables the flag by default for `DATASET=slice` and disables for `DATASET=full`.
- Document behavior in `docs/FEATURE_FLAGS.md`:
  - Coverage index is **slice-only** by default.
  - When enabled, **hints are static** (no consume/replenish).

## Data Flow

1) Client loads DB, generates hints.
2) If `--coverage-index`, build coverage index once.
3) Per query:
   - Choose real hint from `coverage[index]`.
   - Build real/dummy subsets only for selected hints.
   - Decode reply (XOR with hint parity) **without** updating hints.

## Trade-offs

- **Pros:** Makes 1M slice benchmarks feasible (fast query selection).
- **Cons:** Not full protocol behavior (static hints); coverage index is too large for full snapshots.

## Testing

- Ensure coverage index contains expected hints for known subset entries.
- Ensure coverage-based query selection chooses a hint listed for target entry.
- Ensure decode path works without mutating hint state.
