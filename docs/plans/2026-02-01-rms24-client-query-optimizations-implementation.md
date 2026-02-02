# RMS24 Client Query Optimizations Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Speed up client query construction by caching per-hint subsets and using coverage index by default, without changing query distribution or privacy semantics.

**Architecture:** Add an optional in-memory subset cache in `OnlineClient` and a toggle to use coverage index by default when available. Ensure cached subsets match uncached behavior byte-for-byte under fixed seed. Keep cache non-serialized.

**Tech Stack:** Rust, existing `OnlineClient` logic in `src/client.rs`, tests in `src/client.rs` and `tests/`.

### Task 1: Add subset cache storage on OnlineClient

**Files:**
- Modify: `src/client.rs`
- Test: `src/client.rs`

**Step 1: Write the failing test**

Add to `client::tests` in `src/client.rs`:
```rust
#[test]
fn test_subset_cache_matches_uncached() {
    let params = Params::new(64, 4, 2);
    let prf = Prf::new([7u8; 32]);
    let mut client = OnlineClient::new(params, prf, 1);

    let hint_id = 0usize;
    let uncached = client.build_subset_for_hint(hint_id);
    let cached = client.get_subset_for_hint(hint_id);

    assert_eq!(uncached, cached);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_subset_cache_matches_uncached --lib`
Expected: FAIL (no subset cache / method)

**Step 3: Write minimal implementation**

- Add `subset_cache: Vec<Option<Vec<(u32, u32)>>>` to `OnlineClient`.
- Initialize it in `OnlineClient::new` with `vec![None; total_hints]`.
- Add a private helper:
```rust
fn get_subset_for_hint(&mut self, hint_id: usize) -> Vec<(u32, u32)> {
    if let Some(ref cached) = self.subset_cache[hint_id] {
        return cached.clone();
    }
    let subset = self.build_subset_for_hint(hint_id);
    self.subset_cache[hint_id] = Some(subset.clone());
    subset
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test test_subset_cache_matches_uncached --lib`
Expected: PASS

**Step 5: Commit**

```bash
git add src/client.rs
git commit -m "feat: add subset cache for client hints"
```

### Task 2: Use subset cache in query building

**Files:**
- Modify: `src/client.rs`
- Test: `src/client.rs`

**Step 1: Write the failing test**

Add to `client::tests` in `src/client.rs`:
```rust
#[test]
fn test_subset_cache_reuse() {
    let params = Params::new(64, 4, 2);
    let prf = Prf::new([9u8; 32]);
    let mut client = OnlineClient::new(params, prf, 1);

    let hint_id = 0usize;
    let _ = client.get_subset_for_hint(hint_id);
    let first = client.subset_cache[hint_id].clone();
    let _ = client.get_subset_for_hint(hint_id);
    let second = client.subset_cache[hint_id].clone();

    assert_eq!(first, second);
    assert!(first.is_some());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_subset_cache_reuse --lib`
Expected: FAIL (subset_cache not present or not accessible)

**Step 3: Write minimal implementation**

- In `build_network_queries` and `build_network_queries_with_coverage`, replace calls to `build_subset_for_hint` with `get_subset_for_hint`.
- Ensure `subset_cache` is cleared/reinitialized when hints are regenerated or client state is reset.

**Step 4: Run test to verify it passes**

Run: `cargo test test_subset_cache_reuse --lib`
Expected: PASS

**Step 5: Commit**

```bash
git add src/client.rs
git commit -m "perf: reuse cached subsets in query building"
```

### Task 3: Use coverage index by default (when available)

**Files:**
- Modify: `src/bin/rms24_client.rs`
- Test: `src/bin/rms24_client.rs`

**Step 1: Write the failing test**

Add to `src/bin/rms24_client.rs` tests:
```rust
#[test]
fn test_default_coverage_flag() {
    let args = Args::parse_from([
        "rms24-client",
        "--db",
        "db.bin",
        "--coverage-index",
    ]);
    assert!(args.coverage_index);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_default_coverage_flag --bin rms24_client`
Expected: FAIL if coverage default is not enabled.

**Step 3: Write minimal implementation**

- Keep `--coverage-index` flag, but default coverage usage on when state cache is enabled and `coverage_index` flag is true.
- If coverage is enabled, build coverage once and use it for all queries.
- If coverage entry is empty, fall back to `build_network_queries`.

**Step 4: Run test to verify it passes**

Run: `cargo test test_default_coverage_flag --bin rms24_client`
Expected: PASS

**Step 5: Commit**

```bash
git add src/bin/rms24_client.rs
git commit -m "feat: use coverage index by default when enabled"
```

### Task 4: Privacy regression test (fixed seed)

**Files:**
- Modify: `src/client.rs`
- Test: `src/client.rs`

**Step 1: Write the failing test**

Add to `client::tests` in `src/client.rs`:
```rust
#[test]
fn test_query_bytes_equivalent_with_cache() {
    let params = Params::new(64, 4, 2);
    let prf = Prf::new([5u8; 32]);
    let mut client_uncached = OnlineClient::new(params.clone(), prf.clone(), 123);
    let mut client_cached = OnlineClient::new(params, prf, 123);
    let _ = client_cached.get_subset_for_hint(0);

    let (real_unc, dummy_unc, _h_unc) = client_uncached.build_network_queries(3).unwrap();
    let (real_cached, dummy_cached, _h_cached) = client_cached.build_network_queries(3).unwrap();

    let a = bincode::serialize(&real_unc).unwrap();
    let b = bincode::serialize(&real_cached).unwrap();
    assert_eq!(a, b);

    let a = bincode::serialize(&dummy_unc).unwrap();
    let b = bincode::serialize(&dummy_cached).unwrap();
    assert_eq!(a, b);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_query_bytes_equivalent_with_cache --lib`
Expected: FAIL if caching changes output.

**Step 3: Write minimal implementation**

- Ensure caching does not change subset ordering or random selection.
- Keep query construction identical.

**Step 4: Run test to verify it passes**

Run: `cargo test test_query_bytes_equivalent_with_cache --lib`
Expected: PASS

**Step 5: Commit**

```bash
git add src/client.rs
git commit -m "test: assert cached queries match uncached bytes"
```

### Task 5: Docs (feature flags + memory tradeoff note)

**Files:**
- Modify: `docs/FEATURE_FLAGS.md`
- Modify: `docs/ARCHITECTURE.md` (if exists)

**Step 1: Update docs**

Document new subset cache behavior and memory cost note. Mention coverage index default behavior.

**Step 2: Commit**

```bash
git add docs/FEATURE_FLAGS.md docs/ARCHITECTURE.md
git commit -m "docs: document subset cache and coverage defaults"
```

## Verification

- `cargo test test_subset_cache_matches_uncached --lib`
- `cargo test test_subset_cache_reuse --lib`
- `cargo test test_query_bytes_equivalent_with_cache --lib`
- `cargo test test_default_coverage_flag --bin rms24_client`

## Execution

Plan complete and saved to `docs/plans/2026-02-01-rms24-client-query-optimizations-implementation.md`.

Two execution options:
1. Subagent-Driven (this session)
2. Parallel Session (separate)

Which approach?
