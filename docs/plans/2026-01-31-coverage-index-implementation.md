# Coverage Index Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a coverage index option for slice benchmarks to avoid per-query scans of all hints, with explicit flagging and documentation.

**Architecture:** OnlineClient builds a coverage index (entry -> list of hint IDs) from regular hints. When enabled, the benchmark client selects real hints from the index and decodes replies without hint state mutation (static hints).

**Tech Stack:** Rust 2021, existing RMS24 client/hint logic.

---

### Task 1: Add coverage index helpers on OnlineClient

**Files:**
- Modify: `src/client.rs`
- Test: `src/client.rs`

**Step 1: Write failing tests**

Add to `src/client.rs` tests:

```rust
#[test]
fn test_build_coverage_index_contains_hint() {
    let params = Params::new(64, 4, 4);
    let prf = Prf::random();
    let mut client = OnlineClient::new(params.clone(), prf, 1);
    let db = vec![7u8; (params.num_entries as usize) * params.entry_size];
    client.generate_hints(&db).unwrap();

    let coverage = client.build_coverage_index();
    let num_reg = params.num_reg_hints as usize;

    for hint_id in 0..num_reg {
        let subset = client.build_subset_for_hint(hint_id);
        for (block, offset) in subset {
            let idx = (block as u64) * params.block_size + offset as u64;
            assert!(coverage[idx as usize].contains(&(hint_id as u32)));
        }
    }
}

#[test]
fn test_network_queries_with_coverage_selects_hint() {
    let params = Params::new(64, 4, 4);
    let prf = Prf::random();
    let mut client = OnlineClient::new(params.clone(), prf, 1);
    let db = vec![7u8; (params.num_entries as usize) * params.entry_size];
    client.generate_hints(&db).unwrap();
    let coverage = client.build_coverage_index();

    let index = 3u64;
    let (real_query, _dummy_query, real_hint) =
        client.build_network_queries_with_coverage(index, &coverage).unwrap();

    assert!(coverage[index as usize].contains(&(real_hint as u32)));
    assert_eq!(real_query.id, dummy_query.id);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test test_build_coverage_index_contains_hint`
Expected: FAIL (missing methods)

**Step 3: Implement minimal helpers**

Add to `OnlineClient`:

```rust
pub fn build_coverage_index(&self) -> Vec<Vec<u32>> {
    let num_entries = self.params.num_entries as usize;
    let num_reg = self.params.num_reg_hints as usize;
    let mut coverage = vec![Vec::new(); num_entries];
    let block_size = self.params.block_size;

    for hint_id in 0..num_reg {
        let subset = self.build_subset_for_hint(hint_id);
        for (block, offset) in subset {
            let idx = (block as u64) * block_size + (offset as u64);
            if idx < self.params.num_entries {
                coverage[idx as usize].push(hint_id as u32);
            }
        }
    }
    coverage
}

pub fn build_network_queries_with_coverage(
    &mut self,
    index: u64,
    coverage: &[Vec<u32>],
) -> Result<(crate::messages::Query, crate::messages::Query, usize), ClientError> {
    if index >= self.params.num_entries {
        return Err(ClientError::InvalidIndex);
    }
    let target_block = self.params.block_of(index) as u32;
    let target_offset = self.params.offset_in_block(index) as u32;

    let mut candidates: Vec<usize> = coverage[index as usize]
        .iter()
        .copied()
        .map(|id| id as usize)
        .collect();

    if candidates.is_empty() {
        return self.build_network_queries(index);
    }

    let candidate_idx = self.rng.gen_range(0..candidates.len());
    let real_hint = candidates.swap_remove(candidate_idx);
    let mut real_subset = self.build_subset_for_hint(real_hint);
    if let Some(pos) = real_subset
        .iter()
        .position(|(block, offset)| *block == target_block && *offset == target_offset)
    {
        real_subset.swap_remove(pos);
    }

    let dummy_hint = self.available_hints[self.rng.gen_range(0..self.available_hints.len())];
    let dummy_subset = self.build_subset_for_hint(dummy_hint);

    let id = self.next_query_id();
    let real_query = crate::messages::Query { id, subset: real_subset };
    let dummy_query = crate::messages::Query { id, subset: dummy_subset };
    Ok((real_query, dummy_query, real_hint))
}
```

**Step 4: Run tests to verify they pass**

Run:
- `cargo test test_build_coverage_index_contains_hint`
- `cargo test test_network_queries_with_coverage_selects_hint`

Expected: PASS

**Step 5: Commit**

```bash
git add src/client.rs
git commit -m "feat: add coverage index helpers"
```

---

### Task 2: Add static decode path for coverage mode

**Files:**
- Modify: `src/client.rs`
- Test: `src/client.rs`

**Step 1: Write failing test**

```rust
#[test]
fn test_decode_reply_static() {
    let params = Params::new(16, 4, 2);
    let prf = Prf::random();
    let mut client = OnlineClient::new(params.clone(), prf, 1);
    let db = vec![0u8; (params.num_entries as usize) * params.entry_size];
    client.generate_hints(&db).unwrap();

    let real_hint = 0;
    let parity = vec![0u8; params.entry_size];
    let decoded = client.decode_reply_static(real_hint, parity).unwrap();
    assert_eq!(decoded.len(), params.entry_size);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_decode_reply_static`
Expected: FAIL (missing method)

**Step 3: Implement minimal method**

```rust
pub fn decode_reply_static(
    &self,
    real_hint: usize,
    mut parity: Vec<u8>,
) -> Result<Vec<u8>, ClientError> {
    let hint_parity = &self.hints.parities[real_hint];
    if parity.len() != hint_parity.len() {
        return Err(ClientError::ParityLengthMismatch);
    }
    xor_bytes_inplace(&mut parity, hint_parity);
    Ok(parity)
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test test_decode_reply_static`
Expected: PASS

**Step 5: Commit**

```bash
git add src/client.rs
git commit -m "feat: add static decode helper"
```

---

### Task 3: Add coverage flag to rms24-client and hook into harness

**Files:**
- Modify: `src/bin/rms24_client.rs`
- Modify: `scripts/bench_hsiao.sh`
- Test: `src/bin/rms24_client.rs`

**Step 1: Write failing test**

Extend the existing parse_args test to include `--coverage-index`:

```rust
#[test]
fn test_parse_args() {
    let args = Args::parse_from([
        "rms24-client",
        "--db", "db.bin",
        "--entry-size", "40",
        "--lambda", "80",
        "--server", "127.0.0.1:4000",
        "--query-count", "1000",
        "--coverage-index",
    ]);
    assert!(args.coverage_index);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --bin rms24_client test_parse_args`
Expected: FAIL

**Step 3: Implement flag and logic**

- Add `coverage_index: bool` to Args.
- If enabled, build coverage index once after hint generation.
- Use `build_network_queries_with_coverage` and `decode_reply_static`.
- Skip `consume_network_reply` when coverage is enabled.

**Step 4: Run test to verify it passes**

Run: `cargo test --bin rms24_client test_parse_args`
Expected: PASS

**Step 5: Update harness**

- Add `RMS24_COVERAGE_INDEX` env var (default 1 for slice, 0 for full).
- Pass `--coverage-index` when enabled.
- Log flag to `env.txt`.

**Step 6: Commit**

```bash
git add src/bin/rms24_client.rs scripts/bench_hsiao.sh
git commit -m "feat: add coverage index flag to client"
```

---

### Task 4: Document the feature flag

**Files:**
- Modify: `docs/FEATURE_FLAGS.md`

**Step 1: Add flag entry**

Describe:
- `RMS24_COVERAGE_INDEX=1` enables coverage index for slice benchmarks
- When enabled, hint state is static (no consume/replenish)

**Step 2: Commit**

```bash
git add docs/FEATURE_FLAGS.md
git commit -m "docs: document coverage index flag"
```
