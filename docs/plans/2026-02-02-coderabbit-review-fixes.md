# CodeRabbit Review Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Address all CodeRabbit review findings before opening the PR.

**Architecture:** Apply small, targeted fixes across bench timing, client/server networking, and coverage selection. Add missing guards/tests for Python kernel edge cases. Clean up documentation inconsistencies and plan typos flagged by review.

**Tech Stack:** Rust 2021 (cargo tests), Python unittest (torch), Jujutsu (`jj`) for commits.

---

## Task 1: Fix `TimingCounters::should_log` logging at count 0

**Files:**
- Modify: `tests/bench_timing_test.rs`
- Modify: `src/bench_timing.rs`

### Step 1: Write the failing test

Add to `tests/bench_timing_test.rs`:

```rust
#[test]
fn test_should_log_skips_zero_count() {
    let t = TimingCounters::new(2);
    assert!(!t.should_log("phase"));
}
```

### Step 2: Run test to verify it fails

Run: `cargo test test_should_log_skips_zero_count --test bench_timing_test`
Expected: FAIL (currently logs at count 0).

### Step 3: Write minimal implementation

Update `src/bench_timing.rs`:

```rust
let count = *self.counts.get(phase).unwrap_or(&0);
self.log_every > 0 && count > 0 && count % self.log_every == 0
```

### Step 4: Run test to verify it passes

Run: `cargo test test_should_log_skips_zero_count --test bench_timing_test`
Expected: PASS

### Step 5: Commit

```bash
jj add tests/bench_timing_test.rs src/bench_timing.rs
jj describe -m "fix: avoid logging timing at count 0"
```

---

## Task 2: Add TCP read/write timeouts in `rms24_client`

**Files:**
- Modify: `src/bin/rms24_client.rs`
- Test: `src/bin/rms24_client.rs`

### Step 1: Write the failing test

Add to `src/bin/rms24_client.rs` tests:

```rust
#[test]
fn test_connect_with_timeouts_sets_read_write() {
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = thread::spawn(move || {
        let _ = listener.accept();
    });

    let timeout = Duration::from_secs(60);
    let stream = connect_with_timeouts(&addr.to_string(), timeout).unwrap();
    assert_eq!(stream.read_timeout().unwrap(), Some(timeout));
    assert_eq!(stream.write_timeout().unwrap(), Some(timeout));

    let _ = handle.join();
}
```

### Step 2: Run test to verify it fails

Run: `cargo test test_connect_with_timeouts_sets_read_write --bin rms24_client`
Expected: FAIL (helper missing).

### Step 3: Write minimal implementation

Add helper + default timeout in `src/bin/rms24_client.rs`:

```rust
const DEFAULT_TCP_TIMEOUT_SECS: u64 = 60;

fn connect_with_timeouts(addr: &str, timeout: Duration) -> io::Result<TcpStream> {
    let stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}
```

Use it in `main`:

```rust
let timeout = Duration::from_secs(DEFAULT_TCP_TIMEOUT_SECS);
let mut stream = connect_with_timeouts(&args.server, timeout)?;
```

### Step 4: Run test to verify it passes

Run: `cargo test test_connect_with_timeouts_sets_read_write --bin rms24_client`
Expected: PASS

### Step 5: Commit

```bash
jj add src/bin/rms24_client.rs
jj describe -m "fix: set tcp read/write timeouts in client"
```

---

## Task 3: Replace `unwrap()` on server deserialization with proper errors

**Files:**
- Modify: `src/bin/rms24_server.rs`
- Test: `src/bin/rms24_server.rs`

### Step 1: Write the failing tests

Add to `src/bin/rms24_server.rs` tests:

```rust
#[test]
fn test_parse_run_config_invalid_bytes() {
    let err = parse_run_config(&[0xAA, 0xBB]).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn test_parse_client_frame_invalid_bytes() {
    let err = parse_client_frame(&[0xCC, 0xDD]).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}
```

### Step 2: Run test to verify it fails

Run: `cargo test test_parse_run_config_invalid_bytes --bin rms24_server`
Expected: FAIL (helpers missing).

### Step 3: Write minimal implementation

Add helpers in `src/bin/rms24_server.rs`:

```rust
fn parse_run_config(bytes: &[u8]) -> io::Result<RunConfig> {
    bincode::deserialize(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn parse_client_frame(bytes: &[u8]) -> io::Result<ClientFrame> {
    bincode::deserialize(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}
```

Use them in `handle_client`:

```rust
let cfg: RunConfig = parse_run_config(&cfg_bytes)?;
...
let frame: ClientFrame = parse_client_frame(&msg)?;
```

### Step 4: Run test to verify it passes

Run: `cargo test test_parse_run_config_invalid_bytes --bin rms24_server`
Expected: PASS

### Step 5: Commit

```bash
jj add src/bin/rms24_server.rs
jj describe -m "fix: handle server deserialize errors without panic"
```

---

## Task 4: Filter coverage candidates to available hints

**Files:**
- Modify: `src/client.rs`
- Test: `src/client.rs`

### Step 1: Write the failing test

Add to `client::tests` in `src/client.rs`:

```rust
#[test]
fn test_network_queries_with_coverage_filters_unavailable_hints() {
    let params = Params::new(64, 4, 4);
    let prf = Prf::random();
    let mut client = OnlineClient::new(params.clone(), prf, 1);
    let db = vec![7u8; (params.num_entries as usize) * params.entry_size];
    client.generate_hints(&db).unwrap();
    let coverage = client.build_coverage_index();

    let mut target = None;
    for index in 0..params.num_entries {
        let block = params.block_of(index) as u32;
        let offset = params.offset_in_block(index) as u32;
        let covering: Vec<usize> = client
            .available_hints
            .iter()
            .copied()
            .filter(|&hint| client.hint_covers(hint, block, offset))
            .collect();
        if covering.len() >= 2 {
            target = Some((index, covering));
            break;
        }
    }
    let (index, covering) = target.expect("expected index with >=2 covering hints");

    let removed_hint = covering[0];
    if let Some(pos) = client.available_hints.iter().position(|&h| h == removed_hint) {
        client.available_hints.swap_remove(pos);
    }

    let mut coverage_override = coverage.clone();
    coverage_override[index as usize] = vec![removed_hint as u32];

    let (_real_query, _dummy_query, real_hint) =
        client.build_network_queries_with_coverage(index, &coverage_override).unwrap();

    assert_ne!(real_hint, removed_hint);
    assert!(client.available_hints.contains(&real_hint));
}
```

### Step 2: Run test to verify it fails

Run: `cargo test test_network_queries_with_coverage_filters_unavailable_hints --lib`
Expected: FAIL (can select removed hint).

### Step 3: Write minimal implementation

Update `build_network_queries_with_coverage` in `src/client.rs`:

```rust
let mut candidates: Vec<usize> = coverage[index as usize]
    .iter()
    .copied()
    .map(|id| id as usize)
    .filter(|hint_id| self.available_hints.contains(hint_id))
    .collect();

if candidates.is_empty() {
    return self.build_network_queries(index);
}
```

### Step 4: Run test to verify it passes

Run: `cargo test test_network_queries_with_coverage_filters_unavailable_hints --lib`
Expected: PASS

### Step 5: Commit

```bash
jj add src/client.rs
jj describe -m "fix: avoid selecting unavailable hints from coverage index"
```

---

## Task 5: Serialize env-var test in `rms24_client` tests

**Files:**
- Modify: `src/bin/rms24_client.rs`

### Step 1: Update test guard

Add a shared mutex guard (using `OnceLock`) and lock it in `test_coverage_env_enables_index` so env var usage can’t race with other tests.

### Step 2: Run targeted test

Run: `cargo test test_coverage_env_enables_index --bin rms24_client`
Expected: PASS

### Step 3: Commit

```bash
jj add src/bin/rms24_client.rs
jj describe -m "test: guard RMS24_COVERAGE_INDEX env var"
```

---

## Task 6: Guard `forge_v2` for zero subset size (S=0)

**Files:**
- Modify: `python/test_kernel_correctness.py`
- Modify: `python/forge_v2.py`

### Step 1: Write the failing test

Add to `python/test_kernel_correctness.py`:

```python
@unittest.skipUnless(KERNEL_MODULE == "forge_v2", "forge_v2 only")
def test_zero_subset_size_returns_zero(self):
    entries = torch.randint(1, 100, (10, 5), dtype=torch.int64)
    indices = torch.zeros(3, 0, dtype=torch.int64)
    mask = torch.zeros(3, 0, dtype=torch.bool)

    parities = self.kernel(entries, indices, mask)

    expected = torch.zeros(3, 5, dtype=torch.int64)
    self.assertTrue(torch.equal(parities, expected))
```

### Step 2: Run test to verify it fails

Run: `KERNEL_MODULE=forge_v2 python -m unittest python.test_kernel_correctness.TestHintGenKernelCorrectness.test_zero_subset_size_returns_zero`
Expected: FAIL (indexing gathered[:,0,:] panics).

### Step 3: Write minimal implementation

Update `python/forge_v2.py`:

```python
if gathered.shape[1] == 0:
    return torch.zeros(gathered.shape[0], gathered.shape[2], dtype=entries.dtype, device=entries.device)
```

### Step 4: Run test to verify it passes

Run: `KERNEL_MODULE=forge_v2 python -m unittest python.test_kernel_correctness.TestHintGenKernelCorrectness.test_zero_subset_size_returns_zero`
Expected: PASS

### Step 5: Commit

```bash
jj add python/test_kernel_correctness.py python/forge_v2.py
jj describe -m "fix: handle zero subset size in forge_v2"
```

---

## Task 7: Fix documentation inconsistencies and plan typos

**Files:**
- Modify: `docs/reports/2026-02-01-rms24-keywordpir-full-benchmark.md`
- Modify: `docs/plans/2026-02-01-rms24-runtime-instrumentation-implementation.md`
- Modify: `docs/plans/2026-01-31-coverage-index-implementation.md`
- Modify: `docs/plans/2026-02-01-rms24-client-query-optimizations-implementation.md`
- Modify: `docs/plans/2026-02-02-rms24-keywordpir-implementation.md`

### Step 1: Update benchmark report thread counts

Make summary/method match the tables (RMS24: 1 & 4 threads; KeywordPIR: 1 & 64 threads).

### Step 2: Fix incorrect cargo test commands in runtime instrumentation plan

Replace `cargo test tests/bench_timing_test.rs::test_timing_summary_format` with:
- `cargo test test_timing_summary_format --test bench_timing_test`

Apply the same pattern to other test commands in that plan.

### Step 3: Fix tautological assertion in coverage index plan

Change:

```rust
assert_eq!(real_query.id, real_query.id);
```

to:

```rust
assert_eq!(real_query.id, dummy_query.id);
```

### Step 4: Clarify cached-vs-uncached test in client query plan

Update `test_query_bytes_equivalent_with_cache` to explicitly warm the cache (call `get_subset_for_hint` before `build_network_queries`) so the cached path is exercised.

### Step 5: Fix KeywordPIR plan correctness

- `find_candidate` should verify key/tag match before returning a candidate.
- Kick loop should handle empty slots without `unwrap()` panics (insert and return if empty).

### Step 6: Commit

```bash
jj add docs/reports/2026-02-01-rms24-keywordpir-full-benchmark.md \
  docs/plans/2026-02-01-rms24-runtime-instrumentation-implementation.md \
  docs/plans/2026-01-31-coverage-index-implementation.md \
  docs/plans/2026-02-01-rms24-client-query-optimizations-implementation.md \
  docs/plans/2026-02-02-rms24-keywordpir-implementation.md
jj describe -m "docs: fix report inconsistencies and plan issues"
```

---

## Task 8: Final verification + rollup commit (if you want a single commit)

### Step 1: Run full test pass

Run: `cargo test`
Expected: PASS

### Step 2: Commit (optional rollup instead of task commits)

```bash
jj add -A
jj describe -m "fix: address CodeRabbit findings"
```
