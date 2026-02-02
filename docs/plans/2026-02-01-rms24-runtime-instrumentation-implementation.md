# RMS24 Runtime Instrumentation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add optional timing instrumentation to rms24 client and server to attribute runtime to phases without changing protocol behavior.

**Architecture:** Introduce a small timing helper with phase counters and summary formatting. Wire it into `rms24_client` and `rms24_server` behind CLI flags so instrumentation is off by default. Emit periodic and final timing summaries.

**Tech Stack:** Rust, clap, std::time::Instant, existing binaries in `src/bin/`.

### Task 1: Add timing helper module

**Files:**
- Create: `src/bench_timing.rs`
- Modify: `src/lib.rs`
- Test: `tests/bench_timing_test.rs`

**Step 1: Write the failing test**

```rust
use rms24::bench_timing::TimingCounters;

#[test]
fn test_timing_summary_format() {
    let mut t = TimingCounters::new(2);
    t.add("serialize", 1500);
    t.add("serialize", 500);
    let line = t.summary_line("serialize");
    assert!(line.contains("phase=serialize"));
    assert!(line.contains("count=2"));
    assert!(line.contains("total_us=2000"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test tests/bench_timing_test.rs::test_timing_summary_format`
Expected: FAIL (module or type not found)

**Step 3: Write minimal implementation**

```rust
// src/bench_timing.rs
use std::collections::HashMap;

#[derive(Default)]
pub struct TimingCounters {
    counts: HashMap<String, u64>,
    totals_us: HashMap<String, u64>,
    log_every: u64,
}

impl TimingCounters {
    pub fn new(log_every: u64) -> Self {
        Self { counts: HashMap::new(), totals_us: HashMap::new(), log_every }
    }

    pub fn add(&mut self, phase: &str, micros: u64) {
        *self.counts.entry(phase.to_string()).or_insert(0) += 1;
        *self.totals_us.entry(phase.to_string()).or_insert(0) += micros;
    }

    pub fn summary_line(&self, phase: &str) -> String {
        let count = *self.counts.get(phase).unwrap_or(&0);
        let total = *self.totals_us.get(phase).unwrap_or(&0);
        let avg = if count == 0 { 0 } else { total / count };
        format!("timing phase={} count={} total_us={} avg_us={}", phase, count, total, avg)
    }

    pub fn should_log(&self, phase: &str) -> bool {
        let count = *self.counts.get(phase).unwrap_or(&0);
        self.log_every > 0 && count % self.log_every == 0
    }
}
```

Add module export in `src/lib.rs`:
```rust
pub mod bench_timing;
```

**Step 4: Run test to verify it passes**

Run: `cargo test tests/bench_timing_test.rs::test_timing_summary_format`
Expected: PASS

**Step 5: Commit**

```bash
jj add src/bench_timing.rs src/lib.rs tests/bench_timing_test.rs
jj commit -m "feat: add timing helper for benchmarks"
```

### Task 2: Client timing flags and instrumentation

**Files:**
- Modify: `src/bin/rms24_client.rs`
- Test: `src/bin/rms24_client.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_parse_args_timing_flags() {
    let args = Args::parse_from([
        "rms24-client",
        "--db",
        "db.bin",
        "--timing",
        "--timing-every",
        "25",
    ]);
    assert!(args.timing);
    assert_eq!(args.timing_every, 25);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test src/bin/rms24_client.rs::tests::test_parse_args_timing_flags`
Expected: FAIL (flags missing)

**Step 3: Write minimal implementation**

- Add CLI flags to `Args`:
```rust
    #[arg(long)]
    timing: bool,
    #[arg(long, default_value = "1000")]
    timing_every: u64,
```

- Add optional timing counters and phase measurements around:
  - query build
  - serialize
  - write_frame
  - read_frame
  - deserialize
  - decode/replenish

- Emit summary lines when `timing` enabled and `should_log()` is true.

**Step 4: Run test to verify it passes**

Run: `cargo test src/bin/rms24_client.rs::tests::test_parse_args_timing_flags`
Expected: PASS

**Step 5: Commit**

```bash
jj add src/bin/rms24_client.rs
jj commit -m "feat: add timing flags to rms24 client"
```

### Task 3: Server timing flags and instrumentation

**Files:**
- Modify: `src/bin/rms24_server.rs`
- Test: `src/bin/rms24_server.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_parse_args_timing_flags() {
    let args = Args::parse_from([
        "rms24-server",
        "--db",
        "db.bin",
        "--timing",
        "--timing-every",
        "25",
    ]);
    assert!(args.timing);
    assert_eq!(args.timing_every, 25);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test src/bin/rms24_server.rs::tests::test_parse_args_timing_flags`
Expected: FAIL (flags missing)

**Step 3: Write minimal implementation**

- Add CLI flags to `Args`:
```rust
    #[arg(long)]
    timing: bool,
    #[arg(long, default_value = "1000")]
    timing_every: u64,
```

- Add timing counters to `handle_client` around:
  - read_frame
  - deserialize
  - server.answer
  - serialize
  - write_frame

- Emit summary lines when `timing` enabled and `should_log()` is true.

**Step 4: Run test to verify it passes**

Run: `cargo test src/bin/rms24_server.rs::tests::test_parse_args_timing_flags`
Expected: PASS

**Step 5: Commit**

```bash
jj add src/bin/rms24_server.rs
jj commit -m "feat: add timing flags to rms24 server"
```

### Task 4: Wire timing helper in client/server

**Files:**
- Modify: `src/bin/rms24_client.rs`
- Modify: `src/bin/rms24_server.rs`

**Step 1: Write a failing test**

```rust
#[test]
fn test_timing_helper_smoke() {
    let mut t = rms24::bench_timing::TimingCounters::new(1);
    t.add("read", 10);
    assert!(t.summary_line("read").contains("count=1"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test tests/bench_timing_test.rs::test_timing_helper_smoke`
Expected: FAIL

**Step 3: Write minimal implementation**

- Use `TimingCounters` in client/server.
- Add a final summary print when the loop exits.

**Step 4: Run test to verify it passes**

Run: `cargo test tests/bench_timing_test.rs::test_timing_helper_smoke`
Expected: PASS

**Step 5: Commit**

```bash
jj add src/bin/rms24_client.rs src/bin/rms24_server.rs
jj commit -m "feat: wire timing counters into client and server"
```

### Task 5: Docs for flags

**Files:**
- Modify: `docs/FEATURE_FLAGS.md`

**Step 1: Update docs**

Add flags:
- `--timing` and `--timing-every` for `rms24_client`
- `--timing` and `--timing-every` for `rms24_server`

**Step 2: Commit**

```bash
jj add docs/FEATURE_FLAGS.md
jj commit -m "docs: document timing flags"
```

## Verification

- `cargo test tests/bench_timing_test.rs::test_timing_summary_format`
- `cargo test src/bin/rms24_client.rs::tests::test_parse_args_timing_flags`
- `cargo test src/bin/rms24_server.rs::tests::test_parse_args_timing_flags`

## Execution

Plan complete and saved to `docs/plans/2026-02-01-rms24-runtime-instrumentation-implementation.md`.

Two execution options:
1. Subagent-Driven (this session)
2. Parallel Session (separate)

Which approach?
