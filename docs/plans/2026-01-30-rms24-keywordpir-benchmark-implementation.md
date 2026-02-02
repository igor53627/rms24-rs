# RMS24 + KeywordPIR Benchmark Harness Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add raw‑TCP client/server binaries, a benchmark harness script, and logging/report tooling to produce a full RMS24 + KeywordPIR performance report on hsiao.

**Architecture:** Two binaries (`rms24-server`, `rms24-client`) communicate over localhost using length‑prefixed `bincode` frames. A shell script orchestrates dataset download, build, server/client runs, and report generation. JSONL logs record component‑level timings with a shared `run_id`.

**Tech Stack:** Rust 2021, `serde`, `bincode`, `clap`, standard TCP (`std::net`), shell scripting.

---

## Task 1: Add benchmark protocol types

### Files
- Create: `src/bench_proto.rs`
- Modify: `src/lib.rs`
- Test: `src/bench_proto.rs`

### Step 1: Write the failing test

Add to `src/bench_proto.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bincode_roundtrip() {
        let cfg = RunConfig {
            dataset_id: "slice-1m".to_string(),
            mode: Mode::Rms24,
            query_count: 1000,
            threads: 1,
            seed: 42,
        };
        let bytes = bincode::serialize(&cfg).unwrap();
        let decoded: RunConfig = bincode::deserialize(&bytes).unwrap();
        assert_eq!(cfg, decoded);
    }
}
```

### Step 2: Run test to verify it fails

Run: `cargo test bench_proto::tests::test_bincode_roundtrip`
Expected: FAIL (missing types/module)

### Step 3: Write minimal implementation

Create `src/bench_proto.rs`:
```rust
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Mode {
    Rms24,
    KeywordPir,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunConfig {
    pub dataset_id: String,
    pub mode: Mode,
    pub query_count: u64,
    pub threads: u32,
    pub seed: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Query {
    pub id: u64,
    pub index: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reply {
    pub id: u64,
    pub parity: Vec<u8>,
}
```

Update `src/lib.rs` exports:
```rust
pub mod bench_proto;
```

### Step 4: Run test to verify it passes

Run: `cargo test bench_proto::tests::test_bincode_roundtrip`
Expected: PASS

### Step 5: Commit
```bash
git add src/bench_proto.rs src/lib.rs
jj describe -m "feat: add benchmark protocol types"
```

---

## Task 2: Add TCP framing helpers

### Files
- Create: `src/bench_framing.rs`
- Modify: `src/lib.rs`
- Test: `src/bench_framing.rs`

### Step 1: Write the failing test

Add to `src/bench_framing.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let payload = vec![1u8, 2, 3, 4];
        let mut buf = Vec::new();
        write_frame(&mut buf, &payload).unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let out = read_frame(&mut cursor).unwrap();
        assert_eq!(out, payload);
    }
}
```

### Step 2: Run test to verify it fails

Run: `cargo test bench_framing::tests::test_frame_roundtrip`
Expected: FAIL

### Step 3: Implement framing

Create `src/bench_framing.rs`:
```rust
use std::io::{self, Read, Write};

pub fn write_frame<W: Write>(mut w: W, payload: &[u8]) -> io::Result<()> {
    let len = payload.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(payload)
}

pub fn read_frame<R: Read>(mut r: R) -> io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(payload)
}
```

Export in `src/lib.rs`:
```rust
pub mod bench_framing;
```

### Step 4: Run test to verify it passes

Run: `cargo test bench_framing::tests::test_frame_roundtrip`
Expected: PASS

### Step 5: Commit
```bash
git add src/bench_framing.rs src/lib.rs
jj describe -m "feat: add benchmark tcp framing"
```

---

## Task 3: Add rms24-server binary

### Files
- Create: `src/bin/rms24_server.rs`
- Test: `src/bin/rms24_server.rs`

### Step 1: Write the failing test

Add to `src/bin/rms24_server.rs` (test module at bottom):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_args() {
        let args = Args::parse_from([
            "rms24-server",
            "--db", "db.bin",
            "--entry-size", "40",
            "--lambda", "80",
            "--listen", "127.0.0.1:4000",
        ]);
        assert_eq!(args.entry_size, 40);
        assert_eq!(args.lambda, 80);
    }
}
```

### Step 2: Run test to verify it fails

Run: `cargo test rms24_server::tests::test_parse_args`
Expected: FAIL

### Step 3: Implement server

Create `src/bin/rms24_server.rs`:
```rust
use clap::Parser;
use rms24::bench_framing::{read_frame, write_frame};
use rms24::bench_proto::{Query, Reply, RunConfig};
use rms24::server::{InMemoryDb, Server};
use std::net::{TcpListener, TcpStream};
use std::io;
use std::thread;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    db: String,
    #[arg(long, default_value = "40")]
    entry_size: usize,
    #[arg(long, default_value = "80")]
    lambda: u32,
    #[arg(long, default_value = "127.0.0.1:4000")]
    listen: String,
}

fn handle_client(mut stream: TcpStream, server: &Server) -> io::Result<()> {
    // First message: RunConfig (ignored for now)
    let cfg_bytes = read_frame(&mut stream)?;
    let _cfg: RunConfig = bincode::deserialize(&cfg_bytes)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    loop {
        let msg = read_frame(&mut stream)?;
        let query: Query = bincode::deserialize(&msg)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let parity = server.answer(query.index)?;
        let reply = Reply { id: query.id, parity };
        let out = bincode::serialize(&reply)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        write_frame(&mut stream, &out)?;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let db = std::fs::read(&args.db)?;
    let db = InMemoryDb::new(db, args.entry_size)?;
    let server = Server::new(db, args.lambda)?;

    let listener = TcpListener::bind(&args.listen)?;
    for stream in listener.incoming() {
        let server = server.clone();
        thread::spawn(move || {
            if let Ok(stream) = stream {
                let _ = handle_client(stream, &server);
            }
        });
    }
    Ok(())
}
```

### Step 4: Run test to verify it passes

Run: `cargo test rms24_server::tests::test_parse_args`
Expected: PASS

### Step 5: Commit
```bash
git add src/bin/rms24_server.rs
jj describe -m "feat: add rms24 benchmark server"
```

---

## Task 4: Add rms24-client binary

### Files
- Create: `src/bin/rms24_client.rs`
- Test: `src/bin/rms24_client.rs`

### Step 1: Write the failing test

Add to `src/bin/rms24_client.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_args() {
        let args = Args::parse_from([
            "rms24-client",
            "--db", "db.bin",
            "--entry-size", "40",
            "--lambda", "80",
            "--server", "127.0.0.1:4000",
            "--query-count", "1000",
        ]);
        assert_eq!(args.query_count, 1000);
    }
}
```

### Step 2: Run test to verify it fails

Run: `cargo test rms24_client::tests::test_parse_args`
Expected: FAIL

### Step 3: Implement client

Create `src/bin/rms24_client.rs`:
```rust
use clap::Parser;
use rms24::bench_framing::{read_frame, write_frame};
use rms24::bench_proto::{Mode, Query, Reply, RunConfig};
use rms24::client::Client;
use rms24::params::Params;
use rms24::prf::Prf;
use std::net::TcpStream;
use std::time::Instant;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    db: String,
    #[arg(long, default_value = "40")]
    entry_size: usize,
    #[arg(long, default_value = "80")]
    lambda: u32,
    #[arg(long, default_value = "127.0.0.1:4000")]
    server: String,
    #[arg(long, default_value = "1000")]
    query_count: u64,
    #[arg(long, default_value = "1")]
    threads: u32,
    #[arg(long, default_value = "0")]
    seed: u64,
    #[arg(long, default_value = "rms24")]
    mode: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let db = std::fs::read(&args.db)?;
    let num_entries = db.len() / args.entry_size;
    let params = Params::new(num_entries as u64, args.entry_size, args.lambda);
    let prf = if args.seed == 0 { Prf::random() } else { Prf::from_seed(args.seed) };

    let mut client = Client::with_prf(params.clone(), prf.clone());
    client.generate_hints(&db);

    let mode = match args.mode.as_str() {
        "keywordpir" => Mode::KeywordPir,
        _ => Mode::Rms24,
    };

    let cfg = RunConfig {
        dataset_id: "unknown".to_string(),
        mode,
        query_count: args.query_count,
        threads: args.threads,
        seed: args.seed,
    };

    let mut stream = TcpStream::connect(&args.server)?;
    let cfg_bytes = bincode::serialize(&cfg)?;
    write_frame(&mut stream, &cfg_bytes)?;

    let start = Instant::now();
    for i in 0..args.query_count {
        let idx = (i % num_entries as u64) as u64;
        let q = Query { id: i, index: idx };
        let bytes = bincode::serialize(&q)?;
        write_frame(&mut stream, &bytes)?;
        let reply_bytes = read_frame(&mut stream)?;
        let _reply: Reply = bincode::deserialize(&reply_bytes)?;
    }
    let elapsed = start.elapsed();
    println!("elapsed_ms={}", elapsed.as_millis());
    Ok(())
}
```

### Step 4: Run test to verify it passes

Run: `cargo test rms24_client::tests::test_parse_args`
Expected: PASS

### Step 5: Commit
```bash
git add src/bin/rms24_client.rs
jj describe -m "feat: add rms24 benchmark client"
```

---

## Task 5: Add benchmark harness script

### Files
- Create: `scripts/bench_hsiao.sh`

### Step 1: Write script skeleton

Create `scripts/bench_hsiao.sh` with:
```bash
#!/usr/bin/env bash
set -euo pipefail

DATA_ROOT=${DATA_ROOT:-/data/rms24}
RUN_ID=${RUN_ID:-"$(date +%Y%m%d_%H%M%S)_$(git rev-parse --short HEAD)"}
RUN_DIR="$DATA_ROOT/runs/$RUN_ID"

mkdir -p "$RUN_DIR"

echo "run_id=$RUN_ID" | tee "$RUN_DIR/env.txt"
# TODO: add env capture, dataset download, server/client runs
```

### Step 2: Commit skeleton
```bash
git add scripts/bench_hsiao.sh
jj describe -m "feat: add benchmark harness script skeleton"
```

---

## Task 6: Fill harness steps (download, run, report)

### Files
- Modify: `scripts/bench_hsiao.sh`

### Step 1: Add download + checksum steps
- Use URLs from `plinko-rs/docs/data_format.md`
- Write SHA256s to `$RUN_DIR`

### Step 2: Add server start/stop
- Start `rms24-server` in background, save PID
- Trap to kill server on exit

### Step 3: Add client runs
- Run 1k/10k queries, threads 1 and 4
- Save JSONL logs to `$RUN_DIR`

### Step 4: Add summary CSV + report.md
- Parse JSONL with `python` or `jq`

### Step 5: Commit
```bash
git add scripts/bench_hsiao.sh
jj describe -m "feat: add benchmark harness steps"
```

---

Plan complete and saved to `docs/plans/2026-01-30-rms24-keywordpir-benchmark-implementation.md`. Two execution options:

1. **Subagent-Driven (this session)** — I dispatch a fresh subagent per task, review between tasks.
2. **Parallel Session (separate)** — Open a new session with executing-plans and run tasks in batches.

Which approach?
