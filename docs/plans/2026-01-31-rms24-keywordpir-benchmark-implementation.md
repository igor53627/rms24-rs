# RMS24 + KeywordPIR Benchmark Harness Implementation Plan (Updated)

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add raw-TCP client/server binaries, a benchmark harness script, and logging/report tooling to produce a full RMS24 + KeywordPIR performance report on hsiao.

**Architecture:** Two binaries (`rms24-server`, `rms24-client`) communicate over localhost using length-prefixed `bincode` frames. Queries carry RMS24 subsets (not index-only). The client uses `OnlineClient` state to build real/dummy subsets and updates its hint state after replies. A shell script orchestrates dataset download, build, server/client runs, and report generation. JSONL logs record component-level timings with a shared `run_id`.

**Tech Stack:** Rust 2021, `serde`, `bincode`, `clap`, `sha3`, standard TCP (`std::net`), shell scripting.

---

## Task 0: Expose OnlineClient network query helpers

### Files
- Modify: `src/client.rs`
- Test: `src/client.rs`

### Step 1: Write the failing tests

Add to `src/client.rs` tests (near other OnlineClient tests):

```rust
#[test]
fn test_online_client_build_and_consume_network_query() {
    let params = Params::new(16, 4, 4);
    let prf = Prf::random();
    let mut client = OnlineClient::new(params.clone(), prf, 1);

    let db = vec![7u8; (params.num_entries as usize) * params.entry_size];
    client.generate_hints(&db).unwrap();

    let (real_query, dummy_query, real_hint) = client.build_network_queries(3).unwrap();
    assert_eq!(real_query.id, dummy_query.id);
    assert!(!real_query.subset.is_empty());

    // Fake reply parity of correct length
    let parity = vec![0u8; params.entry_size];
    let _ = client.consume_network_reply(3, real_hint, parity).unwrap();
}
```

### Step 2: Run test to verify it fails

Run: `cargo test client::tests::test_online_client_build_and_consume_network_query`
Expected: FAIL (missing methods)

### Step 3: Write minimal implementation

Add public methods to `OnlineClient`:

```rust
pub fn build_network_queries(
    &mut self,
    index: u64,
) -> Result<(crate::messages::Query, crate::messages::Query, usize), ClientError> {
    if index >= self.params.num_entries {
        return Err(ClientError::InvalidIndex);
    }

    let target_block = self.params.block_of(index) as u32;
    let target_offset = self.params.offset_in_block(index) as u32;

    let mut candidates = Vec::new();
    for &hint_id in &self.available_hints {
        let subset = self.build_subset_for_hint(hint_id);
        if subset
            .iter()
            .any(|(block, offset)| *block == target_block && *offset == target_offset)
        {
            candidates.push((hint_id, subset));
        }
    }

    if candidates.is_empty() {
        return Err(ClientError::NoValidHint);
    }

    let id = self.next_query_id();
    let candidate_idx = self.rng.gen_range(0..candidates.len());
    let (real_hint, mut real_subset) = candidates.swap_remove(candidate_idx);
    if let Some(pos) = real_subset
        .iter()
        .position(|(block, offset)| *block == target_block && *offset == target_offset)
    {
        real_subset.swap_remove(pos);
    }

    if self.available_hints.is_empty() {
        return Err(ClientError::NoValidHint);
    }
    let dummy_hint = self.available_hints[self.rng.gen_range(0..self.available_hints.len())];
    let dummy_subset = self.build_subset_for_hint(dummy_hint);

    let real_query = crate::messages::Query { id, subset: real_subset };
    let dummy_query = crate::messages::Query { id, subset: dummy_subset };

    Ok((real_query, dummy_query, real_hint))
}

pub fn consume_network_reply(
    &mut self,
    index: u64,
    real_hint: usize,
    mut parity: Vec<u8>,
) -> Result<Vec<u8>, ClientError> {
    if parity.len() != self.params.entry_size {
        return Err(ClientError::ParityLengthMismatch);
    }

    let hint_parity = &self.hints.parities[real_hint];
    if parity.len() != hint_parity.len() {
        return Err(ClientError::ParityLengthMismatch);
    }
    xor_bytes_inplace(&mut parity, hint_parity);

    if let Some(pos) = self.available_hints.iter().position(|&hint| hint == real_hint) {
        self.available_hints.swap_remove(pos);
    }
    self.replenish_hint(real_hint, index, &parity)?;
    self.available_hints.push(real_hint);

    Ok(parity)
}
```

### Step 4: Run test to verify it passes

Run: `cargo test client::tests::test_online_client_build_and_consume_network_query`
Expected: PASS

### Step 5: Commit

```bash
git add src/client.rs
git commit -m "feat: add online client network query helpers"
```

---

## Task 1: Add benchmark protocol types (subset-based)

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

    #[test]
    fn test_query_subset_roundtrip() {
        let query = Query { id: 7, subset: vec![(1, 2), (3, 4)] };
        let bytes = bincode::serialize(&query).unwrap();
        let decoded: Query = bincode::deserialize(&bytes).unwrap();
        assert_eq!(query, decoded);
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
    pub subset: Vec<(u32, u32)>,
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
git commit -m "feat: add benchmark protocol types"
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

    #[test]
    fn test_frame_rejects_zero_len() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        let mut cursor = std::io::Cursor::new(buf);
        let err = read_frame(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_write_frame_rejects_oversized_payload() {
        let payload = vec![0u8; MAX_FRAME_SIZE + 1];
        let mut buf = Vec::new();
        let err = write_frame(&mut buf, &payload).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
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

const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

pub fn write_frame<W: Write>(mut w: W, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload size must be > 0",
        ));
    }
    if payload.len() > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("payload size {} exceeds maximum {}", payload.len(), MAX_FRAME_SIZE),
        ));
    }
    let len = payload.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(payload)
}

pub fn read_frame<R: Read>(mut r: R) -> io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame size must be > 0",
        ));
    }
    if len > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame size {} exceeds maximum {}", len, MAX_FRAME_SIZE),
        ));
    }
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
git commit -m "feat: add benchmark tcp framing"
```

---

## Task 3: Add rms24-server binary (subset-based)

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
use rms24::messages::Query as RmsQuery;
use rms24::server::{InMemoryDb, Server};
use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
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

fn handle_client(mut stream: TcpStream, server: Arc<Server<InMemoryDb>>) -> io::Result<()> {
    let cfg_bytes = read_frame(&mut stream)?;
    let _cfg: RunConfig = bincode::deserialize(&cfg_bytes)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    loop {
        let msg = read_frame(&mut stream)?;
        let query: Query = bincode::deserialize(&msg)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let rms_query = RmsQuery { id: query.id, subset: query.subset };
        let reply = server
            .answer(&rms_query)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "query failed"))?;
        let out = Reply { id: reply.id, parity: reply.parity };
        let out_bytes = bincode::serialize(&out)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        write_frame(&mut stream, &out_bytes)?;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.entry_size == 0 {
        return Err("entry_size must be >0".into());
    }
    let db = std::fs::read(&args.db)?;
    if db.is_empty() {
        return Err("db must contain at least one entry".into());
    }
    if db.len() % args.entry_size != 0 {
        return Err("entry_size must divide db length".into());
    }
    let db = InMemoryDb::new(db, args.entry_size)?;
    let server = Server::new(db, args.lambda)?;
    let server = Arc::new(server);

    let listener = TcpListener::bind(&args.listen)?;
    for stream in listener.incoming() {
        let server = Arc::clone(&server);
        thread::spawn(move || {
            if let Ok(stream) = stream {
                let _ = handle_client(stream, server);
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
git commit -m "feat: add rms24 benchmark server"
```

---

## Task 4: Add rms24-client binary (subset-based)

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
use rms24::client::{ClientError, OnlineClient};
use rms24::params::Params;
use rms24::prf::Prf;
use sha3::{Digest, Sha3_256};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

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

fn prf_from_seed(seed: u64) -> Prf {
    let mut hasher = Sha3_256::new();
    hasher.update(seed.to_le_bytes());
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    Prf::new(key)
}

fn connect_with_timeouts(addr: &str, timeout: Duration) -> io::Result<TcpStream> {
    let mut last_err = None;
    for sock in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&sock, timeout) {
            Ok(stream) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                return Ok(stream);
            }
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "failed to resolve socket addresses")
    }))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.entry_size == 0 {
        return Err("entry_size must be >0".into());
    }
    let db = std::fs::read(&args.db)?;
    if db.is_empty() {
        return Err("db must contain at least one entry".into());
    }
    if db.len() % args.entry_size != 0 {
        return Err("entry_size must divide db length".into());
    }
    let num_entries = db.len() / args.entry_size;
    let params = Params::new(num_entries as u64, args.entry_size, args.lambda);
    let prf = if args.seed == 0 { Prf::random() } else { prf_from_seed(args.seed) };

    let mut client = OnlineClient::new(params.clone(), prf, args.seed);
    client.generate_hints(&db).map_err(|e| ClientError::from(e))?;

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

    let timeout = Duration::from_secs(10);
    let mut stream = connect_with_timeouts(&args.server, timeout)?;
    let cfg_bytes = bincode::serialize(&cfg)?;
    write_frame(&mut stream, &cfg_bytes)?;

    let start = Instant::now();
    for i in 0..args.query_count {
        let idx = (i % num_entries as u64) as u64;
        let (real_query, dummy_query, real_hint) = client.build_network_queries(idx)?;

        let real = Query { id: real_query.id, subset: real_query.subset };
        let dummy = Query { id: dummy_query.id, subset: dummy_query.subset };

        let bytes = bincode::serialize(&real)?;
        write_frame(&mut stream, &bytes)?;
        let reply_bytes = read_frame(&mut stream)?;
        let reply: Reply = bincode::deserialize(&reply_bytes)?;

        let bytes = bincode::serialize(&dummy)?;
        write_frame(&mut stream, &bytes)?;
        let _dummy_reply: Reply = bincode::deserialize(&read_frame(&mut stream)?)?;

        let _ = client.consume_network_reply(idx, real_hint, reply.parity)?;
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
git commit -m "feat: add rms24 benchmark client"
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
git commit -m "feat: add benchmark harness script skeleton"
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
git commit -m "feat: add benchmark harness steps"
```
