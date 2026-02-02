# RMS24 Online Batching Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add batched query frames to the benchmark online protocol and wire them into the client/server binaries with a count-based cap and per-query error handling.

**Architecture:** Extend `bench_proto` with batch frames and a reply enum, add a small handler module that maps client frames to server frames (including batch size enforcement), and update the TCP client/server binaries to send/receive batches with `--batch-size` / `--max-batch-queries` flags. Keep the single-query path as default.

**Tech Stack:** Rust 2021, `serde`, `bincode`, `clap`, raw TCP framing.

---

### Task 1: Extend bench protocol types for batching

**Files:**
- Modify: `src/bench_proto.rs`
- Test: `src/bench_proto.rs`

**Step 1: Write the failing tests**

Add to `src/bench_proto.rs` test module:

```rust
#[test]
fn test_batch_request_roundtrip() {
    let batch = BatchRequest {
        queries: vec![Query { id: 1, subset: vec![(0, 0)] }],
    };
    let frame = ClientFrame::BatchRequest(batch);
    let bytes = bincode::serialize(&frame).unwrap();
    let decoded: ClientFrame = bincode::deserialize(&bytes).unwrap();
    assert_eq!(frame, decoded);
}

#[test]
fn test_batch_reply_roundtrip() {
    let batch = BatchReply {
        replies: vec![Reply::Ok { id: 2, parity: vec![9, 9] }],
    };
    let frame = ServerFrame::BatchReply(batch);
    let bytes = bincode::serialize(&frame).unwrap();
    let decoded: ServerFrame = bincode::deserialize(&bytes).unwrap();
    assert_eq!(frame, decoded);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test bench_proto::tests::test_batch_request_roundtrip`
Expected: FAIL (missing types `BatchRequest`/`ClientFrame`).

**Step 3: Implement batch types + frame enums**

Update `src/bench_proto.rs`:

```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunConfig {
    pub dataset_id: String,
    pub mode: Mode,
    pub query_count: u64,
    pub threads: usize,
    pub seed: u64,
    pub batch_size: usize,
    pub max_batch_queries: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchRequest {
    pub queries: Vec<Query>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchReply {
    pub replies: Vec<Reply>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientFrame {
    Query(Query),
    BatchRequest(BatchRequest),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServerFrame {
    Reply(Reply),
    BatchReply(BatchReply),
    Error { message: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Reply {
    Ok { id: u64, parity: Vec<u8> },
    Error { id: u64, message: String },
}
```

Update existing tests in `src/bench_proto.rs` to use `Reply::Ok` and set `batch_size`/`max_batch_queries` in `RunConfig` roundtrip tests.

**Step 4: Run tests to verify they pass**

Run: `cargo test bench_proto::tests::test_batch_request_roundtrip`
Expected: PASS

**Step 5: Commit**

```bash
jj add src/bench_proto.rs
jj describe -m "feat: add batch frames to bench protocol"
```

---

### Task 2: Add a bench handler for batched frames

**Files:**
- Create: `src/bench_handler.rs`
- Modify: `src/lib.rs`
- Test: `src/bench_handler.rs`

**Step 1: Write the failing tests**

Create `src/bench_handler.rs` with tests first:

```rust
use crate::bench_proto::{BatchReply, BatchRequest, ClientFrame, Query, Reply, ServerFrame};
use crate::messages::Query as RmsQuery;
use crate::server::{Db, Server};

pub fn handle_client_frame<D: Db>(
    server: &Server<D>,
    frame: ClientFrame,
    max_batch: usize,
) -> ServerFrame {
    match frame {
        ClientFrame::Query(query) => handle_single(server, query),
        ClientFrame::BatchRequest(batch) => handle_batch(server, batch, max_batch),
    }
}

fn handle_single<D: Db>(server: &Server<D>, query: Query) -> ServerFrame {
    let rms_query = RmsQuery { id: query.id, subset: query.subset };
    match server.answer(&rms_query) {
        Ok(reply) => ServerFrame::Reply(Reply::Ok { id: reply.id, parity: reply.parity }),
        Err(err) => ServerFrame::Reply(Reply::Error { id: rms_query.id, message: err.to_string() }),
    }
}

fn handle_batch<D: Db>(server: &Server<D>, batch: BatchRequest, max_batch: usize) -> ServerFrame {
    if batch.queries.len() > max_batch {
        return ServerFrame::Error { message: format!("batch too large: {}", batch.queries.len()) };
    }
    let mut replies = Vec::with_capacity(batch.queries.len());
    for query in batch.queries {
        let rms_query = RmsQuery { id: query.id, subset: query.subset };
        let reply = match server.answer(&rms_query) {
            Ok(reply) => Reply::Ok { id: reply.id, parity: reply.parity },
            Err(err) => Reply::Error { id: rms_query.id, message: err.to_string() },
        };
        replies.push(reply);
    }
    ServerFrame::BatchReply(BatchReply { replies })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::InMemoryDb;

    #[test]
    fn test_batch_reply_order_and_error() {
        let db = InMemoryDb::new(vec![1, 2, 3, 4], 1).unwrap();
        let server = Server::new(db, 2).unwrap();

        let ok = Query { id: 1, subset: vec![(0, 0)] };
        let bad = Query { id: 2, subset: vec![(9, 0)] };
        let frame = ClientFrame::BatchRequest(BatchRequest { queries: vec![ok.clone(), bad.clone()] });
        let out = handle_client_frame(&server, frame, 8);

        match out {
            ServerFrame::BatchReply(batch) => {
                assert_eq!(batch.replies.len(), 2);
                match &batch.replies[0] {
                    Reply::Ok { id, parity } => {
                        assert_eq!(*id, ok.id);
                        assert_eq!(parity, &vec![1]);
                    }
                    _ => panic!("expected ok reply"),
                }
                match &batch.replies[1] {
                    Reply::Error { id, message } => {
                        assert_eq!(*id, bad.id);
                        assert!(message.contains("subset"));
                    }
                    _ => panic!("expected error reply"),
                }
            }
            _ => panic!("expected batch reply"),
        }
    }

    #[test]
    fn test_batch_size_enforced() {
        let db = InMemoryDb::new(vec![1, 2, 3, 4], 1).unwrap();
        let server = Server::new(db, 2).unwrap();
        let frame = ClientFrame::BatchRequest(BatchRequest {
            queries: vec![
                Query { id: 1, subset: vec![(0, 0)] },
                Query { id: 2, subset: vec![(0, 1)] },
            ],
        });
        let out = handle_client_frame(&server, frame, 1);
        match out {
            ServerFrame::Error { message } => assert!(message.contains("batch too large")),
            _ => panic!("expected error frame"),
        }
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test bench_handler::tests::test_batch_reply_order_and_error`
Expected: FAIL (missing module/export/types).

**Step 3: Implement module + export**

- Keep the implementation above in `src/bench_handler.rs`.
- Update `src/lib.rs`:

```rust
pub mod bench_handler;
```

**Step 4: Run tests to verify they pass**

Run: `cargo test bench_handler::tests::test_batch_reply_order_and_error`
Expected: PASS

**Step 5: Commit**

```bash
jj add src/bench_handler.rs src/lib.rs
jj describe -m "feat: add bench frame handler for batching"
```

---

### Task 3: Update server binary for batch frames

**Files:**
- Modify: `src/bin/rms24_server.rs`
- Test: `src/bin/rms24_server.rs`

**Step 1: Write the failing test**

Add to `src/bin/rms24_server.rs` tests:

```rust
#[test]
fn test_parse_args_batching() {
    let args = Args::parse_from([
        "rms24-server",
        "--db",
        "db.bin",
        "--max-batch-queries",
        "32",
    ]);
    assert_eq!(args.max_batch_queries, 32);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test rms24_server::tests::test_parse_args_batching`
Expected: FAIL (unknown arg or missing field).

**Step 3: Implement batching in server**

Update `src/bin/rms24_server.rs`:

```rust
use rms24::bench_handler::handle_client_frame;
use rms24::bench_proto::{ClientFrame, RunConfig, ServerFrame};

#[derive(Parser)]
struct Args {
    // ... existing args ...
    #[arg(long, default_value = "1")]
    max_batch_queries: usize,
}

fn handle_client(
    /* ... */,
    max_batch_queries: usize,
) -> io::Result<()> {
    let cfg_bytes = read_frame(&mut stream)?;
    let cfg: RunConfig = bincode::deserialize(&cfg_bytes).unwrap();
    let max_batch = max_batch_queries.min(cfg.max_batch_queries);

    loop {
        let msg = read_frame(&mut stream)?;
        let frame: ClientFrame = bincode::deserialize(&msg).unwrap();
        let out = handle_client_frame(&server, frame, max_batch);
        let out_bytes = bincode::serialize(&out).unwrap();
        write_frame(&mut stream, &out_bytes)?;
    }
}
```

(Adjust timing measurement to wrap `handle_client_frame` for the `answer` phase.)

**Step 4: Run tests to verify they pass**

Run: `cargo test rms24_server::tests::test_parse_args_batching`
Expected: PASS

**Step 5: Commit**

```bash
jj add src/bin/rms24_server.rs
jj describe -m "feat: add batch handling to rms24 server"
```

---

### Task 4: Update client binary for batched queries

**Files:**
- Modify: `src/bin/rms24_client.rs`
- Test: `src/bin/rms24_client.rs`

**Step 1: Write the failing test**

Add to `src/bin/rms24_client.rs` tests:

```rust
#[test]
fn test_parse_args_batch_size() {
    let args = Args::parse_from([
        "rms24-client",
        "--db",
        "db.bin",
        "--batch-size",
        "8",
    ]);
    assert_eq!(args.batch_size, 8);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test rms24_client::tests::test_parse_args_batch_size`
Expected: FAIL (unknown arg or missing field).

**Step 3: Implement batching in client**

Update `src/bin/rms24_client.rs`:

```rust
use rms24::bench_proto::{BatchRequest, ClientFrame, Query, Reply, RunConfig, ServerFrame};

#[derive(Parser)]
struct Args {
    // ... existing args ...
    #[arg(long, default_value = "1")]
    batch_size: usize,
}

struct PendingItem {
    query: Query,
    kind: PendingKind,
}

enum PendingKind {
    Real { index: u64, hint: usize },
    Dummy,
}

let cfg = RunConfig {
    dataset_id: "unknown".to_string(),
    mode,
    query_count: args.query_count,
    threads: args.threads,
    seed: args.seed,
    batch_size: args.batch_size,
    max_batch_queries: args.batch_size,
};

// Build pending items per logical query
pending.push(PendingItem { query: real, kind: PendingKind::Real { index: idx, hint: real_hint } });
pending.push(PendingItem { query: dummy, kind: PendingKind::Dummy });

fn flush_batch(
    stream: &mut TcpStream,
    pending: &mut Vec<PendingItem>,
    batch_size: usize,
    client: &mut OnlineClient,
    coverage: &Option<Vec<Vec<usize>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let take = batch_size.min(pending.len());
    let batch: Vec<PendingItem> = pending.drain(0..take).collect();
    let queries: Vec<Query> = batch.iter().map(|p| p.query.clone()).collect();
    let frame = if queries.len() == 1 {
        ClientFrame::Query(queries[0].clone())
    } else {
        ClientFrame::BatchRequest(BatchRequest { queries })
    };
    let bytes = bincode::serialize(&frame)?;
    write_frame(stream, &bytes)?;
    let reply_bytes = read_frame(stream)?;
    let reply_frame: ServerFrame = bincode::deserialize(&reply_bytes)?;

    let replies = match reply_frame {
        ServerFrame::Reply(reply) => vec![reply],
        ServerFrame::BatchReply(batch) => batch.replies,
        ServerFrame::Error { message } => return Err(message.into()),
    };

    for (item, reply) in batch.into_iter().zip(replies.into_iter()) {
        match (item.kind, reply) {
            (PendingKind::Real { index, hint }, Reply::Ok { parity, .. }) => {
                if let Some(_) = coverage {
                    let _ = client.decode_reply_static(hint, parity)?;
                } else {
                    let _ = client.consume_network_reply(index, hint, parity)?;
                }
            }
            (_, Reply::Ok { .. }) => {}
            (_, Reply::Error { message, .. }) => return Err(message.into()),
        }
    }
    Ok(())
}
```

Ensure you flush remaining pending items after the loop.

**Step 4: Run tests to verify they pass**

Run: `cargo test rms24_client::tests::test_parse_args_batch_size`
Expected: PASS

**Step 5: Commit**

```bash
jj add src/bin/rms24_client.rs
jj describe -m "feat: add batching to rms24 client"
```

---

### Task 5: Document batching flags

**Files:**
- Modify: `docs/FEATURE_FLAGS.md`

**Step 1: Update docs**

Add a small section:

```markdown
## Online batching (benchmark client/server)

- `rms24_client --batch-size N`: send up to N network queries per frame.
- `rms24_server --max-batch-queries N`: cap the number of queries in a batch.
```

**Step 2: Sanity-check the doc**

Run: `rg -n "batch" docs/FEATURE_FLAGS.md`
Expected: shows the new section.

**Step 3: Commit**

```bash
jj add docs/FEATURE_FLAGS.md
jj describe -m "docs: add batching flags"
```
