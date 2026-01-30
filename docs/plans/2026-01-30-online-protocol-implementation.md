# Online Protocol Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement a production online protocol core for RMS24 and KeywordPIR with shared framing/transport and a sync client/server API.

**Architecture:** Add `online` protocol types, a length-prefixed framing helper, a transport abstraction, and a sync server/client core. RMS24 requests map to `messages::Query` and reuse `Server::answer`. KeywordPIR is wired via a handler trait so it can be plugged in when its module is ready.

**Tech Stack:** Rust 2021, `serde`, `bincode`, `std::net`/`std::io`.

---

### Task 1: Add online protocol types (Mode/RunConfig/Query/Reply/Error)

**Files:**
- Create: `src/online.rs`
- Modify: `src/lib.rs`
- Test: `src/online.rs`

**Step 1: Write the failing tests**

Create `src/online.rs` with tests only:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_config_roundtrip() {
        let cfg = RunConfig { mode: Mode::Rms24, lambda: 80, entry_size: 40 };
        let bytes = bincode::serialize(&cfg).unwrap();
        let decoded: RunConfig = bincode::deserialize(&bytes).unwrap();
        assert_eq!(cfg, decoded);
    }

    #[test]
    fn test_query_roundtrip_rms24() {
        let q = Query::Rms24 { id: 7, subset: vec![(1, 2), (3, 4)] };
        let bytes = bincode::serialize(&q).unwrap();
        let decoded: Query = bincode::deserialize(&bytes).unwrap();
        assert_eq!(q, decoded);
    }

    #[test]
    fn test_query_roundtrip_keywordpir() {
        let q = Query::KeywordPir { id: 9, keyword: b"alice".to_vec() };
        let bytes = bincode::serialize(&q).unwrap();
        let decoded: Query = bincode::deserialize(&bytes).unwrap();
        assert_eq!(q, decoded);
    }

    #[test]
    fn test_reply_roundtrip_error() {
        let r = Reply::Error { code: ErrorCode::Protocol, message: "bad mode".into() };
        let bytes = bincode::serialize(&r).unwrap();
        let decoded: Reply = bincode::deserialize(&bytes).unwrap();
        assert_eq!(r, decoded);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test online::tests::test_run_config_roundtrip`
Expected: FAIL (missing `RunConfig`, `Mode`, etc.).

**Step 3: Write minimal implementation**

Implement in `src/online.rs` above the tests:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Rms24,
    KeywordPir,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunConfig {
    pub mode: Mode,
    pub lambda: u32,
    pub entry_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Query {
    Rms24 { id: u64, subset: Vec<(u32, u32)> },
    KeywordPir { id: u64, keyword: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    Rms24 { id: u64, parity: Vec<u8> },
    KeywordPir { id: u64, payload: Vec<u8> },
    Error { code: ErrorCode, message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    Decode,
    Encode,
    Protocol,
    Unsupported,
    Server,
}

#[derive(Debug, thiserror::Error)]
pub enum OnlineError {
    #[error("decode error")]
    Decode,
    #[error("encode error")]
    Encode,
    #[error("protocol mismatch")]
    Protocol,
    #[error("unsupported mode")]
    Unsupported,
    #[error("server error: {0}")]
    Server(String),
}
```

Update `src/lib.rs` to export the module:

```rust
pub mod online;
```

**Step 4: Run test to verify it passes**

Run: `cargo test online::tests::test_run_config_roundtrip`
Expected: PASS

**Step 5: Commit**

```bash
git add src/online.rs src/lib.rs
git commit -m "feat: add online protocol types"
```

---

### Task 2: Add length-prefixed framing helper for online transport

**Files:**
- Create: `src/online_framing.rs`
- Modify: `src/lib.rs`
- Test: `src/online_framing.rs`

**Step 1: Write the failing test**

Create `src/online_framing.rs` with tests only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_frame_roundtrip() {
        let mut buf = Cursor::new(Vec::new());
        write_frame(&mut buf, b"hello").unwrap();
        buf.set_position(0);
        let out = read_frame(&mut buf).unwrap();
        assert_eq!(out, b"hello");
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test online_framing::tests::test_frame_roundtrip`
Expected: FAIL (missing `read_frame`/`write_frame`).

**Step 3: Write minimal implementation**

Implement in `src/online_framing.rs` above the tests:

```rust
use std::io::{self, Read, Write};

pub fn write_frame<W: Write>(mut writer: W, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(payload)
}

pub fn read_frame<R: Read>(mut reader: R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}
```

Update `src/lib.rs` to export the module:

```rust
pub mod online_framing;
```

**Step 4: Run test to verify it passes**

Run: `cargo test online_framing::tests::test_frame_roundtrip`
Expected: PASS

**Step 5: Commit**

```bash
git add src/online_framing.rs src/lib.rs
git commit -m "feat: add online framing helpers"
```

---

### Task 3: Add transport abstraction + framed I/O implementation

**Files:**
- Create: `src/online_transport.rs`
- Modify: `src/lib.rs`
- Test: `src/online_transport.rs`

**Step 1: Write the failing test**

Create `src/online_transport.rs` with tests only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::online::{Mode, RunConfig};
    use std::io::Cursor;

    #[test]
    fn test_framed_send_recv_roundtrip() {
        let cfg = RunConfig { mode: Mode::Rms24, lambda: 80, entry_size: 40 };
        let mut io = FramedIo::new(Cursor::new(Vec::new()));
        io.send(&cfg).unwrap();
        let inner = io.into_inner().into_inner();
        let mut io = FramedIo::new(Cursor::new(inner));
        let decoded: RunConfig = io.recv().unwrap();
        assert_eq!(cfg, decoded);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test online_transport::tests::test_framed_send_recv_roundtrip`
Expected: FAIL (missing `FramedIo`, `Transport`, `send`, `recv`).

**Step 3: Write minimal implementation**

Implement in `src/online_transport.rs` above the tests:

```rust
use crate::online::{OnlineError};
use crate::online_framing::{read_frame, write_frame};
use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};

pub trait Transport {
    fn send<T: Serialize>(&mut self, value: &T) -> Result<(), OnlineError>;
    fn recv<T: DeserializeOwned>(&mut self) -> Result<T, OnlineError>;
}

pub struct FramedIo<RW> {
    inner: RW,
}

impl<RW> FramedIo<RW> {
    pub fn new(inner: RW) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> RW {
        self.inner
    }
}

impl<RW: Read + Write> Transport for FramedIo<RW> {
    fn send<T: Serialize>(&mut self, value: &T) -> Result<(), OnlineError> {
        let bytes = bincode::serialize(value).map_err(|_| OnlineError::Encode)?;
        write_frame(&mut self.inner, &bytes).map_err(|_| OnlineError::Encode)
    }

    fn recv<T: DeserializeOwned>(&mut self) -> Result<T, OnlineError> {
        let bytes = read_frame(&mut self.inner).map_err(|_| OnlineError::Decode)?;
        bincode::deserialize(&bytes).map_err(|_| OnlineError::Decode)
    }
}
```

Update `src/lib.rs` to export the module:

```rust
pub mod online_transport;
```

**Step 4: Run test to verify it passes**

Run: `cargo test online_transport::tests::test_framed_send_recv_roundtrip`
Expected: PASS

**Step 5: Commit**

```bash
git add src/online_transport.rs src/lib.rs
git commit -m "feat: add online transport abstraction"
```

---

### Task 4: Add server core with RMS24 + KeywordPIR routing

**Files:**
- Create: `src/online_server.rs`
- Modify: `src/lib.rs`
- Test: `src/online_server.rs`

**Step 1: Write the failing tests**

Create `src/online_server.rs` with tests only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::online::{Mode, Query, Reply, RunConfig};
    use crate::server::{InMemoryDb, Server};
    use std::sync::Arc;

    struct FakeKeywordPir;

    impl KeywordPirHandler for FakeKeywordPir {
        fn answer(&self, keyword: &[u8]) -> Result<Vec<u8>, OnlineError> {
            Ok(keyword.to_vec())
        }
    }

    #[test]
    fn test_handle_rms24_query() {
        let db = InMemoryDb::new(vec![1, 2, 3, 4, 5, 6, 7, 8], 4).unwrap();
        let server = Server::new(db, 2).unwrap();
        let core = ServerCore::new(server);
        let cfg = RunConfig { mode: Mode::Rms24, lambda: 2, entry_size: 4 };
        let query = Query::Rms24 { id: 1, subset: vec![(0, 0), (0, 1)] };
        let reply = core.handle_query(&cfg, query).unwrap();
        assert_eq!(reply, Reply::Rms24 { id: 1, parity: vec![1 ^ 5, 2 ^ 6, 3 ^ 7, 4 ^ 8] });
    }

    #[test]
    fn test_handle_keywordpir_query() {
        let db = InMemoryDb::new(vec![1, 2, 3, 4], 2).unwrap();
        let server = Server::new(db, 2).unwrap();
        let core = ServerCore::new(server).with_keyword_handler(Arc::new(FakeKeywordPir));
        let cfg = RunConfig { mode: Mode::KeywordPir, lambda: 2, entry_size: 2 };
        let query = Query::KeywordPir { id: 9, keyword: b"alice".to_vec() };
        let reply = core.handle_query(&cfg, query).unwrap();
        assert_eq!(reply, Reply::KeywordPir { id: 9, payload: b"alice".to_vec() });
    }

    #[test]
    fn test_handle_mismatched_mode() {
        let db = InMemoryDb::new(vec![1, 2, 3, 4], 2).unwrap();
        let server = Server::new(db, 2).unwrap();
        let core = ServerCore::new(server);
        let cfg = RunConfig { mode: Mode::Rms24, lambda: 2, entry_size: 2 };
        let query = Query::KeywordPir { id: 9, keyword: b"alice".to_vec() };
        let err = core.handle_query(&cfg, query).unwrap_err();
        assert!(matches!(err, OnlineError::Protocol));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test online_server::tests::test_handle_rms24_query`
Expected: FAIL (missing `ServerCore`, `KeywordPirHandler`, `OnlineError`, etc.).

**Step 3: Write minimal implementation**

Implement in `src/online_server.rs` above the tests:

```rust
use crate::messages::Query as RmsQuery;
use crate::online::{Mode, OnlineError, Query, Reply, RunConfig};
use crate::server::{Db, Server};
use std::sync::Arc;

pub trait KeywordPirHandler: Send + Sync {
    fn answer(&self, keyword: &[u8]) -> Result<Vec<u8>, OnlineError>;
}

pub struct ServerCore<D: Db> {
    server: Server<D>,
    keyword_handler: Option<Arc<dyn KeywordPirHandler>>,
}

impl<D: Db> ServerCore<D> {
    pub fn new(server: Server<D>) -> Self {
        Self { server, keyword_handler: None }
    }

    pub fn with_keyword_handler(mut self, handler: Arc<dyn KeywordPirHandler>) -> Self {
        self.keyword_handler = Some(handler);
        self
    }

    pub fn handle_query(&self, cfg: &RunConfig, query: Query) -> Result<Reply, OnlineError> {
        match (cfg.mode, query) {
            (Mode::Rms24, Query::Rms24 { id, subset }) => {
                let rms_query = RmsQuery { id, subset };
                let reply = self.server.answer(&rms_query).map_err(|e| OnlineError::Server(e.to_string()))?;
                Ok(Reply::Rms24 { id: reply.id, parity: reply.parity })
            }
            (Mode::KeywordPir, Query::KeywordPir { id, keyword }) => {
                let handler = self.keyword_handler.as_ref().ok_or(OnlineError::Unsupported)?;
                let payload = handler.answer(&keyword)?;
                Ok(Reply::KeywordPir { id, payload })
            }
            _ => Err(OnlineError::Protocol),
        }
    }
}
```

Update `src/lib.rs` to export the module:

```rust
pub mod online_server;
```

**Step 4: Run test to verify it passes**

Run: `cargo test online_server::tests::test_handle_rms24_query`
Expected: PASS

**Step 5: Commit**

```bash
git add src/online_server.rs src/lib.rs
git commit -m "feat: add online server core"
```

---

### Task 5: Add client core helpers for building/parsing online queries

**Files:**
- Create: `src/online_client.rs`
- Modify: `src/lib.rs`
- Test: `src/online_client.rs`

**Step 1: Write the failing tests**

Create `src/online_client.rs` with tests only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::online::{Mode, Query, Reply};

    #[test]
    fn test_build_rms24_query() {
        let client = ClientCore::new(Mode::Rms24);
        let q = client.build_rms24_query(7, vec![(0, 1)]).unwrap();
        assert_eq!(q, Query::Rms24 { id: 7, subset: vec![(0, 1)] });
    }

    #[test]
    fn test_build_keywordpir_query() {
        let client = ClientCore::new(Mode::KeywordPir);
        let q = client.build_keywordpir_query(9, b"alice".to_vec()).unwrap();
        assert_eq!(q, Query::KeywordPir { id: 9, keyword: b"alice".to_vec() });
    }

    #[test]
    fn test_parse_rms24_reply() {
        let client = ClientCore::new(Mode::Rms24);
        let reply = Reply::Rms24 { id: 1, parity: vec![1, 2] };
        let parity = client.expect_rms24_reply(reply).unwrap();
        assert_eq!(parity, vec![1, 2]);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test online_client::tests::test_build_rms24_query`
Expected: FAIL (missing `ClientCore`).

**Step 3: Write minimal implementation**

Implement in `src/online_client.rs` above the tests:

```rust
use crate::online::{Mode, OnlineError, Query, Reply};

pub struct ClientCore {
    mode: Mode,
}

impl ClientCore {
    pub fn new(mode: Mode) -> Self {
        Self { mode }
    }

    pub fn build_rms24_query(&self, id: u64, subset: Vec<(u32, u32)>) -> Result<Query, OnlineError> {
        if self.mode != Mode::Rms24 {
            return Err(OnlineError::Protocol);
        }
        Ok(Query::Rms24 { id, subset })
    }

    pub fn build_keywordpir_query(&self, id: u64, keyword: Vec<u8>) -> Result<Query, OnlineError> {
        if self.mode != Mode::KeywordPir {
            return Err(OnlineError::Protocol);
        }
        Ok(Query::KeywordPir { id, keyword })
    }

    pub fn expect_rms24_reply(&self, reply: Reply) -> Result<Vec<u8>, OnlineError> {
        match reply {
            Reply::Rms24 { parity, .. } => Ok(parity),
            Reply::Error { .. } => Err(OnlineError::Server("server error".into())),
            _ => Err(OnlineError::Protocol),
        }
    }
}
```

Update `src/lib.rs` to export the module:

```rust
pub mod online_client;
```

**Step 4: Run test to verify it passes**

Run: `cargo test online_client::tests::test_build_rms24_query`
Expected: PASS

**Step 5: Commit**

```bash
git add src/online_client.rs src/lib.rs
git commit -m "feat: add online client core"
```

---

### Task 6: Document the online protocol in architecture/deployment docs

**Files:**
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/DEPLOYMENT.md`
- Modify: `docs/API_ENDPOINTS.md`

**Step 1: Write the failing doc review (optional)**

Run: `~/.codex/skills/docs-guardian/scripts/doc-review.sh /Users/user/pse/rms24-rs`
Expected: FAIL if docs missing updates (if not, note OK and proceed).

**Step 2: Update docs**

Add a short section describing:
- The `online` module and its components (protocol types, framing, transport, server/client core).
- Raw TCP framing (length-prefixed bincode) and single-port mode selection.
- How a deployer runs the online server binary once it exists (stub note is fine).

**Step 3: Re-run doc review**

Run: `~/.codex/skills/docs-guardian/scripts/doc-review.sh /Users/user/pse/rms24-rs`
Expected: PASS

**Step 4: Commit**

```bash
git add docs/ARCHITECTURE.md docs/DEPLOYMENT.md docs/API_ENDPOINTS.md
git commit -m "docs: document online protocol"
```
