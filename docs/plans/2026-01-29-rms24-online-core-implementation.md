# RMS24 Online Core Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement RMS24 online index-PIR (query/answer/extract + consume/replenish + point updates) with deterministic, serializable client state and schema40 helpers.

**Architecture:** Add `server`, `messages`, `updates`, and `schema40` modules. Server is stateless over a DB trait and returns parity for explicit subsets. Client owns PRF key, RNG state, hints, and available-hint IDs; all serialized with `serde`+`bincode`.

**Tech Stack:** Rust 2021, `serde`, `bincode`, `rand_chacha`, `sha3`.

---

### Task 0: Fix PRF select/offset consistency (prevents hanging tests)

**Files:**
- Modify: `src/prf.rs`
- Test: `src/prf.rs`

**Step 1: Write the failing test**

Add to `src/prf.rs` tests:

```rust
#[test]
fn test_select_matches_select_vector() {
    let prf = Prf::new([7u8; 32]);
    let num_blocks = 16;
    let values = prf.select_vector(42, num_blocks);
    for (block, value) in values.iter().enumerate() {
        assert_eq!(*value, prf.select(42, block as u32));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test prf::tests::test_select_matches_select_vector`
Expected: FAIL (mismatch between `select_vector` and `select`).

**Step 3: Implement minimal fix**

Update `src/prf.rs` to align `select`/`offset` with stream generation by seeking to `block * 64`.

```rust
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

pub fn select(&self, hint_id: u32, block: u32) -> u32 {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&0u32.to_le_bytes());
    nonce[4..8].copy_from_slice(&hint_id.to_le_bytes());

    let mut cipher = ChaCha12::new((&self.key).into(), (&nonce).into());
    cipher.seek((block as u64) * 64);
    let mut buffer = [0u8; 64];
    cipher.apply_keystream(&mut buffer);
    u32::from_le_bytes(buffer[0..4].try_into().unwrap())
}

pub fn offset(&self, hint_id: u32, block: u32) -> u64 {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&1u32.to_le_bytes());
    nonce[4..8].copy_from_slice(&hint_id.to_le_bytes());

    let mut cipher = ChaCha12::new((&self.key).into(), (&nonce).into());
    cipher.seek((block as u64) * 64);
    let mut buffer = [0u8; 64];
    cipher.apply_keystream(&mut buffer);
    u64::from_le_bytes(buffer[0..8].try_into().unwrap())
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test prf::tests::test_select_matches_select_vector`
Expected: PASS

**Step 5: Commit**

```bash
git add src/prf.rs
jj describe -m "fix: align prf select/offset with vector stream"
```

---

### Task 1: Add serialization + hashing dependencies

**Files:**
- Modify: `Cargo.toml`

**Step 1: Write failing test (compile fail)**

Add a new test module stub in `src/schema40.rs` (created in Task 2) that uses `sha3::Keccak256` and `serde::{Serialize, Deserialize}`. It will fail to compile until deps are added.

**Step 2: Run test to verify it fails**

Run: `cargo test schema40::tests::test_tag_keccak`
Expected: FAIL (missing crates).

**Step 3: Add dependencies**

Update `Cargo.toml`:

```toml
[dependencies]
chacha20 = "0.9"
rand = "0.8"
rand_chacha = { version = "0.3", features = ["serde1"] }
thiserror = "2"
clap = { version = "4", features = ["derive"] }
rayon = "1.10"
memmap2 = "0.9"
serde = { version = "1", features = ["derive"] }
bincode = "1.3"
sha3 = "0.10"
```

**Step 4: Run test to verify it passes**

Run: `cargo test schema40::tests::test_tag_keccak`
Expected: PASS (after Task 2 adds the test body).

**Step 5: Commit**

```bash
git add Cargo.toml
jj describe -m "chore: add serde, bincode, sha3 deps"
```

---

### Task 2: Add schema40 helpers

**Files:**
- Create: `src/schema40.rs`
- Modify: `src/lib.rs`
- Test: `src/schema40.rs`

**Step 1: Write failing tests**

Create `src/schema40.rs` with tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_keccak() {
        let key = [0x11u8; 20];
        let tag = Tag::from_key(&key);
        assert_eq!(tag.0.len(), 8);
    }

    #[test]
    fn test_account_entry_encode_decode() {
        let value = [0xAAu8; 32];
        let tag = Tag([0xBBu8; 8]);
        let entry = AccountEntry40 { value, tag };
        let bytes = entry.encode();
        assert_eq!(bytes.len(), 40);
        let decoded = AccountEntry40::decode(&bytes).unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.tag.0, tag.0);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test schema40::tests::test_account_entry_encode_decode`
Expected: FAIL (missing types/impls).

**Step 3: Implement schema40 helpers**

Implement minimal helpers in `src/schema40.rs`:

```rust
use sha3::{Digest, Keccak256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag(pub [u8; 8]);

impl Tag {
    pub fn from_key(key: &[u8]) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(key);
        let digest = hasher.finalize();
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&digest[..8]);
        Tag(tag)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountEntry40 {
    pub value: [u8; 32],
    pub tag: Tag,
}

impl AccountEntry40 {
    pub fn encode(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.value);
        out[32..].copy_from_slice(&self.tag.0);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 40 {
            return None;
        }
        let mut value = [0u8; 32];
        value.copy_from_slice(&bytes[..32]);
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&bytes[32..]);
        Some(Self { value, tag: Tag(tag) })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageEntry40 {
    pub value: [u8; 32],
    pub tag: Tag,
}

impl StorageEntry40 {
    pub fn encode(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.value);
        out[32..].copy_from_slice(&self.tag.0);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 40 {
            return None;
        }
        let mut value = [0u8; 32];
        value.copy_from_slice(&bytes[..32]);
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&bytes[32..]);
        Some(Self { value, tag: Tag(tag) })
    }
}
```

**Step 4: Export module**

Update `src/lib.rs`:

```rust
pub mod schema40;
```

**Step 5: Run tests to verify they pass**

Run: `cargo test schema40::tests::test_account_entry_encode_decode`
Expected: PASS

**Step 6: Commit**

```bash
git add src/schema40.rs src/lib.rs
jj describe -m "feat: add schema40 helpers"
```

---

### Task 3: Define messages and error types

**Files:**
- Create: `src/messages.rs`
- Modify: `src/lib.rs`
- Test: `src/messages.rs`

**Step 1: Write failing tests**

Create `src/messages.rs` with tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_reply_round_trip_fields() {
        let q = Query { id: 7, subset: vec![(1, 2), (3, 4)] };
        let r = Reply { id: 7, parity: vec![1, 2, 3] };
        assert_eq!(q.id, 7);
        assert_eq!(r.id, 7);
        assert_eq!(q.subset.len(), 2);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test messages::tests::test_query_reply_round_trip_fields`
Expected: FAIL (missing types).

**Step 3: Implement messages and errors**

```rust
#[derive(Clone, Debug)]
pub struct Query {
    pub id: u64,
    pub subset: Vec<(u32, u32)>,
}

#[derive(Clone, Debug)]
pub struct Reply {
    pub id: u64,
    pub parity: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Update {
    pub index: u64,
    pub old_entry: Vec<u8>,
    pub new_entry: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("subset out of range")]
    SubsetOutOfRange,
    #[error("entry size mismatch")]
    EntrySizeMismatch,
    #[error("db error: {0}")]
    DbError(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("invalid index")]
    InvalidIndex,
    #[error("no available hint contains target")]
    NoValidHint,
    #[error("reply parity length mismatch")]
    ParityLengthMismatch,
    #[error("verification failed")]
    VerificationFailed,
    #[error("serialization error: {0}")]
    SerializationError(String),
}
```

**Step 4: Export module**

Update `src/lib.rs`:

```rust
pub mod messages;
```

**Step 5: Run tests to verify they pass**

Run: `cargo test messages::tests::test_query_reply_round_trip_fields`
Expected: PASS

**Step 6: Commit**

```bash
git add src/messages.rs src/lib.rs
jj describe -m "feat: add online message types"
```

---

### Task 4: Add DB trait and server parity computation

**Files:**
- Create: `src/server.rs`
- Modify: `src/lib.rs`
- Test: `src/server.rs`

**Step 1: Write failing tests**

Create `src/server.rs` with tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::Query;

    #[test]
    fn test_server_parity_simple() {
        let entry_size = 4;
        let block_size = 2;
        let db = InMemoryDb::new(vec![1,2,3,4,  5,6,7,8], entry_size).unwrap();
        let server = Server::new(db, block_size);
        let query = Query { id: 1, subset: vec![(0, 0), (0, 1)] };
        let reply = server.answer(&query).unwrap();
        // parity of entry0 ^ entry1
        assert_eq!(reply.parity, vec![1^5, 2^6, 3^7, 4^8]);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test server::tests::test_server_parity_simple`
Expected: FAIL (missing types).

**Step 3: Implement server and DB trait**

```rust
use crate::hints::xor_bytes_inplace;
use crate::messages::{Query, Reply, ServerError, Update};

pub trait Db {
    fn num_entries(&self) -> u64;
    fn entry_size(&self) -> usize;
    fn entry(&self, index: u64) -> Result<Vec<u8>, ServerError>;
    fn update(&mut self, index: u64, entry: &[u8]) -> Result<(), ServerError>;
}

pub struct InMemoryDb {
    entry_size: usize,
    entries: Vec<u8>,
}

impl InMemoryDb {
    pub fn new(entries: Vec<u8>, entry_size: usize) -> Result<Self, ServerError> {
        if entry_size == 0 || entries.len() % entry_size != 0 {
            return Err(ServerError::EntrySizeMismatch);
        }
        Ok(Self { entry_size, entries })
    }
}

impl Db for InMemoryDb {
    fn num_entries(&self) -> u64 {
        (self.entries.len() / self.entry_size) as u64
    }

    fn entry_size(&self) -> usize {
        self.entry_size
    }

    fn entry(&self, index: u64) -> Result<Vec<u8>, ServerError> {
        if index >= self.num_entries() {
            return Err(ServerError::SubsetOutOfRange);
        }
        let start = index as usize * self.entry_size;
        Ok(self.entries[start..start + self.entry_size].to_vec())
    }

    fn update(&mut self, index: u64, entry: &[u8]) -> Result<(), ServerError> {
        if entry.len() != self.entry_size {
            return Err(ServerError::EntrySizeMismatch);
        }
        if index >= self.num_entries() {
            return Err(ServerError::SubsetOutOfRange);
        }
        let start = index as usize * self.entry_size;
        self.entries[start..start + self.entry_size].copy_from_slice(entry);
        Ok(())
    }
}

pub struct Server<D: Db> {
    db: D,
    block_size: u64,
}

impl<D: Db> Server<D> {
    pub fn new(db: D, block_size: u64) -> Self {
        Self { db, block_size }
    }

    pub fn answer(&self, query: &Query) -> Result<Reply, ServerError> {
        let mut parity = vec![0u8; self.db.entry_size()];
        for (block, offset) in &query.subset {
            let index = (*block as u64) * self.block_size + (*offset as u64);
            let entry = self.db.entry(index)?;
            xor_bytes_inplace(&mut parity, &entry);
        }
        Ok(Reply { id: query.id, parity })
    }

    pub fn apply_update(&mut self, update: &Update) -> Result<(), ServerError> {
        self.db.update(update.index, &update.new_entry)
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test server::tests::test_server_parity_simple`
Expected: PASS (note: index computation will be corrected in Task 6).

**Step 5: Commit**

```bash
git add src/server.rs src/lib.rs
jj describe -m "feat: add server and db trait"
```

---

### Task 5: Add online client state + serialization

**Files:**
- Modify: `src/client.rs`
- Modify: `src/lib.rs`
- Test: `src/client.rs`

**Step 1: Write failing tests**

Add to `src/client.rs` tests:

```rust
#[test]
fn test_client_state_roundtrip() {
    let params = Params::new(16, 40, 2);
    let mut client = OnlineClient::new(params, Prf::random(), 1234u64);
    let data = client.serialize_state().unwrap();
    let mut client2 = OnlineClient::deserialize_state(&data).unwrap();
    let id1 = client.next_query_id();
    let id2 = client2.next_query_id();
    assert_eq!(id1, id2);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test client::tests::test_client_state_roundtrip`
Expected: FAIL (missing OnlineClient).

**Step 3: Implement OnlineClient and serialization**

Add to `src/client.rs`:

```rust
use rand_chacha::ChaCha20Rng;
use rand::{SeedableRng, Rng};
use serde::{Serialize, Deserialize};
use crate::messages::ClientError;

#[derive(Serialize, Deserialize)]
pub struct OnlineClient {
    pub params: Params,
    pub prf: Prf,
    pub hints: HintState,
    pub available_hints: Vec<usize>,
    pub rng: ChaCha20Rng,
    pub next_query_id: u64,
}

impl OnlineClient {
    pub fn new(params: Params, prf: Prf, seed: u64) -> Self {
        let hints = HintState::new(params.num_reg_hints as usize, params.num_backup_hints as usize, params.entry_size);
        let available_hints = (0..params.num_reg_hints as usize).collect();
        Self {
            params,
            prf,
            hints,
            available_hints,
            rng: ChaCha20Rng::seed_from_u64(seed),
            next_query_id: 0,
        }
    }

    pub fn serialize_state(&self) -> Result<Vec<u8>, ClientError> {
        bincode::serialize(self).map_err(|e| ClientError::SerializationError(e.to_string()))
    }

    pub fn deserialize_state(bytes: &[u8]) -> Result<Self, ClientError> {
        bincode::deserialize(bytes).map_err(|e| ClientError::SerializationError(e.to_string()))
    }

    pub fn next_query_id(&mut self) -> u64 {
        let id = self.next_query_id;
        self.next_query_id += 1;
        id
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test client::tests::test_client_state_roundtrip`
Expected: PASS

**Step 5: Commit**

```bash
git add src/client.rs
jj describe -m "feat: add online client state and serialization"
```

---

### Task 6: Implement subset building + server parity indexing

**Files:**
- Modify: `src/client.rs`
- Modify: `src/server.rs`
- Test: `src/client.rs`

**Step 1: Write failing tests**

Add to `src/client.rs` tests:

```rust
#[test]
fn test_query_round_trip_basic() {
    let params = Params::new(16, 4, 2);
    let prf = Prf::random();
    let mut client = OnlineClient::new(params.clone(), prf, 42);
    let db = (0..(16*4)).map(|i| i as u8).collect::<Vec<u8>>();
    let server = crate::server::Server::new(crate::server::InMemoryDb::new(db, 4).unwrap(), params.block_size);

    let index = 3u64;
    let result = client.query(&server, index).unwrap();
    let expected = vec![(index*4) as u8, (index*4+1) as u8, (index*4+2) as u8, (index*4+3) as u8];
    assert_eq!(result, expected);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test client::tests::test_query_round_trip_basic`
Expected: FAIL (missing query method and server index computation).

**Step 3: Implement subset building and server index math**

In `src/client.rs`, add helper to build subset for a hint:

```rust
fn build_subset_for_hint(&self, hint_id: usize) -> Vec<(u32, u32)> {
    let cutoff = self.hints.cutoffs[hint_id];
    if cutoff == 0 {
        return Vec::new();
    }
    let mut subset = Vec::new();
    let num_blocks = self.params.num_blocks as u32;
    for block in 0..num_blocks {
        let select = self.prf.select(hint_id as u32, block);
        let offset = (self.prf.offset(hint_id as u32, block) % self.params.block_size) as u32;
        if !self.hints.flips[hint_id] {
            if select < cutoff {
                subset.push((block, offset));
            }
        } else if select >= cutoff {
            subset.push((block, offset));
        }
    }
    if self.hints.extra_blocks[hint_id] != u32::MAX {
        subset.push((self.hints.extra_blocks[hint_id], self.hints.extra_offsets[hint_id]));
    }
    subset
}
```

Add `query` method to `OnlineClient`:

```rust
pub fn query<D: crate::server::Db>(&mut self, server: &crate::server::Server<D>, index: u64) -> Result<Vec<u8>, ClientError> {
    if index >= self.params.num_entries {
        return Err(ClientError::InvalidIndex);
    }
    let id = self.next_query_id();
    // Find a valid hint containing target.
    let mut candidates = Vec::new();
    for &hint_id in &self.available_hints {
        let subset = self.build_subset_for_hint(hint_id);
        if subset.iter().any(|(b, o)| {
            let entry_idx = (*b as u64) * self.params.block_size + (*o as u64);
            entry_idx == index
        }) {
            candidates.push((hint_id, subset));
        }
    }
    if candidates.is_empty() {
        return Err(ClientError::NoValidHint);
    }
    let (hint_id, real_subset) = candidates.swap_remove(self.rng.gen_range(0..candidates.len()));
    // Dummy subset: pick a random hint id and build its subset
    let dummy_hint = self.available_hints[self.rng.gen_range(0..self.available_hints.len())];
    let dummy_subset = self.build_subset_for_hint(dummy_hint);

    let real_query = crate::messages::Query { id, subset: real_subset };
    let dummy_query = crate::messages::Query { id, subset: dummy_subset };

    let real_reply = server.answer(&real_query)?;
    let _dummy_reply = server.answer(&dummy_query)?;

    let mut result = real_reply.parity.clone();
    crate::hints::xor_bytes_inplace(&mut result, &self.hints.parities[hint_id]);

    Ok(result)
}
```

In `src/server.rs`, compute index using `block_size` stored on `Server`.

**Step 4: Run tests to verify they pass**

Run: `cargo test client::tests::test_query_round_trip_basic`
Expected: PASS

**Step 5: Commit**

```bash
git add src/client.rs src/server.rs
jj describe -m "feat: add query subset flow and parity extraction"
```

---

### Task 7: Hint consumption + replenish

**Files:**
- Modify: `src/client.rs`
- Create: `src/updates.rs`
- Test: `src/client.rs`

**Step 1: Write failing tests**

```rust
#[test]
fn test_hint_consumed_after_query() {
    let params = Params::new(16, 4, 2);
    let prf = Prf::random();
    let mut client = OnlineClient::new(params.clone(), prf, 42);
    let db = vec![0u8; (params.num_entries as usize) * params.entry_size];
    let server = crate::server::Server::new(crate::server::InMemoryDb::new(db, params.entry_size).unwrap());
    let _ = client.query(&server, 0).unwrap();
    assert!(client.available_hints.len() < params.num_reg_hints as usize);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test client::tests::test_hint_consumed_after_query`
Expected: FAIL (no consumption).

**Step 3: Implement consumption + replenish**

In `query`, remove chosen hint from `available_hints` using `swap_remove`. Implement `replenish_hint` using Algorithm 5 from the RMS24 paper (single-server replenish). Add helper method `replenish_hint(target_index)` that updates `HintState` and promotes a backup hint.

Provide concrete implementation based on the paper's Algorithm 5 (store in `updates.rs` if needed). Ensure `flips`, `backup_parities_high`, and `next_backup_idx` are updated consistently.

**Step 4: Run tests to verify they pass**

Run: `cargo test client::tests::test_hint_consumed_after_query`
Expected: PASS

**Step 5: Commit**

```bash
git add src/client.rs src/updates.rs
jj describe -m "feat: add hint consumption and replenish"
```

---

### Task 8: Point updates (server + client)

**Files:**
- Modify: `src/server.rs`
- Modify: `src/client.rs`
- Modify/Create: `src/updates.rs`
- Test: `src/client.rs`

**Step 1: Write failing tests**

```rust
#[test]
fn test_point_update_round_trip() {
    let params = Params::new(8, 4, 2);
    let prf = Prf::random();
    let mut client = OnlineClient::new(params.clone(), prf, 1);
    let db = vec![0u8; (params.num_entries as usize) * params.entry_size];
    let mut server = crate::server::Server::new(crate::server::InMemoryDb::new(db, params.entry_size).unwrap(), params.block_size);

    let old_entry = vec![0,0,0,0];
    let new_entry = vec![9,9,9,9];
    let update = crate::messages::Update { index: 2, old_entry, new_entry: new_entry.clone() };
    server.apply_update(&update).unwrap();
    client.apply_update(&update).unwrap();

    let got = client.query(&server, 2).unwrap();
    assert_eq!(got, new_entry);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test client::tests::test_point_update_round_trip`
Expected: FAIL (missing update application).

**Step 3: Implement update logic**

Add `apply_update` on client: for each hint, if the updated index is in its subset, XOR out old entry and XOR in new entry (store old entry or require caller to pass it). For initial implementation, require `Update` to include both `old_entry` and `new_entry` or fetch old entry before updating.

**Step 4: Run tests to verify they pass**

Run: `cargo test client::tests::test_point_update_round_trip`
Expected: PASS

**Step 5: Commit**

```bash
git add src/client.rs src/server.rs src/updates.rs
jj describe -m "feat: add point update flow"
```

---

### Task 9: Optional real-data slice integration test

**Files:**
- Create: `tests/online_slice_test.rs`

**Step 1: Write failing test**

```rust
#[test]
fn test_real_slice_optional() {
    let data_dir = std::env::var("RMS24_DATA_DIR").ok();
    if data_dir.is_none() {
        return;
    }
    // Load slice files and assert query results.
    // (Implement using helpers in this test only.)
    assert!(true);
}
```

**Step 2: Run test to verify it fails (when RMS24_DATA_DIR set)**

Run: `RMS24_DATA_DIR=/path/to/slice cargo test test_real_slice_optional`
Expected: FAIL until loader is implemented.

**Step 3: Implement loader and assertions**

Parse `database.bin` from the slice, pick a few known indices, and verify `query` returns the exact 40B entries (or decode with schema40 helpers).

**Step 4: Run test to verify it passes**

Run: `RMS24_DATA_DIR=/path/to/slice cargo test test_real_slice_optional`
Expected: PASS

**Step 5: Commit**

```bash
git add tests/online_slice_test.rs
jj describe -m "test: add optional real-slice online test"
```

---

Plan complete and saved to `docs/plans/2026-01-29-rms24-online-core-implementation.md`.

Two execution options:

1. Subagent-Driven (this session)
2. Parallel Session (separate session with `superpowers:executing-plans`)
