# RMS24 KeywordPIR Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement full KeywordPIR inside this repo (cuckoo table build + client wrapper + benchmark harness integration) using existing `database.bin` and mapping files, plus a builder binary that produces keywordpir tables and metadata.

**Architecture:** Add a `keyword_pir` module with cuckoo hashing, mapping parsing, and query logic built on RMS24 index PIR. Provide a `rms24_keywordpir_build` binary that builds the main keywordpir table and collision table from existing mapping files. Update benchmark client to run real KeywordPIR when `--mode keywordpir` is set, using metadata + collision tags, while the server stays a standard RMS24 index server over the keywordpir DB file.

**Tech Stack:** Rust 2021, `serde`, `bincode`, `sha3`, `rand_chacha`, `memmap2`, `clap`.

---

## Task 1: Add keyword_pir module skeleton + mapping parsing

### Files
- Create: `src/keyword_pir/mod.rs`
- Modify: `src/lib.rs`
- Test: `src/keyword_pir/mod.rs`

### Step 1: Write the failing tests

Create `src/keyword_pir/mod.rs` with tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mapping_record_account() {
        let mut record = vec![0u8; 24];
        record[..20].copy_from_slice(&[0x11u8; 20]);
        record[20..24].copy_from_slice(&42u32.to_le_bytes());
        let parsed = parse_mapping_record(&record, 20).unwrap();
        assert_eq!(parsed.index, 42);
        assert_eq!(parsed.key.len(), 20);
    }

    #[test]
    fn test_parse_mapping_record_storage() {
        let mut record = vec![0u8; 56];
        record[..52].copy_from_slice(&[0x22u8; 52]);
        record[52..56].copy_from_slice(&7u32.to_le_bytes());
        let parsed = parse_mapping_record(&record, 52).unwrap();
        assert_eq!(parsed.index, 7);
        assert_eq!(parsed.key.len(), 52);
    }

    #[test]
    fn test_tag_for_key_account_vs_storage() {
        let account_key = [0xABu8; 20];
        let storage_key = [0xCDu8; 52];
        let account_tag = tag_for_key(&account_key).unwrap();
        let storage_tag = tag_for_key(&storage_key).unwrap();
        assert_ne!(account_tag.0, storage_tag.0);
    }
}
```

### Step 2: Run test to verify it fails

Run: `cargo test keyword_pir::tests::test_parse_mapping_record_account`
Expected: FAIL (module + functions missing).

### Step 3: Implement minimal module

In `src/keyword_pir/mod.rs`:

```rust
use crate::schema40::Tag;

#[derive(Clone, Debug)]
pub struct MappingRecord {
    pub key: Vec<u8>,
    pub index: u64,
}

pub fn parse_mapping_record(record: &[u8], key_size: usize) -> Option<MappingRecord> {
    if record.len() < key_size + 4 {
        return None;
    }
    let mut key = vec![0u8; key_size];
    key.copy_from_slice(&record[..key_size]);
    let index = u32::from_le_bytes(record[key_size..key_size + 4].try_into().ok()?) as u64;
    Some(MappingRecord { key, index })
}

pub fn tag_for_key(key: &[u8]) -> Option<Tag> {
    match key.len() {
        20 => {
            let mut addr = [0u8; 20];
            addr.copy_from_slice(key);
            Some(Tag::from_address(&addr))
        }
        52 => {
            let mut addr = [0u8; 20];
            let mut slot = [0u8; 32];
            addr.copy_from_slice(&key[..20]);
            slot.copy_from_slice(&key[20..]);
            Some(Tag::from_address_slot(&addr, &slot))
        }
        _ => None,
    }
}
```

Update `src/lib.rs`:

```rust
pub mod keyword_pir;
```

### Step 4: Run tests to verify they pass

Run: `cargo test keyword_pir::tests::test_parse_mapping_record_account`
Expected: PASS

### Step 5: Commit

```bash
jj add src/keyword_pir/mod.rs src/lib.rs
jj describe -m "feat: add keyword_pir module skeleton and mapping parse"
```

---

## Task 2: Implement cuckoo hashing core + parameters

### Files
- Modify: `src/keyword_pir/mod.rs`
- Test: `src/keyword_pir/mod.rs`

### Step 1: Write the failing tests

Add tests in `src/keyword_pir/mod.rs`:

```rust
#[test]
fn test_cuckoo_positions_deterministic() {
    let key = vec![0x55u8; 20];
    let cfg = CuckooConfig::new(16, 2, 2, 32, 123);
    let a = cuckoo_positions(&key, &cfg);
    let b = cuckoo_positions(&key, &cfg);
    assert_eq!(a, b);
}

#[test]
fn test_cuckoo_insert_and_lookup() {
    let cfg = CuckooConfig::new(8, 2, 2, 32, 7);
    let mut table = CuckooTable::new(cfg);
    let key = vec![0x11u8; 20];
    let value = [0xAAu8; 40];
    table.insert(&key, value).unwrap();
    let got = table.find_candidate(&key).unwrap();
    assert_eq!(got, value);
}
```

### Step 2: Run test to verify it fails

Run: `cargo test keyword_pir::tests::test_cuckoo_insert_and_lookup`
Expected: FAIL (types/impls missing).

### Step 3: Implement cuckoo core

Add types and helpers:

```rust
#[derive(Clone, Debug)]
pub struct CuckooConfig {
    pub num_buckets: usize,
    pub bucket_size: usize,
    pub num_hashes: usize,
    pub max_kicks: usize,
    pub seed: u64,
}

impl CuckooConfig {
    pub fn new(num_buckets: usize, bucket_size: usize, num_hashes: usize, max_kicks: usize, seed: u64) -> Self {
        Self { num_buckets, bucket_size, num_hashes, max_kicks, seed }
    }
}

pub fn cuckoo_positions(key: &[u8], cfg: &CuckooConfig) -> Vec<usize> {
    (0..cfg.num_hashes)
        .map(|i| hash_with_seed(key, cfg.seed.wrapping_add(i as u64)) % cfg.num_buckets)
        .collect()
}

fn hash_with_seed(key: &[u8], seed: u64) -> usize {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(seed.to_le_bytes());
    hasher.update(key);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes) as usize
}

#[derive(Clone, Debug)]
pub struct CuckooSlot {
    pub key_hash: [u8; 32],
    pub value: [u8; 40],
}

#[derive(Clone, Debug)]
pub struct CuckooTable {
    cfg: CuckooConfig,
    slots: Vec<Option<CuckooSlot>>,
}

impl CuckooTable {
    pub fn new(cfg: CuckooConfig) -> Self {
        let total = cfg.num_buckets * cfg.bucket_size;
        Self { cfg, slots: vec![None; total] }
    }

    pub fn insert(&mut self, key: &[u8], value: [u8; 40]) -> Result<(), String> {
        let key_hash = hash_key(key);
        let slot = CuckooSlot { key_hash, value };
        let positions = cuckoo_positions(&key_hash, &self.cfg);
        for &bucket in &positions {
            for i in 0..self.cfg.bucket_size {
                let idx = bucket * self.cfg.bucket_size + i;
                if self.slots[idx].is_none() {
                    self.slots[idx] = Some(slot);
                    return Ok(());
                }
            }
        }
        // Minimal deterministic kick loop
        let mut cur_slot = slot;
        let mut cur_bucket = positions[0];
        for kick in 0..self.cfg.max_kicks {
            let idx = cur_bucket * self.cfg.bucket_size + (kick % self.cfg.bucket_size);
            let evicted = self.slots[idx].replace(cur_slot);
            let evicted = match evicted {
                Some(evicted) => evicted,
                None => return Ok(()),
            };
            cur_slot = evicted;
            let evicted_positions = cuckoo_positions(&cur_slot.key_hash, &self.cfg);
            cur_bucket = evicted_positions[0];
            for i in 0..self.cfg.bucket_size {
                let cand = cur_bucket * self.cfg.bucket_size + i;
                if self.slots[cand].is_none() {
                    self.slots[cand] = Some(cur_slot);
                    return Ok(());
                }
            }
        }
        Err("cuckoo insertion failed".into())
    }

    pub fn find_candidate(&self, key: &[u8]) -> Option<[u8; 40]> {
        let key_hash = hash_key(key);
        let positions = cuckoo_positions(&key_hash, &self.cfg);
        for &bucket in &positions {
            for i in 0..self.cfg.bucket_size {
                let idx = bucket * self.cfg.bucket_size + i;
                if let Some(slot) = &self.slots[idx] {
                    if slot.key_hash == key_hash {
                        return Some(slot.value);
                    }
                }
            }
        }
        None
    }
}
```

(Implement `hash_key` using `Sha3_256` of the key bytes.)
(Use the key hash as the canonical input to `cuckoo_positions` so insert/eviction/lookup are consistent.)

### Step 4: Run tests to verify they pass

Run: `cargo test keyword_pir::tests::test_cuckoo_insert_and_lookup`
Expected: PASS

### Step 5: Commit

```bash
jj add src/keyword_pir/mod.rs
jj describe -m "feat: add cuckoo hashing core for keyword_pir"
```

---

## Task 3: Builder binary for KeywordPIR tables

### Files
- Create: `src/bin/rms24_keywordpir_build.rs`
- Modify: `src/keyword_pir/mod.rs`
- Test: `src/bin/rms24_keywordpir_build.rs`

### Step 1: Write the failing test

Add parse test in `src/bin/rms24_keywordpir_build.rs`:

```rust
#[test]
fn test_parse_args() {
    let args = Args::parse_from([
        "rms24_keywordpir_build",
        "--db", "db.bin",
        "--account-mapping", "acc.bin",
        "--storage-mapping", "sto.bin",
        "--out", "out",
    ]);
    assert_eq!(args.db, "db.bin");
    assert_eq!(args.out, "out");
}
```

### Step 2: Run test to verify it fails

Run: `cargo test rms24_keywordpir_build::tests::test_parse_args`
Expected: FAIL (binary missing).

### Step 3: Implement builder

Create builder binary with:
- Inputs: `--db`, `--account-mapping`, `--storage-mapping`, `--out`, `--bucket-size`, `--num-hashes`, `--max-kicks`, `--seed`.
- Uses `memmap2::Mmap` to read DB.
- Reads mapping files record-by-record, builds vector of `(key, index, entry_bytes)`.
- Computes tag for key, verifies tag matches entry bytes at tag offset. If mismatch, error out.
- Detects tag collisions using `HashMap<Tag, Vec<Vec<u8>>>`; builds collision set from tags with >1 key.
- Builds main cuckoo table from all keys.
- Builds collision table (only colliding keys) with **collision entry size = 72 bytes**: `key_hash(32) || entry(40)`. Use `Sha3_256(key)` for key_hash.
- Writes output files in `--out` directory:
  - `keywordpir-db.bin`
  - `keywordpir-collision-db.bin` (if collisions exist)
  - `keywordpir-collision-tags.bin` (list of 8-byte tags)
  - `keywordpir-metadata.json`

Metadata fields:
- `entry_size`, `num_entries`, `bucket_size`, `num_buckets`, `num_hashes`, `max_kicks`, `seed`
- `collision_entry_size`, `collision_count`

### Step 4: Run tests to verify they pass

Run: `cargo test rms24_keywordpir_build::tests::test_parse_args`
Expected: PASS

### Step 5: Commit

```bash
jj add src/bin/rms24_keywordpir_build.rs src/keyword_pir/mod.rs
jj describe -m "feat: add keywordpir builder binary"
```

---

## Task 4: KeywordPIR client wrapper + collision handling

### Files
- Modify: `src/keyword_pir/mod.rs`
- Test: `src/keyword_pir/mod.rs`

### Step 1: Write failing tests

Add tests to `src/keyword_pir/mod.rs`:

```rust
#[test]
fn test_keywordpir_query_returns_matching_tag() {
    let cfg = CuckooConfig::new(8, 2, 2, 32, 1);
    let key = vec![0x11u8; 20];
    let entry = [0xABu8; 40];
    let mut table = CuckooTable::new(cfg.clone());
    table.insert(&key, entry).unwrap();
    let params = KeywordPirParams { cfg, entry_size: 40 };
    let client = KeywordPirClient::new(params);
    let got = client.query_local(&key, &table).unwrap();
    assert_eq!(got, entry);
}
```

### Step 2: Run test to verify it fails

Run: `cargo test keyword_pir::tests::test_keywordpir_query_returns_matching_tag`
Expected: FAIL.

### Step 3: Implement KeywordPirClient

In `src/keyword_pir/mod.rs`:
- Add `KeywordPirParams` (wraps `CuckooConfig` + `entry_size`).
- Add `KeywordPirClient` with methods:
  - `positions_for_key(&self, key: &[u8]) -> Vec<usize>`
  - `query_local(&self, key, table) -> Result<[u8; 40], String>` for unit tests.
  - `query_network(&mut self, key, online: &mut OnlineClient, sender: impl FnMut(Query)->Reply)` (bench client will drive actual network).
- Add tag verification from entry bytes: account tag at 24..32 or storage tag at 32..40 depending on key length.
- Collision handling: if tag in collision set, fall back to `query_collision` which uses collision table (entry size 72) and validates `key_hash`.

### Step 4: Run tests to verify they pass

Run: `cargo test keyword_pir::tests::test_keywordpir_query_returns_matching_tag`
Expected: PASS

### Step 5: Commit

```bash
jj add src/keyword_pir/mod.rs
jj describe -m "feat: add keywordpir client wrapper"
```

---

## Task 5: Wire benchmark client for KeywordPIR mode

### Files
- Modify: `src/bin/rms24_client.rs`
- Modify: `docs/FEATURE_FLAGS.md`
- Modify: `docs/ARCHITECTURE.md`
- Test: `src/bin/rms24_client.rs`

### Step 1: Write failing tests

Add tests in `src/bin/rms24_client.rs`:

```rust
#[test]
fn test_parse_args_keywordpir_flags() {
    let args = Args::parse_from([
        "rms24-client",
        "--db", "keywordpir-db.bin",
        "--mode", "keywordpir",
        "--keywordpir-metadata", "meta.json",
        "--account-mapping", "acc.bin",
        "--storage-mapping", "sto.bin",
    ]);
    assert!(args.keywordpir_metadata.is_some());
    assert!(args.account_mapping.is_some());
}
```

### Step 2: Run test to verify it fails

Run: `cargo test rms24_client::tests::test_parse_args_keywordpir_flags`
Expected: FAIL (missing args).

### Step 3: Implement KeywordPIR mode

Update `Args` with:
- `--keywordpir-metadata <path>` (required in keywordpir mode)
- `--account-mapping <path>` and `--storage-mapping <path>` (required)
- `--collision-tags <path>` (optional)
- `--collision-server <addr>` (optional; only needed if collision tags present)

Implementation changes:
- When `--mode keywordpir`, load metadata, collision tags (if any), and mappings.
- Build a list of keys to query (round-robin from account + storage mappings, size = query_count).
- Use `KeywordPirClient` to compute candidate indices and push real+dummy RMS24 queries for each index.
- Keep batching logic intact by pushing multiple pending items per keyword query.

### Step 4: Run tests to verify they pass

Run: `cargo test rms24_client::tests::test_parse_args_keywordpir_flags`
Expected: PASS

### Step 5: Update docs

Add to `docs/FEATURE_FLAGS.md`:
- KeywordPIR flags and required inputs

Add to `docs/ARCHITECTURE.md`:
- KeywordPIR module + builder pipeline

### Step 6: Commit

```bash
jj add src/bin/rms24_client.rs docs/FEATURE_FLAGS.md docs/ARCHITECTURE.md
jj describe -m "feat: add keywordpir mode to benchmark client"
```
