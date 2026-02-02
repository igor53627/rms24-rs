# KeywordPIR Builder Robustness Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use @superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the KeywordPIR builder robust to cuckoo insertion failures by retrying with expanded bucket counts and seed bumps for the main table, while keeping the collision table seed fixed to the final main seed.

**Architecture:** Add a retry helper in `rms24_keywordpir_build` that attempts table construction with slack-based bucket growth; on failure it expands buckets and (for the main table) bumps the seed. The main table uses bumping; the collision table reuses the final main seed and only expands buckets. Metadata is written with the final main table bucket count and seed.

**Tech Stack:** Rust 2021, `memmap2`, `sha3`, `clap`.

---

### Task 1: Add retry helper + wire main/collision builds

**Files:**
- Modify: `src/bin/rms24_keywordpir_build.rs`
- Test: `src/bin/rms24_keywordpir_build.rs`

**Step 1: Write the failing tests**

Add to `src/bin/rms24_keywordpir_build.rs` under `#[cfg(test)] mod tests`:

```rust
    use rms24::keyword_pir::cuckoo_positions;

    fn entry_record_for_key(key: Vec<u8>) -> EntryRecord {
        let tag = tag_for_key(&key).expect("valid key length");
        let mut entry = [0u8; ENTRY_SIZE];
        match key.len() {
            20 => entry[24..32].copy_from_slice(tag.as_bytes()),
            52 => entry[32..40].copy_from_slice(tag.as_bytes()),
            _ => panic!("unsupported key length"),
        }
        EntryRecord {
            key,
            entry,
            tag,
            index: 0,
        }
    }

    fn hash_key_for_test(key: &[u8]) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(key);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest[..]);
        out
    }

    fn find_keys_with_distinct_buckets(seed: u64) -> (Vec<u8>, Vec<u8>) {
        let cfg = CuckooConfig::new(2, 1, 1, 1, seed);
        for a in 0u8..=255 {
            let key_a = vec![a; 20];
            let hash_a = hash_key_for_test(&key_a);
            let bucket_a = cuckoo_positions(&hash_a, &cfg)[0];
            for b in 0u8..=255 {
                if b == a {
                    continue;
                }
                let key_b = vec![b; 20];
                let hash_b = hash_key_for_test(&key_b);
                let bucket_b = cuckoo_positions(&hash_b, &cfg)[0];
                if bucket_a != bucket_b {
                    return (key_a, key_b);
                }
            }
        }
        panic!("no keys found with distinct buckets");
    }

    #[test]
    fn test_build_cuckoo_retries_and_bumps_seed() {
        let (key_a, key_b) = find_keys_with_distinct_buckets(8);
        let entries = vec![
            entry_record_for_key(key_a),
            entry_record_for_key(key_b),
        ];
        let base = CuckooConfig::new(1, 1, 1, 1, 7);
        let (table, cfg) = build_cuckoo_with_retries(&entries, &base, 2.0, 2, true).unwrap();
        assert!(cfg.num_buckets >= 2);
        assert_eq!(cfg.seed, 8);
        for record in &entries {
            assert!(table.find_candidate(&record.key).is_some());
        }
    }

    #[test]
    fn test_build_cuckoo_retries_without_seed_bump() {
        let (key_a, key_b) = find_keys_with_distinct_buckets(9);
        let entries = vec![entry_record_for_key(key_a), entry_record_for_key(key_b)];
        let base = CuckooConfig::new(1, 1, 1, 1, 9);
        let (_, cfg) = build_cuckoo_with_retries(&entries, &base, 2.0, 2, false).unwrap();
        assert!(cfg.num_buckets >= 2);
        assert_eq!(cfg.seed, 9);
    }
```

**Step 2: Run test to verify it fails**

Run: `cargo test rms24_keywordpir_build::tests::test_build_cuckoo_retries_and_bumps_seed`
Expected: FAIL (missing `build_cuckoo_with_retries`).

**Step 3: Implement retry helper + wire main/collision builds**

In `src/bin/rms24_keywordpir_build.rs`, add constants near the top:

```rust
const BUCKET_SLACK: f64 = 1.15;
const MAX_BUILD_ATTEMPTS: usize = 5;
```

Add helper (place near `buckets_for_entries`):

```rust
fn build_cuckoo_with_retries(
    entries: &[EntryRecord],
    base_cfg: &CuckooConfig,
    slack: f64,
    max_attempts: usize,
    bump_seed: bool,
) -> Result<(CuckooTable, CuckooConfig), String> {
    if entries.is_empty() {
        return Err("no entries".into());
    }
    if slack <= 1.0 {
        return Err("slack must be >1".into());
    }
    if max_attempts == 0 {
        return Err("max_attempts must be >0".into());
    }
    let base_buckets = base_cfg.num_buckets;
    for attempt in 0..max_attempts {
        let factor = slack.powi(attempt as i32);
        let num_buckets = ((base_buckets as f64) * factor).ceil() as usize;
        let seed = if bump_seed {
            base_cfg.seed + attempt as u64
        } else {
            base_cfg.seed
        };
        let cfg = CuckooConfig::new(
            num_buckets,
            base_cfg.bucket_size,
            base_cfg.num_hashes,
            base_cfg.max_kicks,
            seed,
        );
        let mut table = CuckooTable::new(cfg.clone());
        let mut ok = true;
        for record in entries {
            if table.insert(&record.key, record.entry).is_err() {
                ok = false;
                break;
            }
        }
        if ok {
            return Ok((table, cfg));
        }
    }
    Err(format!("cuckoo build failed after {max_attempts} attempts"))
}
```

Wire main table build to use the helper and **use the returned cfg for metadata**:

```rust
    let num_buckets = buckets_for_entries(num_entries, args.bucket_size);
    if num_buckets == 0 {
        return Err("num_buckets must be >0".into());
    }
    let base_cfg = CuckooConfig::new(
        num_buckets,
        args.bucket_size,
        args.num_hashes,
        args.max_kicks,
        args.seed,
    );
    let (table, final_cfg) = build_cuckoo_with_retries(
        &entries,
        &base_cfg,
        BUCKET_SLACK,
        MAX_BUILD_ATTEMPTS,
        true,
    )?;

    ...

    write_metadata(
        out_dir,
        ENTRY_SIZE,
        num_entries,
        final_cfg.bucket_size,
        final_cfg.num_buckets,
        final_cfg.num_hashes,
        final_cfg.max_kicks,
        final_cfg.seed,
        COLLISION_ENTRY_SIZE,
        collision_count,
    )?;
```

Wire collision table build to use **fixed seed** (final main seed) while still expanding buckets:

```rust
        let collision_buckets = buckets_for_entries(collision_count, args.bucket_size);
        if collision_buckets == 0 {
            return Err("collision num_buckets must be >0".into());
        }
        let collision_base_cfg = CuckooConfig::new(
            collision_buckets,
            args.bucket_size,
            args.num_hashes,
            args.max_kicks,
            final_cfg.seed,
        );
        let (collision_table, _) = build_cuckoo_with_retries(
            &collision_entries,
            &collision_base_cfg,
            BUCKET_SLACK,
            MAX_BUILD_ATTEMPTS,
            false,
        )?;
```

(Collect `collision_entries` once to avoid double filters.)

**Step 4: Run tests to verify they pass**

Run: `cargo test rms24_keywordpir_build::tests::test_build_cuckoo_retries_and_bumps_seed`
Expected: PASS

Run: `cargo test rms24_keywordpir_build::tests::test_build_cuckoo_retries_without_seed_bump`
Expected: PASS

**Step 5: Commit (mention the plan in the commit body)**

```bash
jj describe -m "feat: retry keywordpir builder with slack" \
  -m "Plan: docs/plans/2026-02-02-keywordpir-builder-robustness-implementation.md"
```
```

Plan complete and saved to `docs/plans/2026-02-02-keywordpir-builder-robustness-implementation.md`. Two execution options:

1. Subagent-Driven (this session)
2. Parallel Session (separate)

Which approach?
